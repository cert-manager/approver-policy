/*
Copyright 2026 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package allowed

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/assert"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
)

// These tests pin how the evaluator treats the various ASN.1 string encodings a
// Subject RDN value may use.
//
// Design choice (fail-closed, deliberately simple): the evaluator relies on
// Go's ASN.1 decode of the Subject. The common DirectoryString encodings —
// UTF8String, PrintableString, IA5String, TeletexString and BMPString — decode
// to a Go string and are matched against policy normally. The rarely-used
// UniversalString (tag 28) and GeneralString (tag 27) decode to a nil
// interface (Go does not support them), as do genuinely non-string types
// (OctetString, INTEGER). Rather than hand-decode every exotic flavour, the
// evaluator fails closed on anything that is not a Go string and returns an
// actionable message telling the operator to re-issue with a UTF8String /
// PrintableString subject. This keeps the gate simple while never letting an
// unvalidated value through.

// bmpStringRV builds a BMPString (tag 30, UTF-16BE) raw value.
func bmpStringRV(s string) asn1.RawValue {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		binary.BigEndian.PutUint16(b[i*2:], r)
	}
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: 30, Bytes: b}
}

// teletexStringRV builds a TeletexString / T61String (tag 20) raw value.
func teletexStringRV(s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: 20, Bytes: []byte(s)}
}

// universalStringRV builds a UniversalString (tag 28, UTF-32BE) raw value.
func universalStringRV(s string) asn1.RawValue {
	runes := []rune(s)
	b := make([]byte, len(runes)*4)
	for i, r := range runes {
		binary.BigEndian.PutUint32(b[i*4:], uint32(r))
	}
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: 28, Bytes: b}
}

// generalStringRV builds a GeneralString (tag 27) raw value.
func generalStringRV(s string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: 27, Bytes: []byte(s)}
}

func evalSubject(t *testing.T, rdns pkix.RDNSequence, policy *policyapi.CertificateRequestPolicy) approver.EvaluationResponse {
	t.Helper()
	csr := csrFrom(t, withRawSubject(t, rdns))
	resp, err := Approver().Evaluate(t.Context(), policy,
		gen.CertificateRequest("", gen.SetCertificateRequestCSR(csr)))
	assert.NoError(t, err)
	return resp
}

func cnWildcardPolicy() *policyapi.CertificateRequestPolicy {
	return &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				CommonName: &policyapi.CertificateRequestPolicyAllowedString{Value: new("*.tenant.example.com")},
			},
		},
	}
}

// TestEvaluate_CN_SupportedStringEncodings — CN values in the string encodings
// Go decodes (incl. non-UTF8 BMPString/TeletexString) that match the policy
// wildcard must be approved.
func TestEvaluate_CN_SupportedStringEncodings(t *testing.T) {
	cases := map[string]any{
		"UTF8String/GoString": "app.tenant.example.com",
		"BMPString":           bmpStringRV("app.tenant.example.com"),
		"TeletexString":       teletexStringRV("app.tenant.example.com"),
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			resp := evalSubject(t, pkix.RDNSequence{rawATVRDN(oidCommonName, val)}, cnWildcardPolicy())
			assert.Equal(t, approver.ResultNotDenied, resp.Result,
				"%s CN matching the wildcard must be approved; got %v %q", name, resp.Result, resp.Message)
		})
	}
}

// TestEvaluate_CN_SupportedEncodingStillPoliced — a supported encoding does not
// mean "anything goes": a BMPString CN whose value the policy forbids is still
// denied on the value.
func TestEvaluate_CN_SupportedEncodingStillPoliced(t *testing.T) {
	resp := evalSubject(t,
		pkix.RDNSequence{rawATVRDN(oidCommonName, bmpStringRV("kubernetes-admin"))},
		cnWildcardPolicy())
	assert.Equal(t, approver.ResultDenied, resp.Result,
		"forbidden BMPString CN must be denied; got %v %q", resp.Result, resp.Message)
	assert.Contains(t, resp.Message, "kubernetes-admin",
		"denial must police the decoded value: %s", resp.Message)
}

// TestEvaluate_CN_UnsupportedEncodingsDenied — UniversalString / GeneralString
// (which Go cannot decode) are denied fail-closed, with an actionable message,
// even when the underlying text would have matched the policy.
func TestEvaluate_CN_UnsupportedEncodingsDenied(t *testing.T) {
	cases := map[string]asn1.RawValue{
		"UniversalString": universalStringRV("app.tenant.example.com"),
		"GeneralString":   generalStringRV("app.tenant.example.com"),
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			resp := evalSubject(t, pkix.RDNSequence{rawATVRDN(oidCommonName, val)}, cnWildcardPolicy())
			assert.Equal(t, approver.ResultDenied, resp.Result,
				"%s CN must be denied fail-closed; got %v %q", name, resp.Result, resp.Message)
			assert.Contains(t, resp.Message, "unsupported ASN.1 type or string encoding",
				"denial must be actionable (tell the operator to re-issue): %s", resp.Message)
		})
	}
}

// TestEvaluate_NamedSlice_UnsupportedEncodingDenied — named slice fields (here
// Organization) must not silently drop an unsupported-encoding value: it is
// denied even though the decoded text would have matched the allow-list. This
// guards against a bypass where a value invisible to the named evaluator is
// nonetheless signed via csr.RawSubject.
func TestEvaluate_NamedSlice_UnsupportedEncodingDenied(t *testing.T) {
	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				CommonName: &policyapi.CertificateRequestPolicyAllowedString{Value: new("*.tenant.example.com")},
				Subject: &policyapi.CertificateRequestPolicyAllowedX509Subject{
					Organizations: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: new([]string{"tenant-a"})},
				},
			},
		},
	}
	resp := evalSubject(t, pkix.RDNSequence{
		rdn(oidCommonName, "app.tenant.example.com"),
		rawATVRDN(oidOrganization, universalStringRV("tenant-a")),
	}, policy)
	assert.Equal(t, approver.ResultDenied, resp.Result,
		"UniversalString O must be denied fail-closed; got %v %q", resp.Result, resp.Message)
	assert.Contains(t, resp.Message, oidOrganization.String(),
		"denial must name the offending OID: %s", resp.Message)
}

// TestEvaluate_NamedOID_TrulyNonStringStillDenied — genuinely non-string ASN.1
// values (OctetString, Integer) under a named OID remain denied; the smuggle
// the backstop closes must stay closed.
func TestEvaluate_NamedOID_TrulyNonStringStillDenied(t *testing.T) {
	cases := map[string]any{
		"OctetString": asn1.RawValue{Class: asn1.ClassUniversal, Tag: 4, Bytes: []byte("evil-corp")},
		"Integer":     asn1.RawValue{Class: asn1.ClassUniversal, Tag: 2, Bytes: []byte{0x2a}},
	}
	for name, val := range cases {
		t.Run(name, func(t *testing.T) {
			resp := evalSubject(t, pkix.RDNSequence{
				rdn(oidCommonName, "app.tenant.example.com"),
				rawATVRDN(oidOrganization, val),
			}, cnWildcardPolicy())
			assert.Equal(t, approver.ResultDenied, resp.Result,
				"%s under named OID must be denied; got %v %q", name, resp.Result, resp.Message)
			assert.Contains(t, resp.Message, "unsupported ASN.1 type or string encoding",
				"denial should be actionable: %s", resp.Message)
		})
	}
}

// TestEvaluate_OtherAttribute_UnsupportedEncodingDenied — opted-in unmapped
// OIDs are subject to the same rule: an unsupported-encoding value is denied
// even with a matching otherAttributes allow-list entry.
func TestEvaluate_OtherAttribute_UnsupportedEncodingDenied(t *testing.T) {
	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				CommonName: &policyapi.CertificateRequestPolicyAllowedString{Value: new("*.tenant.example.com")},
				Subject: &policyapi.CertificateRequestPolicyAllowedX509Subject{
					OtherAttributes: []policyapi.CertificateRequestPolicyAllowedSubjectOtherAttribute{
						{OID: testOIDEmailAddress.String(), Values: new([]string{"*@tenant.example.com"})},
					},
				},
			},
		},
	}
	resp := evalSubject(t, pkix.RDNSequence{
		rdn(oidCommonName, "app.tenant.example.com"),
		rawATVRDN(testOIDEmailAddress, universalStringRV("ops@tenant.example.com")),
	}, policy)
	assert.Equal(t, approver.ResultDenied, resp.Result,
		"UniversalString under an opted-in OID must be denied; got %v %q", resp.Result, resp.Message)
}
