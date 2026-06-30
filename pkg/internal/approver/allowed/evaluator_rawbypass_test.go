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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"strings"
	"testing"

	"github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/assert"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
)

// OIDs used across the bypass-fix tests.
var (
	testOIDUPN = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	testOIDSAN = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// withRawSAN injects a raw SAN extension whose GeneralName entries are
// supplied as-is. Use this when a test needs SAN GeneralName tags that the
// stdlib CSR builder cannot emit through csr.DNSNames/IPAddresses/URIs/
// EmailAddresses (i.e. otherName / directoryName / x400 / ediParty / regID).
func withRawSAN(t *testing.T, gns ...asn1.RawValue) gen.CSRModifier {
	t.Helper()
	body, err := asn1.Marshal(gns)
	if err != nil {
		t.Fatalf("marshal SAN GeneralNames: %v", err)
	}
	return func(c *x509.CertificateRequest) error {
		c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{
			Id:    testOIDSAN,
			Value: body,
		})
		return nil
	}
}

// dnsGN builds a dNSName SAN GeneralName entry (tag 2).
func dnsGN(name string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(name)}
}

// otherNameGN builds a SAN otherName GeneralName entry (tag 0) with a
// UTF8String value — the encoding used in practice for the Microsoft UPN
// otherName payload.
//
//	otherName ::= [0] IMPLICIT SEQUENCE {
//	    type-id OBJECT IDENTIFIER,
//	    value   [0] EXPLICIT ANY DEFINED BY type-id }
//
// asn1.MarshalWithParams emits FullBytes verbatim for asn1.RawValue inputs,
// so the [0] EXPLICIT wrapper around the inner value must be constructed by
// hand rather than relying on `asn1:"explicit,tag:0"` reflection tags.
func otherNameGN(t *testing.T, oid asn1.ObjectIdentifier, value string) asn1.RawValue {
	t.Helper()
	innerUTF8, err := asn1.MarshalWithParams(value, "utf8")
	if err != nil {
		t.Fatalf("marshal UTF8String: %v", err)
	}
	explicitWrap, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      innerUTF8,
	})
	if err != nil {
		t.Fatalf("marshal [0] EXPLICIT wrapper: %v", err)
	}
	oidDER, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatalf("marshal otherName OID: %v", err)
	}
	seqContent := slices.Concat(oidDER, explicitWrap)
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      seqContent,
	}
}

// constructedGN builds a context-specific constructed GeneralName entry with
// the given tag and inner bytes. Used to fabricate directoryName /
// x400Address / ediPartyName entries cheaply; the exact inner content does
// not matter — these tags are always denied.
func constructedGN(tag int, inner []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner}
}

// registeredIDGN builds a registeredID GeneralName entry (tag 8, primitive,
// content is the OID bytes).
func registeredIDGN(t *testing.T, oid asn1.ObjectIdentifier) asn1.RawValue {
	t.Helper()
	oidDER, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatalf("marshal registeredID OID: %v", err)
	}
	// oidDER starts with 06 LEN <bytes>; we want just the content for the
	// primitive [8] wrapper.
	if len(oidDER) < 2 || oidDER[0] != 0x06 {
		t.Fatalf("unexpected OID DER: %x", oidDER)
	}
	contentLen := int(oidDER[1])
	if contentLen >= 0x80 || 2+contentLen != len(oidDER) {
		t.Fatalf("unsupported OID length encoding: %x", oidDER)
	}
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 8, Bytes: oidDER[2:]}
}

// TestEvaluate_SANOtherNameDeniedByDefault — a SAN containing an
// otherName UPN entry must be denied when no allowed.otherNames entry
// covers that OID, even if the DNS portion of the SAN is permitted.
func TestEvaluate_SANOtherNameDeniedByDefault(t *testing.T) {
	csr := csrFrom(t, withRawSAN(t,
		dnsGN("allowed.example.com"),
		otherNameGN(t, testOIDUPN, "administrator@victim.corp"),
	))
	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{
					Values: new([]string{"allowed.example.com"}),
				},
				// No OtherNames: the UPN must be denied.
			},
		},
	}
	resp, err := Approver().Evaluate(t.Context(), policy,
		gen.CertificateRequest("", gen.SetCertificateRequestCSR(csr)))
	assert.NoError(t, err)
	assert.Equal(t, approver.ResultDenied, resp.Result,
		"otherName UPN must be denied by default; got Result=%v Message=%q", resp.Result, resp.Message)
	assert.True(t, strings.Contains(resp.Message, "administrator@victim.corp"),
		"denial message should include the decoded UPN value: %s", resp.Message)
}

// TestEvaluate_SANOtherNameAllowedByPolicy — operators that
// genuinely need UPN otherNames (smart-card / EAP-TLS / AD-integrated
// workloads) can opt in via allowed.otherNames. With a matching Values
// entry, the request is approved.
func TestEvaluate_SANOtherNameAllowedByPolicy(t *testing.T) {
	csr := csrFrom(t, withRawSAN(t,
		dnsGN("allowed.example.com"),
		otherNameGN(t, testOIDUPN, "user@tenant.example.com"),
	))
	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{
					Values: new([]string{"allowed.example.com"}),
				},
				OtherNames: []policyapi.CertificateRequestPolicyAllowedOtherName{
					{
						OID:    testOIDUPN.String(),
						Values: new([]string{"*@tenant.example.com"}),
					},
				},
			},
		},
	}
	resp, err := Approver().Evaluate(t.Context(), policy,
		gen.CertificateRequest("", gen.SetCertificateRequestCSR(csr)))
	assert.NoError(t, err)
	assert.Equal(t, approver.ResultNotDenied, resp.Result,
		"otherName UPN matching otherNames wildcard must be approved; got Result=%v Message=%q", resp.Result, resp.Message)
}

// TestEvaluate_SANOtherNameValueMismatch — opted-in otherName OIDs
// still get their values policed: a value outside Values must be denied.
func TestEvaluate_SANOtherNameValueMismatch(t *testing.T) {
	csr := csrFrom(t, withRawSAN(t,
		dnsGN("allowed.example.com"),
		otherNameGN(t, testOIDUPN, "administrator@victim.corp"),
	))
	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{
					Values: new([]string{"allowed.example.com"}),
				},
				OtherNames: []policyapi.CertificateRequestPolicyAllowedOtherName{
					{
						OID:    testOIDUPN.String(),
						Values: new([]string{"*@tenant.example.com"}),
					},
				},
			},
		},
	}
	resp, err := Approver().Evaluate(t.Context(), policy,
		gen.CertificateRequest("", gen.SetCertificateRequestCSR(csr)))
	assert.NoError(t, err)
	assert.Equal(t, approver.ResultDenied, resp.Result,
		"otherName UPN with mismatching value must be denied; got Result=%v Message=%q", resp.Result, resp.Message)
}

// TestEvaluate_SANOtherNameRequired — an otherNames entry with
// required=true forces the OID to be present on the request.
func TestEvaluate_SANOtherNameRequired(t *testing.T) {
	// SAN does NOT carry UPN, despite the policy requiring it.
	csr := csrFrom(t, withRawSAN(t, dnsGN("allowed.example.com")))
	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{
					Values: new([]string{"allowed.example.com"}),
				},
				OtherNames: []policyapi.CertificateRequestPolicyAllowedOtherName{
					{
						OID:      testOIDUPN.String(),
						Values:   new([]string{"*@tenant.example.com"}),
						Required: new(true),
					},
				},
			},
		},
	}
	resp, err := Approver().Evaluate(t.Context(), policy,
		gen.CertificateRequest("", gen.SetCertificateRequestCSR(csr)))
	assert.NoError(t, err)
	assert.Equal(t, approver.ResultDenied, resp.Result,
		"missing required otherName must be denied; got Result=%v Message=%q", resp.Result, resp.Message)
}

// TestEvaluate_SANForbiddenTypesAlwaysDenied — SAN GeneralName
// types other than rfc822Name/dNSName/uniformResourceIdentifier/iPAddress/
// otherName (i.e. x400Address tag 3, directoryName tag 4, ediPartyName
// tag 5, registeredID tag 8) are always denied. There is no opt-in
// mechanism for these.
func TestEvaluate_SANForbiddenTypesAlwaysDenied(t *testing.T) {
	// A short DER blob that's valid enough to live inside a context-
	// specific constructed wrapper; the inner content is never inspected.
	dummyInner, err := asn1.Marshal("dummy")
	if err != nil {
		t.Fatalf("marshal dummy: %v", err)
	}

	cases := map[string]asn1.RawValue{
		"x400Address":   constructedGN(3, dummyInner),
		"directoryName": constructedGN(4, dummyInner),
		"ediPartyName":  constructedGN(5, dummyInner),
		"registeredID":  registeredIDGN(t, asn1.ObjectIdentifier{1, 2, 3, 4, 5}),
	}

	for name, gn := range cases {
		t.Run(name, func(t *testing.T) {
			csr := csrFrom(t, withRawSAN(t, dnsGN("allowed.example.com"), gn))
			policy := &policyapi.CertificateRequestPolicy{
				Spec: policyapi.CertificateRequestPolicySpec{
					Allowed: &policyapi.CertificateRequestPolicyAllowed{
						DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{
							Values: new([]string{"allowed.example.com"}),
						},
					},
				},
			}
			resp, err := Approver().Evaluate(t.Context(), policy,
				gen.CertificateRequest("", gen.SetCertificateRequestCSR(csr)))
			assert.NoError(t, err)
			assert.Equal(t, approver.ResultDenied, resp.Result,
				"%s SAN entry must always be denied; got Result=%v Message=%q",
				name, resp.Result, resp.Message)
		})
	}
}

// TestEvaluate_SANDNSOnlyUnaffected — a SAN containing only
// allowed dNSName entries continues to be approved; the new SAN walker
// must not regress the existing DNS-only path.
func TestEvaluate_SANDNSOnlyUnaffected(t *testing.T) {
	// Two distinct DNS entries — exercises the regression-guard path
	// (multi-DNS SAN with a wildcard policy still approves) and confirms
	// the new SAN walker doesn't trip on legitimate stacked dNSName tags.
	csr := csrFrom(t, withRawSAN(t,
		dnsGN("allowed.example.com"),
		dnsGN("api.allowed.example.com"),
	))
	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{
					Values: new([]string{"*.example.com", "allowed.example.com"}),
				},
			},
		},
	}
	resp, err := Approver().Evaluate(t.Context(), policy,
		gen.CertificateRequest("", gen.SetCertificateRequestCSR(csr)))
	assert.NoError(t, err)
	assert.Equal(t, approver.ResultNotDenied, resp.Result,
		"multi-DNS SAN matching the policy must remain approved; got Result=%v Message=%q", resp.Result, resp.Message)
}
