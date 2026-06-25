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
	"encoding/pem"
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
	testOIDUPN          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	testOIDSAN          = asn1.ObjectIdentifier{2, 5, 29, 17}
	testOIDCommonName   = asn1.ObjectIdentifier{2, 5, 4, 3}
	testOIDEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
)

// ---------------------------------------------------------------------------
// SAN bypass helpers (VC-53795)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// RawSubject bypass helpers (VC-53794)
// ---------------------------------------------------------------------------

// withRawSubject overrides the CSR's Subject DER. x509.CreateCertificateRequest
// honours RawSubject verbatim and ignores the typed Subject when it is set, so
// this is the only reliable way to smuggle duplicate or unmapped RDN OIDs past
// the lossy pkix.Name projection.
func withRawSubject(t *testing.T, rdns pkix.RDNSequence) gen.CSRModifier {
	t.Helper()
	raw, err := asn1.Marshal(rdns)
	if err != nil {
		t.Fatalf("marshal RawSubject: %v", err)
	}
	return func(c *x509.CertificateRequest) error {
		c.RawSubject = raw
		return nil
	}
}

// rdn returns a single-ATV RDN carrying the given OID and string value,
// suitable for assembling into a pkix.RDNSequence.
func rdn(oid asn1.ObjectIdentifier, value string) pkix.RelativeDistinguishedNameSET {
	return pkix.RelativeDistinguishedNameSET{
		{Type: oid, Value: value},
	}
}

// rawATVRDN returns a single-ATV RDN whose value is an arbitrary Go type
// (e.g. []byte for OctetString). When marshaled into RawSubject this lets a
// test smuggle non-string values under named OIDs — the exact case
// pkix.Name.FillFromRDNSequence silently drops from its named slices.
func rawATVRDN(oid asn1.ObjectIdentifier, value any) pkix.RelativeDistinguishedNameSET {
	return pkix.RelativeDistinguishedNameSET{
		{Type: oid, Value: value},
	}
}

// ---------------------------------------------------------------------------
// SAN bypass tests (VC-53795)
// ---------------------------------------------------------------------------

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

// TestCryptoX509_DropsNonStandardSANTags is a canary test that asserts
// crypto/x509 silently drops GeneralName tags outside {1,2,6,7}
// (rfc822Name, dNSName, uniformResourceIdentifier, iPAddress) from its
// parsed slices. If a future Go version starts surfacing these tags, this
// test will fail — alerting us that the threat model for the raw SAN
// evaluator may need revisiting.
func TestCryptoX509_DropsNonStandardSANTags(t *testing.T) {
	dummyInner, err := asn1.Marshal("dummy")
	if err != nil {
		t.Fatalf("marshal dummy: %v", err)
	}

	csrPEM := csrFrom(t, withRawSAN(t,
		dnsGN("canary.example.com"),
		otherNameGN(t, testOIDUPN, "user@example.com"),
		constructedGN(3, dummyInner), // x400Address
		constructedGN(4, dummyInner), // directoryName
		constructedGN(5, dummyInner), // ediPartyName
		registeredIDGN(t, asn1.ObjectIdentifier{1, 2, 3, 4, 5}),
	))

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("failed to PEM-decode CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	assert.Equal(t, []string{"canary.example.com"}, csr.DNSNames,
		"crypto/x509 should parse dNSName (tag 2)")
	assert.Empty(t, csr.IPAddresses,
		"no iPAddress entries were added")
	assert.Empty(t, csr.URIs,
		"no URI entries were added")
	assert.Empty(t, csr.EmailAddresses,
		"no rfc822Name entries were added")

	// The key assertion: the otherName, x400Address, directoryName,
	// ediPartyName and registeredID entries we injected must NOT appear
	// anywhere in the parsed slices. If this fails after a Go upgrade,
	// the raw SAN evaluator's threat model should be re-evaluated.
	allParsed := len(csr.DNSNames) + len(csr.IPAddresses) + len(csr.URIs) + len(csr.EmailAddresses)
	assert.Equal(t, 1, allParsed,
		"crypto/x509 should only surface the single dNSName; tags {0,3,4,5,8} must be dropped — got %d parsed entries total", allParsed)
}

// ---------------------------------------------------------------------------
// RawSubject bypass tests (VC-53794)
// ---------------------------------------------------------------------------

// TestEvaluate_VC53794_DualCNDenied — a CSR whose Subject RawSubject DER
// contains two CN RDNs (kubernetes-admin THEN app.tenant.example.com) must
// be denied even when the policy permits the second value. The lossy
// pkix.Name projection used to keep only the last CN and approve.
func TestEvaluate_VC53794_DualCNDenied(t *testing.T) {
	csr := csrFrom(t,
		withRawSubject(t, pkix.RDNSequence{
			rdn(testOIDCommonName, "kubernetes-admin"),
			rdn(testOIDCommonName, "app.tenant.example.com"),
		}),
	)
	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				CommonName: &policyapi.CertificateRequestPolicyAllowedString{
					Value: new("*.tenant.example.com"),
				},
			},
		},
	}
	resp, err := Approver().Evaluate(t.Context(), policy,
		gen.CertificateRequest("", gen.SetCertificateRequestCSR(csr)))
	assert.NoError(t, err)
	assert.Equal(t, approver.ResultDenied, resp.Result,
		"dual-CN CSR must be denied; got Result=%v Message=%q", resp.Result, resp.Message)
	assert.Contains(t, resp.Message, "kubernetes-admin",
		"denial message should call out the forbidden CN")
}

// TestEvaluate_VC53794_DualCNBothAllowed — when the policy's commonName
// wildcard matches BOTH CN values, the CSR is approved. Confirms the gate
// is per-value rather than blanket-rejecting duplicates.
func TestEvaluate_VC53794_DualCNBothAllowed(t *testing.T) {
	csr := csrFrom(t,
		withRawSubject(t, pkix.RDNSequence{
			rdn(testOIDCommonName, "a.tenant.example.com"),
			rdn(testOIDCommonName, "b.tenant.example.com"),
		}),
	)
	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				CommonName: &policyapi.CertificateRequestPolicyAllowedString{
					Value: new("*.tenant.example.com"),
				},
			},
		},
	}
	resp, err := Approver().Evaluate(t.Context(), policy,
		gen.CertificateRequest("", gen.SetCertificateRequestCSR(csr)))
	assert.NoError(t, err)
	assert.Equal(t, approver.ResultNotDenied, resp.Result,
		"two CNs that both match the wildcard must be approved; got Result=%v Message=%q", resp.Result, resp.Message)
}

// TestEvaluate_VC53794_UnknownOIDDeniedByDefault — emailAddress, DC, UID,
// or any other Subject RDN OID outside the named allowed.subject.* set
// must be denied when there is no allowed.subject.otherAttributes entry
// covering it.
func TestEvaluate_VC53794_UnknownOIDDeniedByDefault(t *testing.T) {
	csr := csrFrom(t,
		withRawSubject(t, pkix.RDNSequence{
			rdn(testOIDCommonName, "app.tenant.example.com"),
			rdn(testOIDEmailAddress, "root@victim.corp"),
		}),
	)
	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				CommonName: &policyapi.CertificateRequestPolicyAllowedString{
					Value: new("*.tenant.example.com"),
				},
				// No Subject.OtherAttributes: emailAddress must be denied.
			},
		},
	}
	resp, err := Approver().Evaluate(t.Context(), policy,
		gen.CertificateRequest("", gen.SetCertificateRequestCSR(csr)))
	assert.NoError(t, err)
	assert.Equal(t, approver.ResultDenied, resp.Result,
		"unknown Subject OID must be denied by default; got Result=%v Message=%q", resp.Result, resp.Message)
	assert.True(t, strings.Contains(resp.Message, testOIDEmailAddress.String()),
		"denial message should mention the offending OID: %s", resp.Message)
}

// TestEvaluate_VC53794_UnknownOIDAllowedByOtherAttributes — operators that
// genuinely need emailAddress (or any unmapped OID) in the Subject can
// opt in via allowed.subject.otherAttributes. With a matching Values entry,
// the request is approved.
func TestEvaluate_VC53794_UnknownOIDAllowedByOtherAttributes(t *testing.T) {
	csr := csrFrom(t,
		withRawSubject(t, pkix.RDNSequence{
			rdn(testOIDCommonName, "app.tenant.example.com"),
			rdn(testOIDEmailAddress, "ops@tenant.example.com"),
		}),
	)
	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				CommonName: &policyapi.CertificateRequestPolicyAllowedString{
					Value: new("*.tenant.example.com"),
				},
				Subject: &policyapi.CertificateRequestPolicyAllowedX509Subject{
					OtherAttributes: []policyapi.CertificateRequestPolicyAllowedSubjectOtherAttribute{
						{
							OID:    testOIDEmailAddress.String(),
							Values: new([]string{"*@tenant.example.com"}),
						},
					},
				},
			},
		},
	}
	resp, err := Approver().Evaluate(t.Context(), policy,
		gen.CertificateRequest("", gen.SetCertificateRequestCSR(csr)))
	assert.NoError(t, err)
	assert.Equal(t, approver.ResultNotDenied, resp.Result,
		"emailAddress matching otherAttributes wildcard must be approved; got Result=%v Message=%q", resp.Result, resp.Message)
}

// TestEvaluate_VC53794_UnknownOIDValueMismatch — opted-in OIDs still get
// their values policed: a value outside Values must be denied.
func TestEvaluate_VC53794_UnknownOIDValueMismatch(t *testing.T) {
	csr := csrFrom(t,
		withRawSubject(t, pkix.RDNSequence{
			rdn(testOIDCommonName, "app.tenant.example.com"),
			rdn(testOIDEmailAddress, "root@victim.corp"),
		}),
	)
	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				CommonName: &policyapi.CertificateRequestPolicyAllowedString{
					Value: new("*.tenant.example.com"),
				},
				Subject: &policyapi.CertificateRequestPolicyAllowedX509Subject{
					OtherAttributes: []policyapi.CertificateRequestPolicyAllowedSubjectOtherAttribute{
						{
							OID:    testOIDEmailAddress.String(),
							Values: new([]string{"*@tenant.example.com"}),
						},
					},
				},
			},
		},
	}
	resp, err := Approver().Evaluate(t.Context(), policy,
		gen.CertificateRequest("", gen.SetCertificateRequestCSR(csr)))
	assert.NoError(t, err)
	assert.Equal(t, approver.ResultDenied, resp.Result,
		"emailAddress with mismatching value must be denied; got Result=%v Message=%q", resp.Result, resp.Message)
}

// TestEvaluate_VC53794_OtherAttributesRequired — an otherAttributes entry
// with required=true forces the OID to be present on the request.
func TestEvaluate_VC53794_OtherAttributesRequired(t *testing.T) {
	// Subject DOES NOT carry emailAddress, despite the policy requiring it.
	csr := csrFrom(t,
		withRawSubject(t, pkix.RDNSequence{
			rdn(testOIDCommonName, "app.tenant.example.com"),
		}),
	)
	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				CommonName: &policyapi.CertificateRequestPolicyAllowedString{
					Value: new("*.tenant.example.com"),
				},
				Subject: &policyapi.CertificateRequestPolicyAllowedX509Subject{
					OtherAttributes: []policyapi.CertificateRequestPolicyAllowedSubjectOtherAttribute{
						{
							OID:      testOIDEmailAddress.String(),
							Values:   new([]string{"*@tenant.example.com"}),
							Required: new(true),
						},
					},
				},
			},
		},
	}
	resp, err := Approver().Evaluate(t.Context(), policy,
		gen.CertificateRequest("", gen.SetCertificateRequestCSR(csr)))
	assert.NoError(t, err)
	assert.Equal(t, approver.ResultDenied, resp.Result,
		"missing required otherAttribute must be denied; got Result=%v Message=%q", resp.Result, resp.Message)
}

// TestEvaluate_VC53794_NonStringNamedOIDDenied — VC-53794 adjacent: a CSR
// whose Subject RawSubject contains a named-OID ATV (e.g. O=, OU=, L=, …)
// whose ASN.1 value is NOT a string (here, an OctetString) must be denied.
// pkix.Name.FillFromRDNSequence skips non-string ATVs, so without the
// integrity check the value is invisible to BOTH the named-field
// evaluators (which read pkix.Name.Organization etc.) AND the
// OtherAttributes walker (which `continue`s on named OIDs) — but the
// signer still emits it via csr.RawSubject.
func TestEvaluate_VC53794_NonStringNamedOIDDenied(t *testing.T) {
	// Subject = { CN=app.tenant.example.com, O=<OctetString "evil-corp"> }.
	csr := csrFrom(t, withRawSubject(t, pkix.RDNSequence{
		rdn(testOIDCommonName, "app.tenant.example.com"),
		rawATVRDN(oidOrganization, []byte("evil-corp")),
	}))
	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				CommonName: &policyapi.CertificateRequestPolicyAllowedString{
					Value: new("*.tenant.example.com"),
				},
				// allowed.subject is nil — Organization is implicitly
				// not allowed. Even without that, a non-string O=
				// value would bypass the existing slice check; the
				// fix denies it explicitly.
			},
		},
	}
	resp, err := Approver().Evaluate(t.Context(), policy,
		gen.CertificateRequest("", gen.SetCertificateRequestCSR(csr)))
	assert.NoError(t, err)
	assert.Equal(t, approver.ResultDenied, resp.Result,
		"non-string named-OID value must be denied; got Result=%v Message=%q", resp.Result, resp.Message)
	assert.Contains(t, resp.Message, oidOrganization.String(),
		"denial message should call out the offending named OID")
	assert.Contains(t, resp.Message, "non-string",
		"denial message should explain why the value was rejected")
}

// TestEvaluate_VC53794_MultiStringOrganizationStillWorks — regression guard
// for the named-OID consistency check: a CSR carrying two string-valued O=
// ATVs (a legitimate, common pattern) must still be approved when the
// policy permits both values. The integrity backstop must only fire on
// genuinely non-string values.
func TestEvaluate_VC53794_MultiStringOrganizationStillWorks(t *testing.T) {
	csr := csrFrom(t, withRawSubject(t, pkix.RDNSequence{
		rdn(testOIDCommonName, "app.tenant.example.com"),
		rdn(oidOrganization, "tenant-a"),
		rdn(oidOrganization, "tenant-platform"),
	}))
	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				CommonName: &policyapi.CertificateRequestPolicyAllowedString{
					Value: new("*.tenant.example.com"),
				},
				Subject: &policyapi.CertificateRequestPolicyAllowedX509Subject{
					Organizations: &policyapi.CertificateRequestPolicyAllowedStringSlice{
						Values: new([]string{"tenant-a", "tenant-platform"}),
					},
				},
			},
		},
	}
	resp, err := Approver().Evaluate(t.Context(), policy,
		gen.CertificateRequest("", gen.SetCertificateRequestCSR(csr)))
	assert.NoError(t, err)
	assert.Equal(t, approver.ResultNotDenied, resp.Result,
		"multi-string O= matching the policy must be approved; got Result=%v Message=%q", resp.Result, resp.Message)
}
