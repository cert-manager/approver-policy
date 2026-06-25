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
	"strings"
	"testing"

	"github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/assert"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
)

// OIDs used across the bypass-fix tests.
var (
	testOIDCommonName   = asn1.ObjectIdentifier{2, 5, 4, 3}
	testOIDEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
)

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
