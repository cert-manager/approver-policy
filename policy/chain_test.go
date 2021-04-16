/*
Copyright 2021 The cert-manager Authors.

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

package policy

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"
	"testing"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmpki "github.com/jetstack/cert-manager/pkg/util/pki"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmpolicy "github.com/cert-manager/policy-approver/api/v1alpha1"
)

func TestEvaluateCertificateRequest(t *testing.T) {
	tests := map[string]struct {
		request requestOptions
		policy  cmpolicy.CertificateRequestPolicySpec
		expEl   *field.ErrorList
	}{
		"any request with all fields nil shouldn't return error": {
			request: requestOptions{
				commonName: "test",
				issuerName: "my-issuer",
			},
			policy: cmpolicy.CertificateRequestPolicySpec{},
			expEl:  new(field.ErrorList),
		},
		"violations should return errors": {
			request: requestOptions{
				commonName: "test",
				ca:         true,
				duration: &metav1.Duration{
					Duration: time.Hour * 100,
				},
				dnsNames: []string{
					"foo.bar",
					"example.com",
				},
				ips: []net.IP{
					net.ParseIP("1.2.3.4"),
				},
				uris: []string{
					"hello.world",
				},
				keyAlgorithm: x509.RSA,
				issuerName:   "my-issuer",
				issuerKind:   "my-kind",
				issuerGroup:  "my-group",
			},
			policy: cmpolicy.CertificateRequestPolicySpec{
				AllowedCommonName: stringPtr("not-test"),
				AllowedIsCA:       boolPtr(false),
				MinDuration: &metav1.Duration{
					Duration: time.Hour * 200,
				},
				AllowedDNSNames: &[]string{
					"not-foo.bar",
				},
				AllowedIPAddresses: &[]string{
					"5.6.7.8",
				},
				AllowedURIs: &[]string{
					"world.hello",
				},
				AllowedPrivateKey: &cmpolicy.PolicyPrivateKey{
					AllowedAlgorithm: algPtr(cmapi.ECDSAKeyAlgorithm),
				},
				AllowedIssuers: &[]cmmeta.ObjectReference{
					{
						Name:  "not-my-issuer",
						Kind:  "not-my-kind",
						Group: "not-my-group",
					},
				},
			},
			expEl: &field.ErrorList{
				field.Invalid(field.NewPath("spec.allowedCommonName"), "test", "not-test"),
				field.Invalid(field.NewPath("spec.minDuration"), "100h0m0s", "200h0m0s"),
				field.Invalid(field.NewPath("spec.allowedDNSNames"), []string{"foo.bar", "example.com"}, "[not-foo.bar]"),
				field.Invalid(field.NewPath("spec.allowedIPAddresses"), []string{"1.2.3.4"}, "[5.6.7.8]"),
				field.Invalid(field.NewPath("spec.allowedURIs"), []string{"hello.world"}, "[world.hello]"),
				field.Invalid(field.NewPath("spec.allowedIssuers"), cmmeta.ObjectReference{Name: "my-issuer", Kind: "my-kind", Group: "my-group"}, "[{not-my-issuer not-my-kind not-my-group}]"),
				field.Invalid(field.NewPath("spec.allowedIsCA"), true, "false"),
				field.Invalid(field.NewPath("spec.allowedPrivateKey.allowedAlgorithm"), cmapi.RSAKeyAlgorithm, "ECDSA"),
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cr := mustCertificateRequest(t, test.request)

			el := new(field.ErrorList)
			evaluateCertificateRequest(el, &cmpolicy.CertificateRequestPolicy{Spec: test.policy}, cr)

			if !apiequality.Semantic.DeepEqual(el, test.expEl) {
				t.Errorf("unexpected error, exp=%v got=%v",
					test.expEl, el)
			}
		})
	}
}

type requestOptions struct {
	issuerName, issuerKind, issuerGroup string

	duration     *metav1.Duration
	commonName   string
	dnsNames     []string
	ips          []net.IP
	uris         []string
	keyAlgorithm x509.PublicKeyAlgorithm
	ca           bool
}

func mustCertificateRequest(t *testing.T, opts requestOptions) *cmapi.CertificateRequest {
	var parsedURIs []*url.URL
	for _, uri := range opts.uris {
		parsed, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		parsedURIs = append(parsedURIs, parsed)
	}

	var sk crypto.Signer
	var signatureAlgorithm x509.SignatureAlgorithm
	var err error

	if opts.keyAlgorithm == 0 {
		opts.keyAlgorithm = x509.RSA
	}

	switch opts.keyAlgorithm {
	case x509.RSA:
		sk, err = cmpki.GenerateRSAPrivateKey(2048)
		if err != nil {
			t.Fatal(err)
		}
		signatureAlgorithm = x509.SHA256WithRSA
	case x509.ECDSA:
		sk, err = cmpki.GenerateECPrivateKey(cmpki.ECCurve256)
		if err != nil {
			t.Fatal(err)
		}
		signatureAlgorithm = x509.ECDSAWithSHA256
	default:
		t.Fatalf("unrecognised key algorithm: %s", err)
	}

	csr := &x509.CertificateRequest{
		Version:            3,
		SignatureAlgorithm: signatureAlgorithm,
		PublicKeyAlgorithm: opts.keyAlgorithm,
		PublicKey:          sk.Public(),
		Subject: pkix.Name{
			CommonName: opts.commonName,
		},
		DNSNames:    opts.dnsNames,
		IPAddresses: opts.ips,
		URIs:        parsedURIs,
	}

	csrBytes, err := cmpki.EncodeCSR(csr, sk)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrBytes,
	})

	return &cmapi.CertificateRequest{
		Spec: cmapi.CertificateRequestSpec{
			Duration: opts.duration,
			Request:  csrPEM,
			IsCA:     opts.ca,
			IssuerRef: cmmeta.ObjectReference{
				Name:  opts.issuerName,
				Kind:  opts.issuerKind,
				Group: opts.issuerGroup,
			},
		},
	}
}

func intPtr(i int) *int {
	return &i
}
func stringPtr(s string) *string {
	return &s
}
func boolPtr(b bool) *bool {
	return &b
}
func algPtr(alg cmapi.PrivateKeyAlgorithm) *cmapi.PrivateKeyAlgorithm {
	return &alg
}
