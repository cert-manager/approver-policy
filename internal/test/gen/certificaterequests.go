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

package gen

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"
	"testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	cmpki "github.com/jetstack/cert-manager/pkg/util/pki"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CertificateRequestOptions are passed to MustCertificateRequest
type CertificateRequestOptions struct {
	IssuerName  string
	IssuerKind  string
	IssuerGroup string

	Duration     *metav1.Duration
	CommonName   string
	DNSNames     []string
	IPs          []net.IP
	URIs         []string
	KeyAlgorithm x509.PublicKeyAlgorithm
	CA           bool
}

// MustCertificateRequest will build a cert-manager CertificateRequest with the
// supplied options for use in test cases
func MustCertificateRequest(t *testing.T, opts CertificateRequestOptions) *cmapi.CertificateRequest {
	var parsedURIs []*url.URL
	for _, uri := range opts.URIs {
		parsed, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		parsedURIs = append(parsedURIs, parsed)
	}

	var sk crypto.Signer
	var signatureAlgorithm x509.SignatureAlgorithm
	var err error

	if opts.KeyAlgorithm == 0 {
		opts.KeyAlgorithm = x509.RSA
	}

	switch opts.KeyAlgorithm {
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
		PublicKeyAlgorithm: opts.KeyAlgorithm,
		PublicKey:          sk.Public(),
		Subject: pkix.Name{
			CommonName: opts.CommonName,
		},
		DNSNames:    opts.DNSNames,
		IPAddresses: opts.IPs,
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
			Duration: opts.Duration,
			Request:  csrPEM,
			IsCA:     opts.CA,
			IssuerRef: cmmeta.ObjectReference{
				Name:  opts.IssuerName,
				Kind:  opts.IssuerKind,
				Group: opts.IssuerGroup,
			},
		},
	}
}
