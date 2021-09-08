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

package allowed

import (
	"context"
	"crypto/x509"
	"net"
	"net/url"
	"testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/jetstack/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/pointer"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
)

func Test_Evaluate(t *testing.T) {
	uri1, err := url.Parse("spiffe://cluster.local/ns/foo/sa/bar")
	if err != nil {
		t.Fatal(err)
	}
	uri2, err := url.Parse("foo.bar.com")
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		policy      policyapi.CertificateRequestPolicySpec
		request     *cmapi.CertificateRequest
		expResponse approver.EvaluationResponse
		expErr      bool
	}{
		"if no allowed defined, no attributes set in request, return NotDenied": {
			request: gen.CertificateRequest("", gen.SetCertificateRequestCSR(csrFrom(t, x509.ECDSA))),
			policy: policyapi.CertificateRequestPolicySpec{
				Allowed: nil,
			},
			expResponse: approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: ""},
		},
		"if no allowed defined, all attributes set in request, return Denied": {
			request: gen.CertificateRequest("", gen.SetCertificateRequestCSR(csrFrom(t, x509.ECDSA,
				gen.SetCSRCommonName("hello-world"),
				gen.SetCSRDNSNames("example.com", "foo.bar"),
				gen.SetCSRIPAddresses(net.ParseIP("1.1.1.1"), net.ParseIP("2.3.4.5")),
				gen.SetCSRURIs(uri1, uri2),
				gen.SetCSREmails([]string{"foo@example.com", "bar@example.com"}),
				func(csr *x509.CertificateRequest) { csr.Subject.Organization = []string{"company-1", "company-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.Country = []string{"country-1", "country-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.OrganizationalUnit = []string{"org-1", "org-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.Locality = []string{"loc-1", "loc-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.Province = []string{"prov-1", "prov-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.StreetAddress = []string{"street-1", "street-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.PostalCode = []string{"post-1", "post-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.SerialNumber = "serial-1" },
			)),
				gen.SetCertificateRequestIsCA(true),
				gen.SetCertificateRequestKeyUsages(cmapi.UsageCRLSign, cmapi.UsageClientAuth),
			),
			policy: policyapi.CertificateRequestPolicySpec{
				Allowed: nil,
			},
			expResponse: approver.EvaluationResponse{
				Result: approver.ResultDenied,
				Message: field.ErrorList{
					field.Invalid(field.NewPath("spec.allowed.commonName"), "hello-world", "nil"),
					field.Invalid(field.NewPath("spec.allowed.dnsNames"), []string{"example.com", "foo.bar"}, "nil"),
					field.Invalid(field.NewPath("spec.allowed.ipAddresses"), []string{"1.1.1.1", "2.3.4.5"}, "nil"),
					field.Invalid(field.NewPath("spec.allowed.uris"), []string{"spiffe://cluster.local/ns/foo/sa/bar", "foo.bar.com"}, "nil"),
					field.Invalid(field.NewPath("spec.allowed.emailAddresses"), []string{"foo@example.com", "bar@example.com"}, "nil"),
					field.Invalid(field.NewPath("spec.allowed.isCA"), true, "nil"),
					field.Invalid(field.NewPath("spec.allowed.usages"), []string{"crl sign", "client auth"}, "nil"),
					field.Invalid(field.NewPath("spec.allowed.subject.organizations"), []string{"company-1", "company-2"}, "nil"),
					field.Invalid(field.NewPath("spec.allowed.subject.countries"), []string{"country-1", "country-2"}, "nil"),
					field.Invalid(field.NewPath("spec.allowed.subject.organizationalUnits"), []string{"org-1", "org-2"}, "nil"),
					field.Invalid(field.NewPath("spec.allowed.subject.localities"), []string{"loc-1", "loc-2"}, "nil"),
					field.Invalid(field.NewPath("spec.allowed.subject.provinces"), []string{"prov-1", "prov-2"}, "nil"),
					field.Invalid(field.NewPath("spec.allowed.subject.streetAddresses"), []string{"street-1", "street-2"}, "nil"),
					field.Invalid(field.NewPath("spec.allowed.subject.postalCodes"), []string{"post-1", "post-2"}, "nil"),
					field.Invalid(field.NewPath("spec.allowed.subject.serialNumber"), "serial-1", "nil"),
				}.ToAggregate().Error(),
			},
		},
		"if all allowed defined, all attributes set in request but are different, return Denied": {
			request: gen.CertificateRequest("", gen.SetCertificateRequestCSR(csrFrom(t, x509.ECDSA,
				gen.SetCSRCommonName("hello-world"),
				gen.SetCSRDNSNames("example.com", "foo.bar"),
				gen.SetCSRIPAddresses(net.ParseIP("1.1.1.1"), net.ParseIP("2.3.4.5")),
				gen.SetCSRURIs(uri1, uri2),
				gen.SetCSREmails([]string{"foo@example.com", "bar@example.com"}),
				func(csr *x509.CertificateRequest) { csr.Subject.Organization = []string{"company-1", "company-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.Country = []string{"country-1", "country-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.OrganizationalUnit = []string{"org-1", "org-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.Locality = []string{"loc-1", "loc-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.Province = []string{"prov-1", "prov-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.StreetAddress = []string{"street-1", "street-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.PostalCode = []string{"post-1", "post-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.SerialNumber = "serial-1" },
			)),
				gen.SetCertificateRequestIsCA(true),
				gen.SetCertificateRequestKeyUsages(cmapi.UsageCRLSign, cmapi.UsageClientAuth),
			),
			policy: policyapi.CertificateRequestPolicySpec{
				Allowed: &policyapi.CertificateRequestPolicyAllowed{
					CommonName:     pointer.String("hello-world2"),
					DNSNames:       &[]string{"example.com2", "foo.bar2"},
					IPAddresses:    &[]string{"1.1.1.12", "2.3.4.52"},
					URIs:           &[]string{"spiffe://cluster.local/ns/foo/sa/bar2", "foo.bar.com2"},
					EmailAddresses: &[]string{"foo@example.com2", "bar@example.com2"},
					IsCA:           pointer.Bool(false),
					Usages:         &[]cmapi.KeyUsage{cmapi.UsageCRLSign, cmapi.UsageServerAuth},
					Subject: &policyapi.CertificateRequestPolicyAllowedX509Subject{
						Organizations:       &[]string{"company-3", "company-4"},
						Countries:           &[]string{"country-3", "country-4"},
						OrganizationalUnits: &[]string{"org-3", "org-4"},
						Localities:          &[]string{"loc-3", "loc-4"},
						Provinces:           &[]string{"prov-3", "prov-4"},
						StreetAddresses:     &[]string{"street-3", "street-4"},
						PostalCodes:         &[]string{"post-3", "post-4"},
						SerialNumber:        pointer.String("serial-2"),
					},
				},
			},
			expResponse: approver.EvaluationResponse{
				Result: approver.ResultDenied,
				Message: field.ErrorList{
					field.Invalid(field.NewPath("spec.allowed.commonName"), "hello-world", "hello-world2"),
					field.Invalid(field.NewPath("spec.allowed.dnsNames"), []string{"example.com", "foo.bar"}, "example.com2, foo.bar2"),
					field.Invalid(field.NewPath("spec.allowed.ipAddresses"), []string{"1.1.1.1", "2.3.4.5"}, "1.1.1.12, 2.3.4.52"),
					field.Invalid(field.NewPath("spec.allowed.uris"), []string{"spiffe://cluster.local/ns/foo/sa/bar", "foo.bar.com"}, "spiffe://cluster.local/ns/foo/sa/bar2, foo.bar.com2"),
					field.Invalid(field.NewPath("spec.allowed.emailAddresses"), []string{"foo@example.com", "bar@example.com"}, "foo@example.com2, bar@example.com2"),
					field.Invalid(field.NewPath("spec.allowed.isCA"), true, "false"),
					field.Invalid(field.NewPath("spec.allowed.usages"), []string{"crl sign", "client auth"}, "crl sign, server auth"),
					field.Invalid(field.NewPath("spec.allowed.subject.organizations"), []string{"company-1", "company-2"}, "company-3, company-4"),
					field.Invalid(field.NewPath("spec.allowed.subject.countries"), []string{"country-1", "country-2"}, "country-3, country-4"),
					field.Invalid(field.NewPath("spec.allowed.subject.organizationalUnits"), []string{"org-1", "org-2"}, "org-3, org-4"),
					field.Invalid(field.NewPath("spec.allowed.subject.localities"), []string{"loc-1", "loc-2"}, "loc-3, loc-4"),
					field.Invalid(field.NewPath("spec.allowed.subject.provinces"), []string{"prov-1", "prov-2"}, "prov-3, prov-4"),
					field.Invalid(field.NewPath("spec.allowed.subject.streetAddresses"), []string{"street-1", "street-2"}, "street-3, street-4"),
					field.Invalid(field.NewPath("spec.allowed.subject.postalCodes"), []string{"post-1", "post-2"}, "post-3, post-4"),
					field.Invalid(field.NewPath("spec.allowed.subject.serialNumber"), "serial-1", "serial-2"),
				}.ToAggregate().Error(),
			},
		},
		"if all allowed defined, all attributes set in request and match exactly, return Not-Denied": {
			request: gen.CertificateRequest("", gen.SetCertificateRequestCSR(csrFrom(t, x509.ECDSA,
				gen.SetCSRCommonName("hello-world"),
				gen.SetCSRDNSNames("example.com", "foo.bar", "*.example.com"),
				gen.SetCSRIPAddresses(net.ParseIP("1.1.1.1"), net.ParseIP("2.3.4.5")),
				gen.SetCSRURIs(uri1, uri2),
				gen.SetCSREmails([]string{"foo@example.com", "bar@example.com"}),
				func(csr *x509.CertificateRequest) { csr.Subject.Organization = []string{"company-1", "company-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.Country = []string{"country-1", "country-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.OrganizationalUnit = []string{"org-1", "org-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.Locality = []string{"loc-1", "loc-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.Province = []string{"prov-1", "prov-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.StreetAddress = []string{"street-1", "street-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.PostalCode = []string{"post-1", "post-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.SerialNumber = "serial-1" },
			)),
				gen.SetCertificateRequestIsCA(true),
				gen.SetCertificateRequestKeyUsages(cmapi.UsageCRLSign, cmapi.UsageClientAuth),
			),
			policy: policyapi.CertificateRequestPolicySpec{
				Allowed: &policyapi.CertificateRequestPolicyAllowed{
					CommonName:     pointer.String("hello-world"),
					DNSNames:       &[]string{"example.com", "foo.bar", "*.example.com"},
					IPAddresses:    &[]string{"1.1.1.1", "2.3.4.5"},
					URIs:           &[]string{"spiffe://cluster.local/ns/foo/sa/bar", "foo.bar.com"},
					EmailAddresses: &[]string{"foo@example.com", "bar@example.com"},
					IsCA:           pointer.Bool(true),
					Usages:         &[]cmapi.KeyUsage{cmapi.UsageCRLSign, cmapi.UsageClientAuth},
					Subject: &policyapi.CertificateRequestPolicyAllowedX509Subject{
						Organizations:       &[]string{"company-1", "company-2"},
						Countries:           &[]string{"country-1", "country-2"},
						OrganizationalUnits: &[]string{"org-1", "org-2"},
						Localities:          &[]string{"loc-1", "loc-2"},
						Provinces:           &[]string{"prov-1", "prov-2"},
						StreetAddresses:     &[]string{"street-1", "street-2"},
						PostalCodes:         &[]string{"post-1", "post-2"},
						SerialNumber:        pointer.String("serial-1"),
					},
				},
			},
			expResponse: approver.EvaluationResponse{
				Result:  approver.ResultNotDenied,
				Message: "",
			},
		},
		"if all allowed defined, all attributes set in request and match with wildcard, return Not-Denied": {
			request: gen.CertificateRequest("", gen.SetCertificateRequestCSR(csrFrom(t, x509.ECDSA,
				gen.SetCSRCommonName("hello-world"),
				gen.SetCSRDNSNames("example.com", "foo.bar"),
				gen.SetCSRIPAddresses(net.ParseIP("1.1.1.1"), net.ParseIP("2.3.4.5")),
				gen.SetCSRURIs(uri1, uri2),
				gen.SetCSREmails([]string{"foo@example.com", "bar@example.com"}),
				func(csr *x509.CertificateRequest) { csr.Subject.Organization = []string{"company-1", "company-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.Country = []string{"country-1", "country-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.OrganizationalUnit = []string{"org-1", "org-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.Locality = []string{"loc-1", "loc-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.Province = []string{"prov-1", "prov-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.StreetAddress = []string{"street-1", "street-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.PostalCode = []string{"post-1", "post-2"} },
				func(csr *x509.CertificateRequest) { csr.Subject.SerialNumber = "serial-1" },
			)),
				gen.SetCertificateRequestIsCA(true),
				gen.SetCertificateRequestKeyUsages(cmapi.UsageCRLSign, cmapi.UsageClientAuth),
			),
			policy: policyapi.CertificateRequestPolicySpec{
				Allowed: &policyapi.CertificateRequestPolicyAllowed{
					CommonName:     pointer.String("hello-*"),
					DNSNames:       &[]string{"example.*", "*.bar"},
					IPAddresses:    &[]string{"1.1*", "*2.3.4.5"},
					URIs:           &[]string{"spiffe://cluster.local/*/foo/sa/bar", "*.bar.com"},
					EmailAddresses: &[]string{"foo@*", "*r@example.com"},
					IsCA:           pointer.Bool(true),
					Usages:         &[]cmapi.KeyUsage{cmapi.UsageCRLSign, cmapi.UsageClientAuth},
					Subject: &policyapi.CertificateRequestPolicyAllowedX509Subject{
						Organizations:       &[]string{"company*"},
						Countries:           &[]string{"country*"},
						OrganizationalUnits: &[]string{"*-1", "*-2"},
						Localities:          &[]string{"loc-*", "*-2"},
						Provinces:           &[]string{"prov*"},
						StreetAddresses:     &[]string{"street-1", "street-*"},
						PostalCodes:         &[]string{"post-1", "post-2"},
						SerialNumber:        pointer.String("serial-*"),
					},
				},
			},
			expResponse: approver.EvaluationResponse{
				Result:  approver.ResultNotDenied,
				Message: "",
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			response, err := Allowed{}.Evaluate(context.TODO(), &policyapi.CertificateRequestPolicy{Spec: test.policy}, test.request)
			assert.Equal(t, test.expErr, err != nil, "%v", err)
			assert.Equal(t, test.expResponse, response, "unexpected evaluation response")
		})
	}
}

func csrFrom(t *testing.T, keyAlgorithm x509.PublicKeyAlgorithm, mods ...gen.CSRModifier) []byte {
	t.Helper()
	csr, _, err := gen.CSR(keyAlgorithm, mods...)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}
