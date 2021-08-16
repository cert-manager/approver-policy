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

package attribute

import (
	"context"
	"crypto/x509"
	"net"
	"net/url"
	"testing"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/pointer"

	cmpapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/pkg/approver"
)

func TestEvaluateCertificateRequest(t *testing.T) {
	var ecdaKeyAlg = cmapi.ECDSAKeyAlgorithm

	urlHelloWorld, err := url.Parse("hello.world")
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		policy      cmpapi.CertificateRequestPolicySpec
		request     *cmapi.CertificateRequest
		expResponse approver.EvaluationResponse
	}{
		"any request with all fields nil shouldn't return error": {
			request: gen.CertificateRequest("",
				gen.SetCertificateRequestCSR(csrFrom(t, x509.ECDSA,
					gen.SetCSRCommonName("test"),
				)),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "my-issuer",
				}),
			),
			policy: cmpapi.CertificateRequestPolicySpec{},
			expResponse: approver.EvaluationResponse{
				Result:  approver.ResultNotDenied,
				Message: "",
			},
		},
		"violations should return errors": {
			request: gen.CertificateRequest("",
				gen.SetCertificateRequestCSR(csrFrom(t, x509.RSA,
					gen.SetCSRCommonName("test"),
					gen.SetCSRDNSNames("foo.bar", "example.com"),
					gen.SetCSRURIs(urlHelloWorld),
					gen.SetCSRIPAddresses(net.ParseIP("1.2.3.4")),
				)),
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name:  "my-issuer",
					Kind:  "my-kind",
					Group: "my-group",
				}),
				gen.SetCertificateRequestIsCA(true),
				gen.SetCertificateRequestDuration(&metav1.Duration{Duration: time.Hour * 100}),
			),
			policy: cmpapi.CertificateRequestPolicySpec{
				AllowedCommonName: pointer.String("not-test"),
				AllowedIsCA:       pointer.Bool(false),
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
				AllowedPrivateKey: &cmpapi.PolicyPrivateKey{
					AllowedAlgorithm: &ecdaKeyAlg,
				},
				AllowedIssuers: &[]cmmeta.ObjectReference{
					{
						Name:  "not-my-issuer",
						Kind:  "not-my-kind",
						Group: "not-my-group",
					},
				},
			},
			expResponse: approver.EvaluationResponse{
				Result: approver.ResultDenied,
				Message: field.ErrorList{
					field.Invalid(field.NewPath("spec.allowedCommonName"), "test", "not-test"),
					field.Invalid(field.NewPath("spec.minDuration"), "100h0m0s", "200h0m0s"),
					field.Invalid(field.NewPath("spec.allowedDNSNames"), []string{"foo.bar", "example.com"}, "[not-foo.bar]"),
					field.Invalid(field.NewPath("spec.allowedIPAddresses"), []string{"1.2.3.4"}, "[5.6.7.8]"),
					field.Invalid(field.NewPath("spec.allowedURIs"), []string{"hello.world"}, "[world.hello]"),
					field.Invalid(field.NewPath("spec.allowedIssuers"), cmmeta.ObjectReference{Name: "my-issuer", Kind: "my-kind", Group: "my-group"}, "[{not-my-issuer not-my-kind not-my-group}]"),
					field.Invalid(field.NewPath("spec.allowedIsCA"), true, "false"),
					field.Invalid(field.NewPath("spec.allowedPrivateKey.allowedAlgorithm"), cmapi.RSAKeyAlgorithm, "ECDSA"),
				}.ToAggregate().Error(),
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cr := gen.MustCertificateRequest(t, test.request)

			response, err := attribute{}.Evaluate(context.TODO(), &cmpapi.CertificateRequestPolicy{Spec: test.policy}, cr)
			assert.NoError(t, err)
			assert.Equal(t, test.expResponse, response, "unexpected evaluation response")
		})
	}
}

func csrFrom(t *testing.T, keyAlgorithm x509.PublicKeyAlgorithm, mods ...gen.CSRModifier) []byte {
	csr, _, err := gen.CSR(keyAlgorithm, mods...)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}
