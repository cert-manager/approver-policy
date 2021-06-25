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
	"crypto/x509"
	"net"
	"testing"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmpolicy "github.com/cert-manager/policy-approver/pkg/api/v1alpha1"

	test "github.com/cert-manager/policy-approver/test/gen"
)

func TestEvaluateCertificateRequest(t *testing.T) {
	tests := map[string]struct {
		request test.RequestOptions
		policy  cmpolicy.CertificateRequestPolicySpec
		expEl   *field.ErrorList
	}{
		"any request with all fields nil shouldn't return error": {
			request: test.RequestOptions{
				CommonName: "test",
				IssuerName: "my-issuer",
			},
			policy: cmpolicy.CertificateRequestPolicySpec{},
			expEl:  new(field.ErrorList),
		},
		"violations should return errors": {
			request: test.RequestOptions{
				CommonName: "test",
				CA:         true,
				Duration: &metav1.Duration{
					Duration: time.Hour * 100,
				},
				DNSNames: []string{
					"foo.bar",
					"example.com",
				},
				IPs: []net.IP{
					net.ParseIP("1.2.3.4"),
				},
				URIs: []string{
					"hello.world",
				},
				KeyAlgorithm: x509.RSA,
				IssuerName:   "my-issuer",
				IssuerKind:   "my-kind",
				IssuerGroup:  "my-group",
			},
			policy: cmpolicy.CertificateRequestPolicySpec{
				AllowedCommonName: test.StringPtr("not-test"),
				AllowedIsCA:       test.BoolPtr(false),
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
					AllowedAlgorithm: test.AlgPtr(cmapi.ECDSAKeyAlgorithm),
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

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cr := test.MustCertificateRequest(t, tc.request)

			_, message, _ := evaluateChainChecks(&cmpolicy.CertificateRequestPolicy{Spec: tc.policy}, cr)

			expectedMessage := ""
			if len(*tc.expEl) > 0 {
				expectedMessage = tc.expEl.ToAggregate().Error()
			}

			if message != expectedMessage {
				t.Errorf("unexpected error, exp=%v got=%v", expectedMessage, message)
			}
		})
	}
}
