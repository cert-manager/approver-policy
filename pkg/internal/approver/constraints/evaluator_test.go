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

package constraints

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
)

func Test_Evaluate(t *testing.T) {
	var (
		ecdsaAlg = cmapi.ECDSAKeyAlgorithm
		rsaAlg   = cmapi.RSAKeyAlgorithm
	)

	tests := map[string]struct {
		policy      policyapi.CertificateRequestPolicySpec
		request     *cmapi.CertificateRequest
		expResponse approver.EvaluationResponse
		expErr      bool
	}{
		"if no constraints defined, should return NotDenied": {
			request: gen.CertificateRequest("", gen.SetCertificateRequestCSR(csrFrom(t, x509.ECDSA))),
			policy: policyapi.CertificateRequestPolicySpec{
				Constraints: nil,
			},
			expResponse: approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: ""},
		},
		"if constraints contains duration but duration wasn't requested, return Denied": {
			request: gen.CertificateRequest("",
				gen.SetCertificateRequestDuration(nil),
			),
			policy: policyapi.CertificateRequestPolicySpec{
				Constraints: &policyapi.CertificateRequestPolicyConstraints{
					MinDuration: &metav1.Duration{Duration: time.Hour},
					MaxDuration: &metav1.Duration{Duration: time.Hour * 24},
				},
			},
			expResponse: approver.EvaluationResponse{
				Result: approver.ResultDenied,
				Message: field.ErrorList{
					field.Invalid(field.NewPath("spec.constraints.maxDuration"), "nil", "24h0m0s"),
					field.Invalid(field.NewPath("spec.constraints.minDuration"), "nil", "1h0m0s"),
				}.ToAggregate().Error(),
			},
		},
		"if constraints contains duration but requested duration is too small, return Denied": {
			request: gen.CertificateRequest("",
				gen.SetCertificateRequestDuration(&metav1.Duration{Duration: time.Minute}),
			),
			policy: policyapi.CertificateRequestPolicySpec{
				Constraints: &policyapi.CertificateRequestPolicyConstraints{
					MinDuration: &metav1.Duration{Duration: time.Hour},
					MaxDuration: &metav1.Duration{Duration: time.Hour * 24},
				},
			},
			expResponse: approver.EvaluationResponse{
				Result:  approver.ResultDenied,
				Message: field.ErrorList{field.Invalid(field.NewPath("spec.constraints.minDuration"), "1m0s", "1h0m0s")}.ToAggregate().Error(),
			},
		},
		"if constraints contains duration but requested duration is too large, return Denied": {
			request: gen.CertificateRequest("",
				gen.SetCertificateRequestDuration(&metav1.Duration{Duration: time.Hour * 48}),
			),
			policy: policyapi.CertificateRequestPolicySpec{
				Constraints: &policyapi.CertificateRequestPolicyConstraints{
					MinDuration: &metav1.Duration{Duration: time.Hour},
					MaxDuration: &metav1.Duration{Duration: time.Hour * 24},
				},
			},
			expResponse: approver.EvaluationResponse{
				Result: approver.ResultDenied,
				Message: field.ErrorList{
					field.Invalid(field.NewPath("spec.constraints.maxDuration"), "48h0m0s", "24h0m0s"),
				}.ToAggregate().Error(),
			},
		},
		"if constraints contains private key but CSR fails to decode, return error": {
			request: gen.CertificateRequest("",
				gen.SetCertificateRequestDuration(nil),
			),
			policy: policyapi.CertificateRequestPolicySpec{
				Constraints: &policyapi.CertificateRequestPolicyConstraints{
					PrivateKey: &policyapi.CertificateRequestPolicyConstraintsPrivateKey{},
				},
			},
			expErr:      true,
			expResponse: approver.EvaluationResponse{},
		},
		"if constraints contains private key but CSR uses the wrong key type and is too small, return error": {
			request: gen.CertificateRequest("",
				gen.SetCertificateRequestCSR(csrFrom(t, x509.RSA)),
			),
			policy: policyapi.CertificateRequestPolicySpec{
				Constraints: &policyapi.CertificateRequestPolicyConstraints{
					PrivateKey: &policyapi.CertificateRequestPolicyConstraintsPrivateKey{
						Algorithm: &ecdsaAlg,
						MinSize:   ptr.To(4000),
					},
				},
			},
			expResponse: approver.EvaluationResponse{
				Result: approver.ResultDenied,
				Message: field.ErrorList{
					field.Invalid(field.NewPath("spec.constraints.privateKey.algorithm"), "RSA", "ECDSA"),
					field.Invalid(field.NewPath("spec.constraints.privateKey.minSize"), "2048", "4000"),
				}.ToAggregate().Error(),
			},
		},
		"if constraints contains private key but CSR uses the wrong key type and is too large, return error": {
			request: gen.CertificateRequest("",
				gen.SetCertificateRequestCSR(csrFrom(t, x509.ECDSA)),
			),
			policy: policyapi.CertificateRequestPolicySpec{
				Constraints: &policyapi.CertificateRequestPolicyConstraints{
					PrivateKey: &policyapi.CertificateRequestPolicyConstraintsPrivateKey{
						Algorithm: &rsaAlg,
						MaxSize:   ptr.To(200),
					},
				},
			},
			expResponse: approver.EvaluationResponse{
				Result: approver.ResultDenied,
				Message: field.ErrorList{
					field.Invalid(field.NewPath("spec.constraints.privateKey.algorithm"), "ECDSA", "RSA"),
					field.Invalid(field.NewPath("spec.constraints.privateKey.maxSize"), "256", "200"),
				}.ToAggregate().Error(),
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			response, err := Approver().Evaluate(context.TODO(), &policyapi.CertificateRequestPolicy{Spec: test.policy}, test.request)
			assert.Equal(t, test.expErr, err != nil, "%v", err)
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
