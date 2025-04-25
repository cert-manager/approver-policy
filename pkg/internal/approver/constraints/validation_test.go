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
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
)

func Test_Validate(t *testing.T) {
	badAlg := cmapi.PrivateKeyAlgorithm("bad-alg")
	edAlg := cmapi.Ed25519KeyAlgorithm
	rsaAlg := cmapi.RSAKeyAlgorithm

	tests := map[string]struct {
		policy      *policyapi.CertificateRequestPolicy
		expResponse approver.WebhookValidationResponse
	}{
		"if policy contains no constraints, expect a Allowed=true response": {
			policy: &policyapi.CertificateRequestPolicy{
				Spec: policyapi.CertificateRequestPolicySpec{
					Constraints: nil,
				},
			},
			expResponse: approver.WebhookValidationResponse{
				Allowed: true,
				Errors:  nil,
			},
		},
		"if policy contains validation errors, expect a Allowed=false response": {
			policy: &policyapi.CertificateRequestPolicy{
				Spec: policyapi.CertificateRequestPolicySpec{
					Constraints: &policyapi.CertificateRequestPolicyConstraints{
						PrivateKey: &policyapi.CertificateRequestPolicyConstraintsPrivateKey{
							Algorithm: &badAlg,
							MinSize:   ptr.To(9999),
							MaxSize:   ptr.To(-1),
						},
						MinDuration: &metav1.Duration{Duration: -time.Minute},
						MaxDuration: &metav1.Duration{Duration: -2 * time.Minute},
					},
				},
			},
			expResponse: approver.WebhookValidationResponse{
				Allowed: false,
				Errors: field.ErrorList{
					field.NotSupported(field.NewPath("spec.constraints.privateKey.algorithm"), cmapi.PrivateKeyAlgorithm("bad-alg"), []string{"RSA", "ECDSA", "Ed25519"}),
					field.Invalid(field.NewPath("spec.constraints.privateKey.maxSize"), -1, "must be between 0 and 8192 inclusive"),
					field.Invalid(field.NewPath("spec.constraints.privateKey.minSize"), 9999, "must be between 0 and 8192 inclusive"),
					field.Invalid(field.NewPath("spec.constraints.privateKey.maxSize"), -1, "maxSize must be the same value as minSize or larger"),
					field.Invalid(field.NewPath("spec.constraints.maxDuration"), "-2m0s", "maxDuration must be the same value as minDuration or larger"),
					field.Invalid(field.NewPath("spec.constraints.maxDuration"), "-2m0s", "maxDuration must be a value greater or equal to 0"),
					field.Invalid(field.NewPath("spec.constraints.minDuration"), "-1m0s", "minDuration must be a value greater or equal to 0"),
				},
			},
		},
		"if policy is using Ed25519 constraints but defined min and max key sizes, expect a Allowed=false response": {
			policy: &policyapi.CertificateRequestPolicy{
				Spec: policyapi.CertificateRequestPolicySpec{
					Constraints: &policyapi.CertificateRequestPolicyConstraints{
						PrivateKey: &policyapi.CertificateRequestPolicyConstraintsPrivateKey{
							Algorithm: &edAlg,
							MinSize:   ptr.To(100),
							MaxSize:   ptr.To(500),
						},
					},
				},
			},
			expResponse: approver.WebhookValidationResponse{
				Allowed: false,
				Errors: field.ErrorList{
					field.Invalid(field.NewPath("spec.constraints.privateKey.maxSize"), 500, "maxSize cannot be defined with algorithm constraint Ed25519"),
					field.Invalid(field.NewPath("spec.constraints.privateKey.minSize"), 100, "minSize cannot be defined with algorithm constraint Ed25519"),
				},
			},
		},
		"if policy contains no validation errors, expect a Allowed=true response": {
			policy: &policyapi.CertificateRequestPolicy{
				Spec: policyapi.CertificateRequestPolicySpec{
					Constraints: &policyapi.CertificateRequestPolicyConstraints{
						PrivateKey: &policyapi.CertificateRequestPolicyConstraintsPrivateKey{
							Algorithm: &rsaAlg,
							MinSize:   ptr.To(100),
							MaxSize:   ptr.To(500),
						},
						MinDuration: &metav1.Duration{Duration: 0},
						MaxDuration: &metav1.Duration{Duration: 2 * time.Minute},
					},
				},
			},
			expResponse: approver.WebhookValidationResponse{
				Allowed: true,
				Errors:  nil,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			response, err := Approver().Validate(t.Context(), test.policy)
			assert.NoError(t, err)
			assert.Equal(t, test.expResponse, response)
		})
	}
}
