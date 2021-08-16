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
	"testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/pointer"

	policyapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/pkg/approver"
)

func Test_Validate(t *testing.T) {
	badAlg := cmapi.PrivateKeyAlgorithm("bad-alg")
	goodAlg := cmapi.RSAKeyAlgorithm

	tests := map[string]struct {
		policy      *policyapi.CertificateRequestPolicy
		expResponse approver.WebhookValidationResponse
	}{
		"if policy contains validation errors, expect a Allowed=false response": {
			policy: &policyapi.CertificateRequestPolicy{
				Spec: policyapi.CertificateRequestPolicySpec{
					AllowedPrivateKey: &policyapi.CertificateRequestPolicyPrivateKey{
						AllowedAlgorithm: &badAlg,
						MinSize:          pointer.Int(9999),
						MaxSize:          pointer.Int(-1),
					},
					IssuerRefSelector: nil,
					Plugins: map[string]cmpapi.CertificateRequestPolicyPluginData{
						"plugin-1":  cmpapi.CertificateRequestPolicyPluginData{Values: map[string]string{"foo": "bar"}},
						"plugin-2":  cmpapi.CertificateRequestPolicyPluginData{Values: map[string]string{"bar": "foo"}},
						"attribute": cmpapi.CertificateRequestPolicyPluginData{Values: map[string]string{"hello": "world"}},
					},
				},
			},
			expResponse: approver.WebhookValidationResponse{
				Allowed: false,
				Errors: field.ErrorList{
					field.Invalid(field.NewPath("spec.allowedPrivateKey.allowedAlgorithm"), cmapi.PrivateKeyAlgorithm("bad-alg"), `must be either one of "RSA", "ECDSA", or "Ed25519"`),
					field.Invalid(field.NewPath("spec.allowedPrivateKey.maxSize"), -1, "must be between 0 and 8192 inclusive"),
					field.Invalid(field.NewPath("spec.allowedPrivateKey.minSize"), 9999, "must be between 0 and 8192 inclusive"),
					field.Invalid(field.NewPath("spec.allowedPrivateKey.maxSize"), -1, "maxSize must be the same value as minSize or larger"),
					field.NotSupported(field.NewPath("spec.plugins"), "attribute", []string{"plugin-2", "plugin-3"}),
					field.NotSupported(field.NewPath("spec.plugins"), "plugin-1", []string{"plugin-2", "plugin-3"}),
					field.Required(field.NewPath("spec.issuerRefSelector"), "must be defined, hint: `{}` matches everything"),
				},
			},
		},
		"if policy contains no validation errors, expect a Allowed=true response": {
			policy: &policyapi.CertificateRequestPolicy{
				Spec: policyapi.CertificateRequestPolicySpec{
					AllowedPrivateKey: &policyapi.CertificateRequestPolicyPrivateKey{
						AllowedAlgorithm: &goodAlg,
						MinSize:          pointer.Int(100),
						MaxSize:          pointer.Int(500),
					},
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{},
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
			response, err := attribute{[]string{"plugin-2", "plugin-3"}}.Validate(nil, test.policy)
			assert.NoError(t, err)
			assert.Equal(t, test.expResponse, response)
		})
	}
}
