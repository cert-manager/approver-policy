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
	"fmt"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	policyapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/pkg/approver"
)

// Validate validates that the processed CertificateRequestPolicy has valid
// constraint fields defined and there are no parsing errors in the values.
func (c Constraints) Validate(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
	// If no constraints are defined we can exit early
	if policy.Spec.Constraints == nil {
		return approver.WebhookValidationResponse{
			Allowed: true,
			Errors:  nil,
		}, nil
	}

	var (
		el      field.ErrorList
		consts  = policy.Spec.Constraints
		fldPath = field.NewPath("spec", "constraints")
	)

	if consts.PrivateKey != nil {
		fldPath := fldPath.Child("privateKey")

		if consts.PrivateKey.Algorithm != nil {
			switch alg := *consts.PrivateKey.Algorithm; alg {
			case cmapi.RSAKeyAlgorithm, cmapi.ECDSAKeyAlgorithm, cmapi.Ed25519KeyAlgorithm:
				break
			default:
				el = append(el, field.NotSupported(fldPath.Child("algorithm"), alg, []string{string(cmapi.RSAKeyAlgorithm), string(cmapi.ECDSAKeyAlgorithm), string(cmapi.Ed25519KeyAlgorithm)}))
			}

			if *consts.PrivateKey.Algorithm == cmapi.Ed25519KeyAlgorithm {
				if consts.PrivateKey.MaxSize != nil {
					el = append(el, field.Invalid(fldPath.Child("maxSize"), *consts.PrivateKey.MaxSize, fmt.Sprintf("maxSize cannot be defined with algorithm constraint %s", cmapi.Ed25519KeyAlgorithm)))
				}
				if consts.PrivateKey.MinSize != nil {
					el = append(el, field.Invalid(fldPath.Child("minSize"), *consts.PrivateKey.MinSize, fmt.Sprintf("minSize cannot be defined with algorithm constraint %s", cmapi.Ed25519KeyAlgorithm)))
				}
			}
		}

		maxSize := consts.PrivateKey.MaxSize
		if maxSize != nil && (*maxSize <= 0 || *maxSize > 8192) {
			el = append(el, field.Invalid(fldPath.Child("maxSize"), *maxSize, "must be between 0 and 8192 inclusive"))
		}

		minSize := consts.PrivateKey.MinSize
		if minSize != nil && (*minSize <= 0 || *minSize > 8192) {
			el = append(el, field.Invalid(fldPath.Child("minSize"), *minSize, "must be between 0 and 8192 inclusive"))
		}

		if maxSize != nil && minSize != nil && *maxSize < *minSize {
			el = append(el, field.Invalid(fldPath.Child("maxSize"), *maxSize, "maxSize must be the same value as minSize or larger"))
		}
	}

	return approver.WebhookValidationResponse{
		Allowed: len(el) == 0,
		Errors:  el,
	}, nil
}
