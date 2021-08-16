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
	"fmt"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmpapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/pkg/approver"
)

// Validate validates that the processed CertificateRequestPolicy meets the
// requirements for the base set of attribute fields, and there are no parsing
// errors in the values.
func (a attribute) Validate(_ context.Context, crp *cmpapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
	var (
		el      field.ErrorList
		fldPath = field.NewPath("spec")
	)

	if crp.Spec.AllowedPrivateKey != nil {
		fldPath := fldPath.Child("allowedPrivateKey")

		if crp.Spec.AllowedPrivateKey.AllowedAlgorithm != nil {
			switch alg := *crp.Spec.AllowedPrivateKey.AllowedAlgorithm; alg {
			case cmapi.RSAKeyAlgorithm, cmapi.ECDSAKeyAlgorithm, cmapi.Ed25519KeyAlgorithm:
				break
			default:
				el = append(el, field.Invalid(fldPath.Child("allowedAlgorithm"), alg, fmt.Sprintf("must be either one of %q, %q, or %q",
					cmapi.RSAKeyAlgorithm, cmapi.ECDSAKeyAlgorithm, cmapi.Ed25519KeyAlgorithm)))
			}
		}

		maxSize := crp.Spec.AllowedPrivateKey.MaxSize
		if maxSize != nil && (*maxSize <= 0 || *maxSize > 8192) {
			el = append(el, field.Invalid(fldPath.Child("maxSize"), *maxSize, "must be between 0 and 8192 inclusive"))
		}

		minSize := crp.Spec.AllowedPrivateKey.MinSize
		if minSize != nil && (*minSize <= 0 || *minSize > 8192) {
			el = append(el, field.Invalid(fldPath.Child("minSize"), *minSize, "must be between 0 and 8192 inclusive"))
		}

		if maxSize != nil && minSize != nil && *maxSize < *minSize {
			el = append(el, field.Invalid(fldPath.Child("maxSize"), *maxSize, "maxSize must be the same value as minSize or larger"))
		}
	}

	if crp.Spec.IssuerRefSelector == nil {
		el = append(el, field.Required(fldPath.Child("issuerRefSelector"), "must be defined, hint: `{}` matches everything"))
	}

	if len(el) > 0 {
		return approver.WebhookValidationResponse{
			Allowed: false,
			Message: el.ToAggregate().Error(),
		}, nil
	}

	return approver.WebhookValidationResponse{Allowed: true}, nil
}
