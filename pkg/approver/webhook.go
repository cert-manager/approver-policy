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

package approver

import (
	"context"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
)

// WebhookValidationResponse is the response to a validate request to a
// Webhook.
type WebhookValidationResponse struct {
	// Allowed indicates whether the request was permitted by this Webhook.
	Allowed bool

	// Errors are errors in response to the validation request being not Allowed.
	Errors field.ErrorList

	// Warnings are non-fatal warnings when validating a CertificateRequestPolicy
	// Will be displayed as admission warnings when a CertificateRequestPolicy is applied
	// https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#response
	Warnings admission.Warnings
}

// Webhook is responsible for making decisions about whether a
// CertificateRequestPolicy should be committed to the API server at admission
// time.
type Webhook interface {
	// Validate is run every time a CertificateRequestPolicy is created or
	// updated at admission time to the API server. If Validate returns a
	// response with Allowed set to false, the object will not be committed.
	// Similarly, any error will cause the object not to be committed
	// immediately, and no other webhooks will be run.
	Validate(context.Context, *policyapi.CertificateRequestPolicy) (WebhookValidationResponse, error)
}
