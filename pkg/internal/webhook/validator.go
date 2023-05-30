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

package webhook

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
)

// validator validates against policy.cert-manager.io resources.
type validator struct {
	log logr.Logger

	registeredPlugins []string
	webhooks          []approver.Webhook

	lister client.Reader
}

var _ admission.CustomValidator = &validator{}

func (v *validator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	return v.validate(ctx, obj)
}

func (v *validator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	return v.validate(ctx, newObj)
}

func (v *validator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	// always allow deletes
	return nil, nil
}

// certificateRequestPolicy validates the given CertificateRequestPolicy with
// the base validations, along with all webhook validations registered.
func (v *validator) validate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	policy, ok := obj.(*policyapi.CertificateRequestPolicy)
	if !ok {
		return nil, fmt.Errorf("expected a CertificateRequestPolicy, but got a %T", obj)
	}
	var (
		fieldErrs field.ErrorList
		warnings  admission.Warnings
		fldPath   = field.NewPath("spec")
	)

	// Ensure no plugin has been defined which is not registered.
	var unrecognisedNames []string
	for name := range policy.Spec.Plugins {
		var found bool
		for _, known := range v.registeredPlugins {
			if name == known {
				found = true
				break
			}
		}

		if !found {
			unrecognisedNames = append(unrecognisedNames, name)
		}
	}

	if len(unrecognisedNames) > 0 {
		// Sort list so testing is deterministic.
		sort.Strings(unrecognisedNames)
		for _, name := range unrecognisedNames {
			fieldErrs = append(fieldErrs, field.NotSupported(fldPath.Child("plugins"), name, v.registeredPlugins))
		}
	}

	if policy.Spec.Selector.IssuerRef == nil && policy.Spec.Selector.Namespace == nil {
		fieldErrs = append(fieldErrs, field.Required(fldPath.Child("selector"), "one of issuerRef or namespace must be defined, hint: `{}` on either matches everything"))
	}

	if nsSel := policy.Spec.Selector.Namespace; nsSel != nil && len(nsSel.MatchLabels) > 0 {
		if _, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{MatchLabels: nsSel.MatchLabels}); err != nil {
			fieldErrs = append(fieldErrs, field.Invalid(fldPath.Child("selector", "namespace", "matchLabels"), nsSel.MatchLabels, err.Error()))
		}
	}

	allAllowed := true
	for _, webhook := range v.webhooks {
		response, err := webhook.Validate(ctx, policy)
		if err != nil {
			return nil, err
		}
		if !response.Allowed {
			fieldErrs = append(fieldErrs, response.Errors...)

			allAllowed = false
		}
		warnings = append(warnings, response.Warnings...)
	}

	var errs []error

	if aggregateError := fieldErrs.ToAggregate(); aggregateError != nil {
		errs = append(errs, aggregateError.Errors()...)
	}

	// do not allow a CertificateRequestPolicy if it was not
	// allowed by a plugin that did not set any errors
	// TODO: when webhooks implement Name() method, provide a plugin name
	if !allAllowed && len(errs) == 0 {
		errs = append(errs, errors.New("a plugin did not allow the CertificateRequest for unknown reasons"))
	}

	return warnings, utilerrors.NewAggregate(errs)
}
