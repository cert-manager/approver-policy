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
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/klog/v2/klogr"
	"k8s.io/utils/pointer"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	fakeapprover "github.com/cert-manager/approver-policy/pkg/approver/fake"
)

func Test_validate(t *testing.T) {
	someError := field.Invalid(field.NewPath("spec"), "foo", "some error occurred")
	testObjectMeta := metav1.ObjectMeta{Name: "test-policy", ResourceVersion: "3"}
	testTypeMeta := metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"}
	notAllowedWebhook := fakeapprover.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
		return approver.WebhookValidationResponse{Allowed: false, Errors: field.ErrorList{someError}}, nil
	})
	notAllowedWebhookNoDetail := fakeapprover.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
		return approver.WebhookValidationResponse{Allowed: false}, nil
	})
	passingWebhook := fakeapprover.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
		return approver.WebhookValidationResponse{Allowed: true}, nil
	})
	warningsWebhook := fakeapprover.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
		return approver.WebhookValidationResponse{Allowed: true, Warnings: admission.Warnings{"some warning"}}, nil
	})
	failingWebhook := fakeapprover.NewFakeWebhook().WithValidate(func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
		return approver.WebhookValidationResponse{}, errors.New("some error")
	})
	tests := map[string]struct {
		crp               runtime.Object
		webhooks          []approver.Webhook
		registeredPlugins []string

		expectedWarnings admission.Warnings
		expectedError    *string
	}{
		"if the object being validated is not a CertificateRequestPolicy return an error": {
			crp: &corev1.Pod{},

			expectedError: pointer.String("expected a CertificateRequestPolicy, but got a *v1.Pod"),
		},
		"if the CertificateRequestPolicy refers to a plugin that is not registered return an error": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
				},
			},
			registeredPlugins: []string{"foo", "baz"},

			expectedError: pointer.String("[spec.plugins: Unsupported value: \"bar\": supported values: \"foo\", \"baz\", spec.selector: Required value: one of issuerRef or namespace must be defined, hint: `{}` on either matches everything]"),
		},
		"if neither issuer ref nor namespace are defined, return error": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
				},
			},
			registeredPlugins: []string{"foo", "bar"},

			expectedError: pointer.String("spec.selector: Required value: one of issuerRef or namespace must be defined, hint: `{}` on either matches everything"),
		},
		"if an invalid namespace label selector is defined, return error": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
					Selector: policyapi.CertificateRequestPolicySelector{
						Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{
							MatchLabels: map[string]string{"$%234": "8dsdk"},
						},
					},
				},
			},
			registeredPlugins: []string{"foo", "bar"},

			expectedError: pointer.String("spec.selector.namespace.matchLabels: Invalid value: map[string]string{\"$%234\":\"8dsdk\"}: key: Invalid value: \"$%234\": name part must consist of alphanumeric characters, '-', '_' or '.', and must start and end with an alphanumeric character (e.g. 'MyName',  or 'my.name',  or '123-abc', regex used for validation is '([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]')"),
		},
		"if a registered webhook does not allow CertificateRequestPolicy, return an error": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
					Selector: policyapi.CertificateRequestPolicySelector{
						Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{
							MatchLabels: map[string]string{"foo": "bar"},
						},
					},
				},
			},
			registeredPlugins: []string{"foo", "bar"},
			webhooks:          []approver.Webhook{passingWebhook, notAllowedWebhook},

			expectedError: pointer.String("spec: Invalid value: \"foo\": some error occurred"),
		},
		"if a registered webhook errors when validating CertificateRequestPolicy, return an error": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
					Selector: policyapi.CertificateRequestPolicySelector{
						Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{
							MatchLabels: map[string]string{"foo": "bar"},
						},
					},
				},
			},
			registeredPlugins: []string{"foo", "bar"},
			webhooks:          []approver.Webhook{passingWebhook, failingWebhook},

			expectedError: pointer.String("some error"),
		},
		"if a registered webhook does not allow CertificteRequestPolicy without further detail, return an error": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
					Selector: policyapi.CertificateRequestPolicySelector{
						Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{
							MatchLabels: map[string]string{"foo": "bar"},
						},
					},
				},
			},
			registeredPlugins: []string{"foo", "bar"},
			webhooks:          []approver.Webhook{passingWebhook, notAllowedWebhookNoDetail},

			expectedError: pointer.String("a plugin did not allow the CertificateRequest for unknown reasons"),
		},
		"if a webhook validation returns warnings, add return them": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
					Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					},
				},
			},
			registeredPlugins: []string{"foo", "bar"},
			webhooks:          []approver.Webhook{passingWebhook, warningsWebhook},
			expectedWarnings:  admission.Warnings{"some warning"},
		},
		"if a  CertificateRequestPolicy with a defined issuer ref passes validation, allow it": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
					Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					},
				},
			},
			registeredPlugins: []string{"foo", "bar"},
			webhooks:          []approver.Webhook{passingWebhook},
		},
		"if a  CertificateRequestPolicy with a defined namespace selector passes validation, allow it": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
					Selector: policyapi.CertificateRequestPolicySelector{
						Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{},
					},
				},
			},
			registeredPlugins: []string{"foo", "bar"},
			webhooks:          []approver.Webhook{passingWebhook},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fakeclient := fakeclient.NewClientBuilder().
				WithScheme(policyapi.GlobalScheme).
				Build()

			v := &validator{lister: fakeclient, log: klogr.New(), webhooks: test.webhooks, registeredPlugins: test.registeredPlugins}
			gotWarnings, gotErr := v.validate(context.Background(), test.crp)
			if test.expectedError == nil && gotErr != nil {
				t.Errorf("unexpected error: %v", gotErr)
			} else if test.expectedError != nil && (gotErr == nil || *test.expectedError != gotErr.Error()) {
				t.Errorf("wants error: %v got: %v", *test.expectedError, gotErr)
			}
			assert.Equal(t, test.expectedWarnings, gotWarnings)
		})
	}
}
