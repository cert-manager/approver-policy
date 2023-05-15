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
		expectedWarnings  admission.Warnings
		wantsErr          bool
		webhooks          []approver.Webhook
		registeredPlugins []string
	}{
		"if the object being validated is not a CertificateRequestPolicy return an error": {
			crp:      &corev1.Pod{},
			wantsErr: true,
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
			wantsErr:          true,
		},
		"if neither issuer ref nor namespace are defined, return error": {
			crp: &policyapi.CertificateRequestPolicy{
				TypeMeta:   testTypeMeta,
				ObjectMeta: testObjectMeta,
				Spec: policyapi.CertificateRequestPolicySpec{
					Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"foo": {}, "bar": {}},
				},
			},
			wantsErr:          true,
			registeredPlugins: []string{"foo", "bar"},
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
			wantsErr:          true,
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
			wantsErr:          true,
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
			wantsErr:          true,
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
			if test.wantsErr != (gotErr != nil) {
				t.Errorf("wants error: %t got: %v", test.wantsErr, gotErr)
			}
			assert.Equal(t, test.expectedWarnings, gotWarnings)
		})
	}
}
