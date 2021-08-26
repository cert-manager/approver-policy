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

package controllers

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2/klogr"
	fakeclock "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/pkg/approver"
	fakeapprover "github.com/cert-manager/policy-approver/pkg/approver/fake"
)

func Test_certificaterequestpolicies_Reconcile(t *testing.T) {
	const (
		policyName             = "test-policy"
		policyGeneration int64 = 999
	)

	var (
		fixedTime     = time.Date(2021, 01, 01, 01, 0, 0, 0, time.UTC)
		fixedmetatime = &metav1.Time{Time: fixedTime}
		fixedclock    = fakeclock.NewFakeClock(fixedTime)
	)

	tests := map[string]struct {
		existingObjects []runtime.Object
		reconcilers     []approver.Reconciler

		expResult  ctrl.Result
		expError   bool
		expObjects []runtime.Object
		expEvent   string
	}{
		"if policy doesn't exist, no nothing": {
			existingObjects: nil,
			expResult:       ctrl.Result{},
			expError:        false,
			expObjects:      nil,
			expEvent:        "",
		},
		"if no reconcilers defined, always update ready status": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "4"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				}},
			}},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if reconciler returns ready response, update to ready": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: true}, nil
			})},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "4"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				}},
			}},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if reconciler returns not ready response, update to ready": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("foo"), "not allowed")}}, nil
			})},
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "4"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for evaluation: foo: Forbidden: not allowed",
						ObservedGeneration: policyGeneration},
				}},
			}},
			expEvent: "Warning NotReady CertificateRequestPolicy is not ready for evaluation: foo: Forbidden: not allowed",
		},
		"if reconciler returns error, return error": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{}, errors.New("this is an error")
			})},
			expResult: ctrl.Result{},
			expError:  true,
			expObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			expEvent: "",
		},
		"if reconciler returns ready response with requeue, update to ready and mark requeue": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{Requeue: true}}, nil
			})},
			expResult: ctrl.Result{Requeue: true},
			expError:  false,
			expObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "4"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				}},
			}},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if reconciler returns ready response with requeue and requeueAfter, update to ready and mark requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{Requeue: true, RequeueAfter: time.Second}}, nil
			})},
			expResult: ctrl.Result{Requeue: true, RequeueAfter: time.Second},
			expError:  false,
			expObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "4"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				}},
			}},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if two reconcilers returns ready response with requeue and requeueAfter, update to ready and mark requeue with requeueAfter of smaller duration": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			reconcilers: []approver.Reconciler{
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{Requeue: true, RequeueAfter: time.Minute}}, nil
				}),
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{Requeue: true, RequeueAfter: time.Second}}, nil
				}),
			},
			expResult: ctrl.Result{Requeue: true, RequeueAfter: time.Second},
			expError:  false,
			expObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "4"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				}},
			}},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if one reconciler returns ready response with requeue and requeueAfter but condition already exists, requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				}},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{Requeue: true, RequeueAfter: time.Second}}, nil
			})},
			expResult: ctrl.Result{Requeue: true, RequeueAfter: time.Second},
			expError:  false,
			expObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				}},
			}},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if one reconciler returns not-ready response with requeue and requeueAfter but condition already exists, requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for evaluation: foo: Forbidden: not allowed",
						ObservedGeneration: policyGeneration},
				}},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("foo"), "not allowed")}, Result: ctrl.Result{Requeue: true, RequeueAfter: time.Second}}, nil
			})},
			expResult: ctrl.Result{Requeue: true, RequeueAfter: time.Second},
			expError:  false,
			expObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for evaluation: foo: Forbidden: not allowed",
						ObservedGeneration: policyGeneration},
				}},
			}},
			expEvent: "Warning NotReady CertificateRequestPolicy is not ready for evaluation: foo: Forbidden: not allowed",
		},
		"if two reconcilers returns ready response with only one requeue and requeueAfter, requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				}},
			}},
			reconcilers: []approver.Reconciler{
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{Requeue: true, RequeueAfter: time.Second}}, nil
				}),
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{}}, nil
				}),
			},
			expResult: ctrl.Result{Requeue: true, RequeueAfter: time.Second},
			expError:  false,
			expObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				}},
			}},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if two reconcilers returns not-ready response with requeue and requeueAfter exists, update with not ready requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for evaluation: [foo: Forbidden: not allowed, bar: Forbidden: also not allowed]",
						ObservedGeneration: policyGeneration - 1},
				}},
			}},
			reconcilers: []approver.Reconciler{
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("foo"), "not allowed")}, Result: ctrl.Result{Requeue: true, RequeueAfter: time.Second}}, nil
				}),
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("bar"), "also not allowed")}, Result: ctrl.Result{Requeue: true, RequeueAfter: time.Second}}, nil
				}),
			},
			expResult: ctrl.Result{Requeue: true, RequeueAfter: time.Second},
			expError:  false,
			expObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "4"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for evaluation: [foo: Forbidden: not allowed, bar: Forbidden: also not allowed]",
						ObservedGeneration: policyGeneration},
				}},
			}},
			expEvent: "Warning NotReady CertificateRequestPolicy is not ready for evaluation: [foo: Forbidden: not allowed, bar: Forbidden: also not allowed]",
		},
		"if two reconcilers returns ready and not-ready response with requeue and requeueAfter exists, update with not ready requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for evaluation: [foo: Forbidden: not allowed, bar: Forbidden: also not allowed]",
						ObservedGeneration: policyGeneration - 1},
				}},
			}},
			reconcilers: []approver.Reconciler{
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{Requeue: true, RequeueAfter: time.Second}}, nil
				}),
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("foo"), "not allowed")}, Result: ctrl.Result{Requeue: true, RequeueAfter: time.Minute}}, nil
				}),
			},
			expResult: ctrl.Result{Requeue: true, RequeueAfter: time.Second},
			expError:  false,
			expObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "4"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for evaluation: foo: Forbidden: not allowed",
						ObservedGeneration: policyGeneration},
				}},
			}},
			expEvent: "Warning NotReady CertificateRequestPolicy is not ready for evaluation: foo: Forbidden: not allowed",
		},
		"if one reconciler returns ready but the other errors, return error": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for evaluation: [foo: Forbidden: not allowed, bar: Forbidden: also not allowed]",
						ObservedGeneration: policyGeneration - 1},
				}},
			}},
			reconcilers: []approver.Reconciler{
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{Requeue: true, RequeueAfter: time.Second}}, nil
				}),
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{}, errors.New("this is an error")
				}),
			},
			expResult: ctrl.Result{},
			expError:  true,
			expObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady,
						Status:             corev1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for evaluation: [foo: Forbidden: not allowed, bar: Forbidden: also not allowed]",
						ObservedGeneration: policyGeneration - 1},
				}},
			}},
			expEvent: "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fakeclient := fakeclient.NewClientBuilder().
				WithScheme(policyapi.GlobalScheme).
				WithRuntimeObjects(test.existingObjects...).
				Build()

			fakerecorder := record.NewFakeRecorder(1)

			c := &certificaterequestpolicies{
				log:         klogr.New(),
				clock:       fixedclock,
				client:      fakeclient,
				lister:      fakeclient,
				recorder:    fakerecorder,
				reconcilers: test.reconcilers,
			}

			resp, err := c.Reconcile(context.TODO(), ctrl.Request{NamespacedName: types.NamespacedName{Name: policyName}})
			if (err != nil) != test.expError {
				t.Errorf("unexpected error, exp=%t got=%v", test.expError, err)
			}

			if !apiequality.Semantic.DeepEqual(resp, test.expResult) {
				t.Errorf("unexpected Reconcile response, exp=%v got=%v", test.expResult, resp)
			}

			var event string
			select {
			case event = <-fakerecorder.Events:
			default:
			}
			if event != test.expEvent {
				t.Errorf("unexpected event, exp=%q got=%q", test.expEvent, event)
			}

			for _, expectedObject := range test.expObjects {
				expObj := expectedObject.(client.Object)
				var actual client.Object
				switch expObj.(type) {
				case *policyapi.CertificateRequestPolicy:
					actual = &policyapi.CertificateRequestPolicy{}
				default:
					t.Errorf("unexpected object kind in expected: %#+v", expObj)
				}

				err := fakeclient.Get(context.TODO(), client.ObjectKeyFromObject(expObj), actual)
				if err != nil {
					t.Errorf("unexpected error getting expected object: %s", err)
				} else if !apiequality.Semantic.DeepEqual(expObj, actual) {
					t.Errorf("unexpected expected object, exp=%#+v got=%#+v", expObj, actual)
				}
			}
		})
	}
}

func Test_certificaterequestpolicies_setCertificateRequestPolicyCondition(t *testing.T) {
	const policyGeneration int64 = 2

	var (
		fixedTime     = time.Date(2021, 01, 01, 01, 0, 0, 0, time.UTC)
		fixedmetatime = &metav1.Time{Time: fixedTime}
		fixedclock    = fakeclock.NewFakeClock(fixedTime)
	)

	tests := map[string]struct {
		existingConditions []policyapi.CertificateRequestPolicyCondition
		newCondition       policyapi.CertificateRequestPolicyCondition
		expectedConditions []policyapi.CertificateRequestPolicyCondition
	}{
		"no existing conditions should add the condition with time and gen to the bundle": {
			existingConditions: []policyapi.CertificateRequestPolicyCondition{},
			newCondition: policyapi.CertificateRequestPolicyCondition{
				Type:    "A",
				Status:  corev1.ConditionTrue,
				Reason:  "B",
				Message: "C",
			},
			expectedConditions: []policyapi.CertificateRequestPolicyCondition{{
				Type:               "A",
				Status:             corev1.ConditionTrue,
				Reason:             "B",
				Message:            "C",
				LastTransitionTime: fixedmetatime,
				ObservedGeneration: policyGeneration,
			}},
		},
		"an existing condition of different type should add a different condition with time and gen to the bundle": {
			existingConditions: []policyapi.CertificateRequestPolicyCondition{{Type: "B"}},
			newCondition: policyapi.CertificateRequestPolicyCondition{
				Type:    "A",
				Status:  corev1.ConditionTrue,
				Reason:  "B",
				Message: "C",
			},
			expectedConditions: []policyapi.CertificateRequestPolicyCondition{
				{Type: "B"},
				{
					Type:               "A",
					Status:             corev1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: fixedmetatime,
					ObservedGeneration: policyGeneration,
				},
			},
		},
		"an existing condition of the same type but different status should be replaced with new time if it has a different status": {
			existingConditions: []policyapi.CertificateRequestPolicyCondition{
				{Type: "B"},
				{
					Type:               "A",
					Status:             corev1.ConditionFalse,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: fixedmetatime,
					ObservedGeneration: policyGeneration - 1,
				},
			},
			newCondition: policyapi.CertificateRequestPolicyCondition{
				Type:    "A",
				Status:  corev1.ConditionTrue,
				Reason:  "B",
				Message: "C",
			},
			expectedConditions: []policyapi.CertificateRequestPolicyCondition{
				{Type: "B"},
				{
					Type:               "A",
					Status:             corev1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: fixedmetatime,
					ObservedGeneration: policyGeneration,
				},
			},
		},
		"an existing condition of the same type and status should be replaced with same time": {
			existingConditions: []policyapi.CertificateRequestPolicyCondition{
				{Type: "B"},
				{
					Type:               "A",
					Status:             corev1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: &metav1.Time{Time: fixedTime.Add(-time.Second)},
					ObservedGeneration: policyGeneration - 1,
				},
			},
			newCondition: policyapi.CertificateRequestPolicyCondition{
				Type:    "A",
				Status:  corev1.ConditionTrue,
				Reason:  "B",
				Message: "C",
			},
			expectedConditions: []policyapi.CertificateRequestPolicyCondition{
				{Type: "B"},
				{
					Type:               "A",
					Status:             corev1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: &metav1.Time{Time: fixedTime.Add(-time.Second)},
					ObservedGeneration: policyGeneration,
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c := &certificaterequestpolicies{clock: fixedclock}
			policy := &policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Generation: policyGeneration},
				Status:     policyapi.CertificateRequestPolicyStatus{Conditions: test.existingConditions},
			}

			c.setCertificateRequestPolicyCondition(policy, test.newCondition)
			if !apiequality.Semantic.DeepEqual(policy.Status.Conditions, test.expectedConditions) {
				t.Errorf("unexpected resulting conditions, exp=%v got=%v", test.expectedConditions, policy.Status.Conditions)
			}
		})
	}
}
