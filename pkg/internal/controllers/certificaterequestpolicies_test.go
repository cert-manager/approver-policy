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

	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2/ktesting"
	fakeclock "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	fakeapprover "github.com/cert-manager/approver-policy/pkg/approver/fake"
)

func Test_certificaterequestpolicies_Reconcile(t *testing.T) {
	const (
		policyName             = "test-policy"
		policyGeneration int64 = 999
	)

	var (
		fixedTime     = time.Date(2021, 01, 01, 01, 0, 0, 0, time.UTC)
		fixedmetatime = metav1.Time{Time: fixedTime}
		fixedclock    = fakeclock.NewFakeClock(fixedTime)
	)

	tests := map[string]struct {
		existingObjects []runtime.Object
		reconcilers     []approver.Reconciler

		expResult      ctrl.Result
		expError       bool
		expStatusPatch *policyapi.CertificateRequestPolicyStatus
		expEvent       string
	}{
		"if policy doesn't exist, no nothing": {
			existingObjects: nil,
			expResult:       ctrl.Result{},
			expError:        false,
			expStatusPatch:  nil,
			expEvent:        "",
		},
		"if no reconcilers defined, always update ready status": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			expResult: ctrl.Result{},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				},
			},
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
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				},
			},
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
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for approval evaluation: foo: Forbidden: not allowed",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Warning NotReady CertificateRequestPolicy is not ready for approval evaluation: foo: Forbidden: not allowed",
		},
		"if reconciler returns error, return error": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{}, errors.New("this is an error")
			})},
			expResult:      ctrl.Result{},
			expError:       true,
			expStatusPatch: nil,
			expEvent:       "",
		},
		"if reconciler returns ready response with requeue and requeueAfter, update to ready and mark requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
			})},
			expResult: ctrl.Result{RequeueAfter: time.Second},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if reconciler returns ready response with just requeueAfter > 0, update to ready and mark requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
			})},
			expResult: ctrl.Result{RequeueAfter: time.Second},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if two reconcilers returns ready response with requeue and requeueAfter, update to ready and mark requeue with requeueAfter of smaller duration": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
			}},
			reconcilers: []approver.Reconciler{
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{RequeueAfter: time.Minute}}, nil
				}),
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
				}),
			},
			expResult: ctrl.Result{RequeueAfter: time.Second},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if one reconciler returns ready response with requeue and requeueAfter but condition already exists, requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				}},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
			})},
			expResult: ctrl.Result{RequeueAfter: time.Second},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if one reconciler returns not-ready response with requeue and requeueAfter but condition already exists, requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for approval evaluation: foo: Forbidden: not allowed",
						ObservedGeneration: policyGeneration},
				}},
			}},
			reconcilers: []approver.Reconciler{fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("foo"), "not allowed")}, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
			})},
			expResult: ctrl.Result{RequeueAfter: time.Second},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for approval evaluation: foo: Forbidden: not allowed",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Warning NotReady CertificateRequestPolicy is not ready for approval evaluation: foo: Forbidden: not allowed",
		},
		"if two reconcilers returns ready response with only one requeue and requeueAfter, requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				}},
			}},
			reconcilers: []approver.Reconciler{
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
				}),
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{}}, nil
				}),
			},
			expResult: ctrl.Result{RequeueAfter: time.Second},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "Ready",
						Message:            "CertificateRequestPolicy is ready for approval evaluation",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Normal Ready CertificateRequestPolicy is ready for approval evaluation",
		},
		"if two reconcilers returns not-ready response with requeue and requeueAfter exists, update with not ready requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for approval evaluation: [foo: Forbidden: not allowed, bar: Forbidden: also not allowed]",
						ObservedGeneration: policyGeneration - 1},
				}},
			}},
			reconcilers: []approver.Reconciler{
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("foo"), "not allowed")}, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
				}),
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("bar"), "also not allowed")}, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
				}),
			},
			expResult: ctrl.Result{RequeueAfter: time.Second},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for approval evaluation: [foo: Forbidden: not allowed, bar: Forbidden: also not allowed]",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Warning NotReady CertificateRequestPolicy is not ready for approval evaluation: [foo: Forbidden: not allowed, bar: Forbidden: also not allowed]",
		},
		"if two reconcilers returns ready and not-ready response with requeue and requeueAfter exists, update with not ready requeue with requeueAfter": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for approval evaluation: [foo: Forbidden: not allowed, bar: Forbidden: also not allowed]",
						ObservedGeneration: policyGeneration - 1},
				}},
			}},
			reconcilers: []approver.Reconciler{
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
				}),
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("foo"), "not allowed")}, Result: ctrl.Result{RequeueAfter: time.Minute}}, nil
				}),
			},
			expResult: ctrl.Result{RequeueAfter: time.Second},
			expError:  false,
			expStatusPatch: &policyapi.CertificateRequestPolicyStatus{
				Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for approval evaluation: foo: Forbidden: not allowed",
						ObservedGeneration: policyGeneration},
				},
			},
			expEvent: "Warning NotReady CertificateRequestPolicy is not ready for approval evaluation: foo: Forbidden: not allowed",
		},
		"if one reconciler returns ready but the other errors, return error": {
			existingObjects: []runtime.Object{&policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy", Generation: policyGeneration, ResourceVersion: "3"},
				TypeMeta:   metav1.TypeMeta{Kind: "CertificateRequestPolicy", APIVersion: "policy.cert-manager.io/v1alpha1"},
				Status: policyapi.CertificateRequestPolicyStatus{Conditions: []metav1.Condition{
					{Type: policyapi.ConditionTypeReady,
						Status:             metav1.ConditionFalse,
						LastTransitionTime: fixedmetatime,
						Reason:             "NotReady",
						Message:            "CertificateRequestPolicy is not ready for approval evaluation: [foo: Forbidden: not allowed, bar: Forbidden: also not allowed]",
						ObservedGeneration: policyGeneration - 1},
				}},
			}},
			reconcilers: []approver.Reconciler{
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{Ready: true, Result: ctrl.Result{RequeueAfter: time.Second}}, nil
				}),
				fakeapprover.NewFakeReconciler().WithReady(func(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
					return approver.ReconcilerReadyResponse{}, errors.New("this is an error")
				}),
			},
			expResult:      ctrl.Result{},
			expError:       true,
			expStatusPatch: nil,
			expEvent:       "",
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
				log:         ktesting.NewLogger(t, ktesting.DefaultConfig),
				clock:       fixedclock,
				client:      fakeclient,
				lister:      fakeclient,
				recorder:    fakerecorder,
				reconcilers: test.reconcilers,
			}

			resp, statusPatch, err := c.reconcileStatusPatch(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Name: policyName}})
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

			if !apiequality.Semantic.DeepEqual(statusPatch, test.expStatusPatch) {
				t.Errorf("unexpected Reconcile response, exp=%v got=%v", test.expStatusPatch, statusPatch)
			}
		})
	}
}

func Test_certificaterequestpolicies_setCondition(t *testing.T) {
	const policyGeneration int64 = 2

	var (
		fixedTime     = time.Date(2021, 01, 01, 01, 0, 0, 0, time.UTC)
		fixedmetatime = metav1.Time{Time: fixedTime}
		fixedclock    = fakeclock.NewFakeClock(fixedTime)
	)

	tests := map[string]struct {
		existingConditions []metav1.Condition
		patchConditions    []metav1.Condition
		newCondition       metav1.Condition
		expectedConditions []metav1.Condition
	}{
		"no existing conditions should add the condition with time and gen to the policy": {
			existingConditions: []metav1.Condition{},
			newCondition: metav1.Condition{
				Type:    "A",
				Status:  metav1.ConditionTrue,
				Reason:  "B",
				Message: "C",
			},
			expectedConditions: []metav1.Condition{{
				Type:               "A",
				Status:             metav1.ConditionTrue,
				Reason:             "B",
				Message:            "C",
				LastTransitionTime: fixedmetatime,
				ObservedGeneration: policyGeneration,
			}},
		},
		"an existing patch condition of different type should add a different condition with time and gen to the policy": {
			patchConditions: []metav1.Condition{{Type: "B"}},
			newCondition: metav1.Condition{
				Type:    "A",
				Status:  metav1.ConditionTrue,
				Reason:  "B",
				Message: "C",
			},
			expectedConditions: []metav1.Condition{
				{Type: "B"},
				{
					Type:               "A",
					Status:             metav1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: fixedmetatime,
					ObservedGeneration: policyGeneration,
				},
			},
		},
		"an existing patch condition of the same type but different status should be replaced with new time if it has a different status": {
			patchConditions: []metav1.Condition{
				{Type: "B"},
				{
					Type:               "A",
					Status:             metav1.ConditionFalse,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: fixedmetatime,
					ObservedGeneration: policyGeneration - 1,
				},
			},
			newCondition: metav1.Condition{
				Type:    "A",
				Status:  metav1.ConditionTrue,
				Reason:  "B",
				Message: "C",
			},
			expectedConditions: []metav1.Condition{
				{Type: "B"},
				{
					Type:               "A",
					Status:             metav1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: fixedmetatime,
					ObservedGeneration: policyGeneration,
				},
			},
		},
		"an existing patch condition of the same type and status should be replaced with same time": {
			patchConditions: []metav1.Condition{
				{Type: "B"},
				{
					Type:               "A",
					Status:             metav1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: metav1.Time{Time: fixedTime.Add(-time.Second)},
					ObservedGeneration: policyGeneration - 1,
				},
			},
			newCondition: metav1.Condition{
				Type:    "A",
				Status:  metav1.ConditionTrue,
				Reason:  "B",
				Message: "C",
			},
			expectedConditions: []metav1.Condition{
				{Type: "B"},
				{
					Type:               "A",
					Status:             metav1.ConditionTrue,
					Reason:             "B",
					Message:            "C",
					LastTransitionTime: metav1.Time{Time: fixedTime.Add(-time.Second)},
					ObservedGeneration: policyGeneration,
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c := &certificaterequestpolicies{clock: fixedclock}
			c.setCondition(
				test.existingConditions,
				&test.patchConditions, // #nosec G601 -- False positive. See https://github.com/golang/go/discussions/56010
				policyGeneration,
				test.newCondition,
			)

			if !apiequality.Semantic.DeepEqual(test.patchConditions, test.expectedConditions) {
				t.Errorf("unexpected resulting conditions, exp=%v got=%v", test.expectedConditions, test.patchConditions)
			}
		})
	}
}
