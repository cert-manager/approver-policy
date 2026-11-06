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

package manager

import (
	"context"
	"errors"
	"path"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/approver/fake"
	"github.com/cert-manager/approver-policy/pkg/approver/manager"
	"github.com/cert-manager/approver-policy/pkg/internal/approver/manager/predicate"
	testenv "github.com/cert-manager/approver-policy/test/env"
)

func Test_hasUnreconciledPolicies(t *testing.T) {
	tests := map[string]struct {
		conditions      []metav1.Condition
		expUnreconciled bool
	}{
		"no Ready condition": {
			expUnreconciled: true,
		},
		"unrelated condition": {
			conditions:      []metav1.Condition{{Type: "Other", Status: metav1.ConditionTrue, ObservedGeneration: 2}},
			expUnreconciled: true,
		},
		"current Ready condition": {
			conditions: []metav1.Condition{{Type: policyapi.ConditionTypeReady, Status: metav1.ConditionTrue, ObservedGeneration: 2}},
		},
		"current NotReady condition": {
			conditions: []metav1.Condition{{Type: policyapi.ConditionTypeReady, Status: metav1.ConditionFalse, ObservedGeneration: 2}},
		},
		"stale Ready condition": {
			conditions:      []metav1.Condition{{Type: policyapi.ConditionTypeReady, Status: metav1.ConditionTrue, ObservedGeneration: 1}},
			expUnreconciled: true,
		},
		"stale NotReady condition": {
			conditions:      []metav1.Condition{{Type: policyapi.ConditionTypeReady, Status: metav1.ConditionFalse, ObservedGeneration: 1}},
			expUnreconciled: true,
		},
		"missing observed generation": {
			conditions:      []metav1.Condition{{Type: policyapi.ConditionTypeReady, Status: metav1.ConditionTrue}},
			expUnreconciled: true,
		},
		"future observed generation": {
			conditions:      []metav1.Condition{{Type: policyapi.ConditionTypeReady, Status: metav1.ConditionTrue, ObservedGeneration: 3}},
			expUnreconciled: true,
		},
	}

	assert.False(t, hasUnreconciledPolicies(nil))
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			policies := []policyapi.CertificateRequestPolicy{{
				ObjectMeta: metav1.ObjectMeta{Generation: 2},
				Status:     policyapi.CertificateRequestPolicyStatus{Conditions: test.conditions},
			}}
			assert.Equal(t, test.expUnreconciled, hasUnreconciledPolicies(policies))
		})
	}
}

func Test_Review(t *testing.T) {
	env := testenv.RunControlPlane(t, t.Context(),
		testenv.GetenvOrFail(t, "CERT_MANAGER_CRDS"),
		path.Join("..", "..", "..", "..", "deploy", "crds"),
	)

	expNoEvaluation := func(t *testing.T) approver.Evaluator {
		return fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
			t.Fatal("unexpected evaluator call")
			return approver.EvaluationResponse{}, nil
		})
	}

	approveUpdatedPolicy := func(t *testing.T) approver.Evaluator {
		return fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, policy *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
			if policy.Name == "test-policy-updated" {
				return approver.EvaluationResponse{Result: approver.ResultNotDenied}, nil
			}
			return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
		})
	}

	tests := map[string]struct {
		evaluator                 func(t *testing.T) approver.Evaluator
		predicate                 func(t *testing.T) predicate.Predicate
		policies                  []policyapi.CertificateRequestPolicy
		readyConditions           map[string]metav1.ConditionStatus
		updatePolicies            []string
		expResponse               manager.ReviewResponse
		expResponseAfterReconcile *manager.ReviewResponse
		expErr                    bool
	}{
		"if no CertificateRequestPolicies exist, return ResultUnprocessed": {
			evaluator: expNoEvaluation,
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, _ []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					t.Fatal("unexpected predicate call")
					return nil, nil
				}
			},
			policies:    nil,
			expResponse: manager.ReviewResponse{Result: manager.ResultUnprocessed, Message: "No CertificateRequestPolicies exist"},
			expErr:      false,
		},
		"if predicate returns an error, return an error": {
			evaluator: expNoEvaluation,
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, _ []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return nil, errors.New("this is an error")
				}
			},
			policies: []policyapi.CertificateRequestPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
			}},
			expResponse: manager.ReviewResponse{},
			expErr:      true,
		},
		"if predicate returns no policies, return ResultUnprocessed": {
			evaluator: expNoEvaluation,
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, _ []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return nil, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
			}},
			expResponse: manager.ReviewResponse{Result: manager.ResultUnprocessed, Message: "No CertificateRequestPolicies bound or applicable"},
			expErr:      false,
		},
		"if single policy returns but evaluator denies, return ResultDenied": {
			evaluator: func(t *testing.T) approver.Evaluator {
				return fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
				})
			},
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return policies, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
			}},
			readyConditions: map[string]metav1.ConditionStatus{"test-policy-a": metav1.ConditionTrue},
			expResponse:     manager.ReviewResponse{Result: manager.ResultDenied, Message: "No policy approved this request: [test-policy-a: this is a denied response]"},
			expErr:          false,
		},
		"if single policy returns and evaluator returns not-denied, return ResultApproved": {
			evaluator: func(t *testing.T) approver.Evaluator {
				return fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: "this is a not-denied response"}, nil
				})
			},
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return policies, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
			}},
			readyConditions: map[string]metav1.ConditionStatus{"test-policy-a": metav1.ConditionTrue},
			expResponse:     manager.ReviewResponse{Result: manager.ResultApproved, Message: `Approved by CertificateRequestPolicy: "test-policy-a"`},
			expErr:          false,
		},
		"if two policies returned and evaluator returns one not-denied, return ResultApproved": {
			evaluator: func(t *testing.T) approver.Evaluator {
				return fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, policy *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					if policy.Name == "test-policy-b" {
						return approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: "this is an approved response"}, nil
					}
					return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
				})
			},
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return policies, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
			},
			readyConditions: map[string]metav1.ConditionStatus{"test-policy-a": metav1.ConditionTrue, "test-policy-b": metav1.ConditionTrue},
			expResponse:     manager.ReviewResponse{Result: manager.ResultApproved, Message: `Approved by CertificateRequestPolicy: "test-policy-b"`},
			expErr:          false,
		},
		"if two policies returned and both return denied, return ResultDenied": {
			evaluator: func(t *testing.T) approver.Evaluator {
				return fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, policy *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
				})
			},
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return policies, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
			},
			readyConditions: map[string]metav1.ConditionStatus{"test-policy-a": metav1.ConditionTrue, "test-policy-b": metav1.ConditionTrue},
			expResponse:     manager.ReviewResponse{Result: manager.ResultDenied, Message: "No policy approved this request: [test-policy-a: this is a denied response] [test-policy-b: this is a denied response]"},
			expErr:          false,
		},
		"if evaluator denies but some policies are unreconciled, return ResultUnprocessed": {
			evaluator: func(t *testing.T) approver.Evaluator {
				return fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
				})
			},
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return policies, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-deny"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-unreconciled"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
			},
			readyConditions: map[string]metav1.ConditionStatus{"test-policy-deny": metav1.ConditionTrue},
			expResponse: manager.ReviewResponse{
				Result:  manager.ResultUnprocessed,
				Message: "Not all policies are ready for evaluation; refusing to deny pending policy readiness: [test-policy-deny: this is a denied response]",
			},
			expErr: false,
		},
		"if an approving policy has stale Ready=True, defer denial until it reconciles": {
			evaluator: approveUpdatedPolicy,
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return policies, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-deny"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-updated"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
			},
			readyConditions: map[string]metav1.ConditionStatus{"test-policy-deny": metav1.ConditionTrue, "test-policy-updated": metav1.ConditionTrue},
			updatePolicies:  []string{"test-policy-updated"},
			expResponse: manager.ReviewResponse{
				Result:  manager.ResultUnprocessed,
				Message: "Not all policies are ready for evaluation; refusing to deny pending policy readiness: [test-policy-deny: this is a denied response]",
			},
			expResponseAfterReconcile: &manager.ReviewResponse{Result: manager.ResultApproved, Message: `Approved by CertificateRequestPolicy: "test-policy-updated"`},
		},
		"if an approving policy has stale Ready=False, defer denial until it reconciles": {
			evaluator: approveUpdatedPolicy,
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return policies, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-deny"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-updated"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
			},
			readyConditions: map[string]metav1.ConditionStatus{"test-policy-deny": metav1.ConditionTrue, "test-policy-updated": metav1.ConditionFalse},
			updatePolicies:  []string{"test-policy-updated"},
			expResponse: manager.ReviewResponse{
				Result:  manager.ResultUnprocessed,
				Message: "Not all policies are ready for evaluation; refusing to deny pending policy readiness: [test-policy-deny: this is a denied response]",
			},
			expResponseAfterReconcile: &manager.ReviewResponse{Result: manager.ResultApproved, Message: `Approved by CertificateRequestPolicy: "test-policy-updated"`},
		},
		"if another policy is NotReady at its current generation, do not defer denial": {
			evaluator: approveUpdatedPolicy,
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return policies, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-deny"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-updated"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
			},
			readyConditions: map[string]metav1.ConditionStatus{"test-policy-deny": metav1.ConditionTrue, "test-policy-updated": metav1.ConditionFalse},
			expResponse:     manager.ReviewResponse{Result: manager.ResultDenied, Message: "No policy approved this request: [test-policy-deny: this is a denied response]"},
		},
		"if a stale policy does not match, do not defer denial": {
			evaluator: approveUpdatedPolicy,
			predicate: func(t *testing.T) predicate.Predicate {
				return predicate.SelectorIssuerRef
			},
			policies: []policyapi.CertificateRequestPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-deny"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-updated"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
			},
			readyConditions: map[string]metav1.ConditionStatus{"test-policy-deny": metav1.ConditionTrue, "test-policy-updated": metav1.ConditionTrue},
			updatePolicies:  []string{"test-policy-updated"},
			expResponse:     manager.ReviewResponse{Result: manager.ResultDenied, Message: "No policy approved this request: [test-policy-deny: this is a denied response]"},
		},
		"if a current policy approves, a stale policy does not block approval": {
			evaluator: func(t *testing.T) approver.Evaluator {
				return fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, policy *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					assert.Equal(t, "test-policy-current", policy.Name)
					return approver.EvaluationResponse{Result: approver.ResultNotDenied}, nil
				})
			},
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return policies, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-current"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-updated"},
					Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
				},
			},
			readyConditions: map[string]metav1.ConditionStatus{"test-policy-current": metav1.ConditionTrue, "test-policy-updated": metav1.ConditionTrue},
			updatePolicies:  []string{"test-policy-updated"},
			expResponse:     manager.ReviewResponse{Result: manager.ResultApproved, Message: `Approved by CertificateRequestPolicy: "test-policy-current"`},
		},
		"if the only policy has stale readiness, do not evaluate it": {
			evaluator: expNoEvaluation,
			predicate: func(t *testing.T) predicate.Predicate {
				return func(_ context.Context, _ *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
					return policies, nil
				}
			},
			policies: []policyapi.CertificateRequestPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-updated"},
				Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}}},
			}},
			readyConditions: map[string]metav1.ConditionStatus{"test-policy-updated": metav1.ConditionTrue},
			updatePolicies:  []string{"test-policy-updated"},
			expResponse:     manager.ReviewResponse{Result: manager.ResultUnprocessed, Message: "No CertificateRequestPolicies bound or applicable"},
		},
	}

	ctx := t.Context()
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() {
				for _, obj := range test.policies {
					if err := env.AdminClient.Delete(ctx, &obj); /* #nosec G601 -- Func drops pointer at end of call. */ err != nil {
						// Don't Fatal here as a ditch effort to at least try to clean-up
						// everything.
						t.Errorf("failed to delete policy: %s", err)
					}
				}
			})

			for _, obj := range test.policies {
				if err := env.AdminClient.Create(ctx, &obj); /* #nosec G601 -- Func drops pointer at end of call. */ err != nil {
					t.Fatalf("failed to create new policy: %s", err)
				}
			}

			// Set the Ready condition on specified policies via status subresource.
			for name, status := range test.readyConditions {
				var policy policyapi.CertificateRequestPolicy
				if err := env.AdminClient.Get(ctx, client.ObjectKey{Name: name}, &policy); err != nil {
					t.Fatalf("failed to get policy %q for status update: %s", name, err)
				}
				policy.Status.Conditions = []metav1.Condition{
					{
						Type:               policyapi.ConditionTypeReady,
						Status:             status,
						ObservedGeneration: policy.Generation,
						Reason:             "TestReadiness",
						Message:            "Test policy readiness",
						LastTransitionTime: metav1.Now(),
					},
				}
				if err := env.AdminClient.Status().Update(ctx, &policy); err != nil {
					t.Fatalf("failed to update status for policy %q: %s", name, err)
				}
			}

			for _, name := range test.updatePolicies {
				var policy policyapi.CertificateRequestPolicy
				if err := env.AdminClient.Get(ctx, client.ObjectKey{Name: name}, &policy); err != nil {
					t.Fatalf("failed to get policy %q for spec update: %s", name, err)
				}
				previousGeneration := policy.Generation
				issuerName := "updated-issuer"
				policy.Spec.Selector.IssuerRef.Name = &issuerName
				if err := env.AdminClient.Update(ctx, &policy); err != nil {
					t.Fatalf("failed to update spec for policy %q: %s", name, err)
				}
				assert.Greater(t, policy.Generation, previousGeneration)
			}

			mngr := &mngr{
				reader:         env.AdminClient,
				readyPredicate: predicate.Ready,
				predicates:     []predicate.Predicate{test.predicate(t)},
				evaluators:     []approver.Evaluator{test.evaluator(t)},
			}

			request := &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "test-req"},
				Spec: cmapi.CertificateRequestSpec{
					Username: "example",
					IssuerRef: cmmeta.IssuerReference{
						Name:  "test-name",
						Kind:  "test-kind",
						Group: "test-group",
					},
				},
			}

			response, err := mngr.Review(ctx, request)
			assert.Equalf(t, test.expErr, err != nil, "%v", err)
			assert.Equal(t, test.expResponse, response)

			if test.expResponseAfterReconcile != nil {
				for _, name := range test.updatePolicies {
					var policy policyapi.CertificateRequestPolicy
					if err := env.AdminClient.Get(ctx, client.ObjectKey{Name: name}, &policy); err != nil {
						t.Fatalf("failed to get policy %q for reconciliation: %s", name, err)
					}
					policy.Status.Conditions[0].Status = metav1.ConditionTrue
					policy.Status.Conditions[0].ObservedGeneration = policy.Generation
					if err := env.AdminClient.Status().Update(ctx, &policy); err != nil {
						t.Fatalf("failed to reconcile policy %q: %s", name, err)
					}
				}
				response, err := mngr.Review(ctx, request)
				assert.NoError(t, err)
				assert.Equal(t, *test.expResponseAfterReconcile, response)
			}
		})
	}
}
