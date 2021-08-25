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
	"path/filepath"
	"testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/pkg/approver"
	"github.com/cert-manager/policy-approver/pkg/approver/fake"
	"github.com/cert-manager/policy-approver/test/env"
)

func Test_Review(t *testing.T) {
	rootDir := env.RootDirOrSkip(t)
	env := env.RunControlPlane(t,
		filepath.Join(rootDir, "bin/cert-manager"),
		filepath.Join(rootDir, "config/crd/bases"),
	)

	const (
		requestUser      = "example"
		requestNamespace = "test-namespace"
	)

	if err := env.AdminClient.Create(context.TODO(),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: requestNamespace}},
	); err != nil {
		t.Fatal(err)
	}

	expNoEvaluation := func(t *testing.T) []approver.Evaluator {
		return []approver.Evaluator{fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
			t.Fatal("unexpected evaluator call")
			return approver.EvaluationResponse{}, nil
		})}
	}

	tests := map[string]struct {
		evaluators      func(t *testing.T) []approver.Evaluator
		existingObjects []client.Object

		expResponse ReviewResponse
		expErr      bool
	}{
		"if no CertificateRequestPolicies exist, return ResultUnrpocessed": {
			evaluators:      expNoEvaluation,
			existingObjects: nil,
			expResponse:     ReviewResponse{Result: ResultUnprocessed, Message: "No CertificateRequestPolicies exist"},
			expErr:          false,
		},
		"if no CertificateRequestPolicies are bound to the user, return ResultUnprocessed": {
			evaluators: expNoEvaluation,
			existingObjects: []client.Object{
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
			},
			expResponse: ReviewResponse{Result: ResultUnprocessed, Message: "No CertificateRequestPolicies bound or applicable"},
			expErr:      false,
		},
		"if single CertificateRequestPolicy bound at cluster level but returns denied, return ResultDenied": {
			evaluators: func(t *testing.T) []approver.Evaluator {
				return []approver.Evaluator{fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
				})}
			},
			existingObjects: []client.Object{
				&policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec: policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "test-binding"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"}, Verbs: []string{"use"}, ResourceNames: []string{"test-policy-a"}},
					},
				},
				&rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "test-role"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: requestUser, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "test-binding"},
				},
			},
			expResponse: ReviewResponse{Result: ResultDenied, Message: "No policy approved this request: [test-policy-a: this is a denied response]"},
			expErr:      false,
		},
		"if single CertificateRequestPolicy bound at namespace level but returns denied, return ResultDenied": {
			evaluators: func(t *testing.T) []approver.Evaluator {
				return []approver.Evaluator{fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
				})}
			},
			existingObjects: []client.Object{
				&policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec: policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				&rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-binding"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"}, Verbs: []string{"use"}, ResourceNames: []string{"test-policy-a"}},
					},
				},
				&rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-role"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: requestUser, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "test-binding"},
				},
			},
			expResponse: ReviewResponse{Result: ResultDenied, Message: "No policy approved this request: [test-policy-a: this is a denied response]"},
			expErr:      false,
		},
		"if single CertificateRequestPolicy bound at cluster level and returns not denied, return ResultApproved": {
			evaluators: func(t *testing.T) []approver.Evaluator {
				return []approver.Evaluator{fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: "this is a not-denied response"}, nil
				})}
			},
			existingObjects: []client.Object{
				&policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec: policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "test-binding"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"}, Verbs: []string{"use"}, ResourceNames: []string{"test-policy-a"}},
					},
				},
				&rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "test-role"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: requestUser, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "test-binding"},
				},
			},
			expResponse: ReviewResponse{Result: ResultApproved, Message: `Approved by CertificateRequestPolicy: "test-policy-a"`},
			expErr:      false,
		},
		"if single CertificateRequestPolicy bound at namespace level and returns not denied, return ResultApproved": {
			evaluators: func(t *testing.T) []approver.Evaluator {
				return []approver.Evaluator{fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: "this is a not-denied response"}, nil
				})}
			},
			existingObjects: []client.Object{
				&policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec: policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				&rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-binding"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"}, Verbs: []string{"use"}, ResourceNames: []string{"test-policy-a"}},
					},
				},
				&rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-role"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: requestUser, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "test-binding"},
				},
			},
			expResponse: ReviewResponse{Result: ResultApproved, Message: `Approved by CertificateRequestPolicy: "test-policy-a"`},
			expErr:      false,
		},
		"if two CertificateRequestPolicies bound at cluster level and one returns not denied, return ResultApproved": {
			evaluators: func(t *testing.T) []approver.Evaluator {
				return []approver.Evaluator{fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, policy *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					if policy.Name == "test-policy-b" {
						return approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: "this is an approved response"}, nil
					}
					return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
				})}
			},
			existingObjects: []client.Object{
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "test-binding"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"},
							Verbs: []string{"use"}, ResourceNames: []string{"test-policy-a", "test-policy-b"},
						},
					},
				},
				&rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "test-role"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: requestUser, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "test-binding"},
				},
			},
			expResponse: ReviewResponse{Result: ResultApproved, Message: `Approved by CertificateRequestPolicy: "test-policy-b"`},
			expErr:      false,
		},
		"if two CertificateRequestPolicies bound at namespace level and one returns not denied, return ResultApproved": {
			evaluators: func(t *testing.T) []approver.Evaluator {
				return []approver.Evaluator{fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, policy *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					if policy.Name == "test-policy-b" {
						return approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: "this is an approved response"}, nil
					}
					return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
				})}
			},
			existingObjects: []client.Object{
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				&rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-binding"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"},
							Verbs: []string{"use"}, ResourceNames: []string{"test-policy-a", "test-policy-b"},
						},
					},
				},
				&rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-role"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: requestUser, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "test-binding"},
				},
			},
			expResponse: ReviewResponse{Result: ResultApproved, Message: `Approved by CertificateRequestPolicy: "test-policy-b"`},
			expErr:      false,
		},
		"if two CertificateRequestPolicies bound at cluster level and both returns denied, return ResultDenied": {
			evaluators: func(t *testing.T) []approver.Evaluator {
				return []approver.Evaluator{fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, policy *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
				})}
			},
			existingObjects: []client.Object{
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "test-binding"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"},
							Verbs: []string{"use"}, ResourceNames: []string{"test-policy-a", "test-policy-b"},
						},
					},
				},
				&rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "test-role"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: requestUser, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "test-binding"},
				},
			},
			expResponse: ReviewResponse{Result: ResultDenied, Message: "No policy approved this request: [test-policy-a: this is a denied response] [test-policy-b: this is a denied response]"},
			expErr:      false,
		},
		"if two CertificateRequestPolicies bound at namespace level and both return denied response, return ResultDenied": {
			evaluators: func(t *testing.T) []approver.Evaluator {
				return []approver.Evaluator{fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, policy *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
				})}
			},
			existingObjects: []client.Object{
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				&rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-role"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"},
							Verbs: []string{"use"}, ResourceNames: []string{"test-policy-a", "test-policy-b"},
						},
					},
				},
				&rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-rolebinding"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: requestUser, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "test-role"},
				},
			},
			expResponse: ReviewResponse{Result: ResultDenied, Message: "No policy approved this request: [test-policy-a: this is a denied response] [test-policy-b: this is a denied response]"},
			expErr:      false,
		},
		"if two CertificateRequestPolicies bound at namespace and cluster level and both return denied response, return ResultDenied": {
			evaluators: func(t *testing.T) []approver.Evaluator {
				return []approver.Evaluator{fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, policy *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
				})}
			},
			existingObjects: []client.Object{
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				&rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-binding-namespaced"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"},
							Verbs: []string{"use"}, ResourceNames: []string{"test-policy-a"},
						},
					},
				},
				&rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-role"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: requestUser, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "test-binding-namespaced"},
				},
				&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "test-binding-cluster"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"}, Verbs: []string{"use"}, ResourceNames: []string{"test-policy-b"}},
					},
				},
				&rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "test-role"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: requestUser, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "test-binding-cluster"},
				},
			},
			expResponse: ReviewResponse{Result: ResultDenied, Message: "No policy approved this request: [test-policy-a: this is a denied response] [test-policy-b: this is a denied response]"},
			expErr:      false,
		},
		"if single CertificateRequestPolicy bound at namespace one evaluator returns deined, return Denied": {
			evaluators: func(t *testing.T) []approver.Evaluator {
				return []approver.Evaluator{
					fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
						return approver.EvaluationResponse{Result: approver.ResultNotDenied}, nil
					}),
					fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
						return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
					}),
				}
			},
			existingObjects: []client.Object{
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				&rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-binding"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"}, Verbs: []string{"use"}, ResourceNames: []string{"test-policy-a"}},
					},
				},
				&rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-role"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: requestUser, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "test-binding"},
				},
			},
			expResponse: ReviewResponse{Result: ResultDenied, Message: "No policy approved this request: [test-policy-a: this is a denied response]"},
			expErr:      false,
		},
		"if single CertificateRequestPolicy bound at namespace level but issuerRefSelector doesn't match, return ResultUnprocessed": {
			evaluators: func(t *testing.T) []approver.Evaluator {
				return []approver.Evaluator{fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: "this is a not-denied response"}, nil
				})}
			},
			existingObjects: []client.Object{
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec: policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("name"), Kind: pointer.String("kind "), Group: pointer.String("group"),
					}},
				},
				&rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-binding"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"}, Verbs: []string{"use"}, ResourceNames: []string{"test-policy-a"}},
					},
				},
				&rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-role"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: requestUser, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "test-binding"},
				},
			},
			expResponse: ReviewResponse{Result: ResultUnprocessed, Message: "No CertificateRequestPolicies bound or applicable"},
			expErr:      false,
		},
		"if single CertificateRequestPolicy bound at namespace, two evaluators returns deined, return Denied": {
			evaluators: func(t *testing.T) []approver.Evaluator {
				return []approver.Evaluator{
					fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
						return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is a denied response"}, nil
					}),
					fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
						return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "this is another denied response"}, nil
					}),
				}
			},
			existingObjects: []client.Object{
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				&rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-binding"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"}, Verbs: []string{"use"}, ResourceNames: []string{"test-policy-a"}},
					},
				},
				&rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-role"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: requestUser, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "test-binding"},
				},
			},
			expResponse: ReviewResponse{Result: ResultDenied, Message: "No policy approved this request: [test-policy-a: this is a denied response, this is another denied response]"},
			expErr:      false,
		},
		"if single CertificateRequestPolicy bound at namespace level and issuerRefSelector matches, return ResultApproved": {
			evaluators: func(t *testing.T) []approver.Evaluator {
				return []approver.Evaluator{fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
					return approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: "this is a not-denied response"}, nil
				})}
			},
			existingObjects: []client.Object{
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec: policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("test-name"), Kind: pointer.String("*"), Group: pointer.String("*-group"),
					}},
				},
				&rbacv1.Role{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-binding"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"}, Verbs: []string{"use"}, ResourceNames: []string{"test-policy-a"}},
					},
				},
				&rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace, Name: "test-role"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: requestUser, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "test-binding"},
				},
			},
			expResponse: ReviewResponse{Result: ResultApproved, Message: `Approved by CertificateRequestPolicy: "test-policy-a"`},
			expErr:      false,
		},
		"if single CertificateRequestPolicy bound at cluster level and both evaluators return not denied, return ResultApproved": {
			evaluators: func(t *testing.T) []approver.Evaluator {
				return []approver.Evaluator{
					fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
						return approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: "this is a not-denied response"}, nil
					}),
					fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
						return approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: "this is another not-denied response"}, nil
					}),
				}
			},
			existingObjects: []client.Object{
				&policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec: policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("test-name"), Kind: pointer.String("*"), Group: pointer.String("*-group"),
					}},
				},
				&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "test-binding"},
					Rules: []rbacv1.PolicyRule{
						{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"}, Verbs: []string{"use"}, ResourceNames: []string{"test-policy-a"}},
					},
				},
				&rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: "test-role"},
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: requestUser, APIGroup: "rbac.authorization.k8s.io"}},
					RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "test-binding"},
				},
			},
			expResponse: ReviewResponse{Result: ResultApproved, Message: `Approved by CertificateRequestPolicy: "test-policy-a"`},
			expErr:      false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() {
				for _, obj := range test.existingObjects {
					if err := env.AdminClient.Delete(context.TODO(), obj); err != nil {
						// Don't Fatal here as a ditch effort to at least try to clean-up
						// everything.
						t.Errorf("failed to deleted existing object: %s", err)
					}
				}
			})

			for _, obj := range test.existingObjects {
				if err := env.AdminClient.Create(context.TODO(), obj); err != nil {
					t.Fatalf("failed to create new object: %s", err)
				}
			}

			s := NewSubjectAccessReview(
				env.AdminClient,
				test.evaluators(t),
			)

			response, err := s.Review(context.TODO(), &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace},
				Spec: cmapi.CertificateRequestSpec{
					Username: "example",
					IssuerRef: cmmeta.ObjectReference{
						Name:  "test-name",
						Kind:  "test-kind",
						Group: "test-group",
					},
				},
			})

			assert.Equalf(t, test.expErr, err != nil, "%v", err)
			assert.Equal(t, test.expResponse, response)
		})
	}
}

func Test_issuerRefSelector(t *testing.T) {
	baseRequest := &cmapi.CertificateRequest{
		Spec: cmapi.CertificateRequestSpec{
			IssuerRef: cmmeta.ObjectReference{
				Name:  "test-name",
				Kind:  "test-kind",
				Group: "test-group",
			},
		},
	}

	tests := map[string]struct {
		policies    []policyapi.CertificateRequestPolicy
		expPolicies []policyapi.CertificateRequestPolicy
	}{
		"if no policies given, return no policies": {
			policies:    nil,
			expPolicies: nil,
		},
		"if policy given that doesn't match, return no policies": {
			policies: []policyapi.CertificateRequestPolicy{
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("name"), Kind: pointer.String("kind"), Group: pointer.String("group"),
					},
				}},
			},
			expPolicies: nil,
		},
		"if two policies given that doesn't match, return no policies": {
			policies: []policyapi.CertificateRequestPolicy{
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("name"), Kind: pointer.String("kind"), Group: pointer.String("group"),
					},
				}},
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("name-2"), Kind: pointer.String("kind-2"), Group: pointer.String("group-2"),
					},
				}},
			},
			expPolicies: nil,
		},
		"if one of two policies match all with all nils, return policy": {
			policies: []policyapi.CertificateRequestPolicy{
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: new(policyapi.CertificateRequestPolicyIssuerRefSelector),
				}},
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("name"), Kind: pointer.String("kind"), Group: pointer.String("group"),
					},
				}},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: new(policyapi.CertificateRequestPolicyIssuerRefSelector),
				}},
			},
		},
		"if one of two policies match all with wildcard, return policy": {
			policies: []policyapi.CertificateRequestPolicy{
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("*"), Kind: pointer.String("*"), Group: pointer.String("*"),
					},
				}},
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("name"), Kind: pointer.String("kind"), Group: pointer.String("group"),
					},
				}},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("*"), Kind: pointer.String("*"), Group: pointer.String("*"),
					},
				}},
			},
		},
		"if both of two policies match all with empty, return policy": {
			policies: []policyapi.CertificateRequestPolicy{
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: new(policyapi.CertificateRequestPolicyIssuerRefSelector),
				}},
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: new(policyapi.CertificateRequestPolicyIssuerRefSelector),
				}},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: new(policyapi.CertificateRequestPolicyIssuerRefSelector),
				}},
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: new(policyapi.CertificateRequestPolicyIssuerRefSelector),
				}},
			},
		},
		"if both of two policies match all with wildcard, return policy": {
			policies: []policyapi.CertificateRequestPolicy{
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("*"), Kind: pointer.String("*"), Group: pointer.String("*"),
					},
				}},
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("*"), Kind: pointer.String("*"), Group: pointer.String("*"),
					},
				}},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("*"), Kind: pointer.String("*"), Group: pointer.String("*"),
					},
				}},
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("*"), Kind: pointer.String("*"), Group: pointer.String("*"),
					},
				}},
			},
		},
		"if one policy matches with, other doesn't, return 1": {
			policies: []policyapi.CertificateRequestPolicy{
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("test-name"), Kind: pointer.String("test-kind"), Group: pointer.String("test-group"),
					},
				}},
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("name"), Kind: pointer.String("kind"), Group: pointer.String("group"),
					},
				}},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("test-name"), Kind: pointer.String("test-kind"), Group: pointer.String("test-group"),
					},
				}},
			},
		},
		"if some polices match with a mix of exact, just wildcard and mix return policies": {
			policies: []policyapi.CertificateRequestPolicy{
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("test-name"), Kind: pointer.String("test-kind"), Group: pointer.String("test-group"),
					},
				}},
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("name"), Kind: pointer.String("kind"), Group: pointer.String("group"),
					},
				}},
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("*"), Kind: pointer.String("*"), Group: pointer.String("*"),
					},
				}},
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("test-*"), Kind: pointer.String("*-kind"), Group: pointer.String("*up"),
					},
				}},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("test-name"), Kind: pointer.String("test-kind"), Group: pointer.String("test-group"),
					},
				}},
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("*"), Kind: pointer.String("*"), Group: pointer.String("*"),
					},
				}},
				{Spec: policyapi.CertificateRequestPolicySpec{
					IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
						Name: pointer.String("test-*"), Kind: pointer.String("*-kind"), Group: pointer.String("*up"),
					},
				}},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			policies := issuerRefSelector(baseRequest, test.policies)
			if !apiequality.Semantic.DeepEqual(test.expPolicies, policies) {
				t.Errorf("unexpected policy response:\nexp=%#+v\ngot=%#+v", test.expPolicies, policies)
			}
		})
	}
}
