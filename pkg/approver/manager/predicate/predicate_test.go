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

package predicate

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
	"github.com/cert-manager/policy-approver/test/env"
)

func Test_RBACBound(t *testing.T) {
	rootDir := env.RootDirOrSkip(t)
	env := env.RunControlPlane(t,
		filepath.Join(rootDir, "bin/cert-manager"),
		filepath.Join(rootDir, "deploy/charts/policy-approver/templates/crds"),
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

	tests := map[string]struct {
		apiObjects  []client.Object
		policies    []policyapi.CertificateRequestPolicy
		expPolicies []policyapi.CertificateRequestPolicy
	}{
		"if no CertificateRequestPolicies exist, return nothing": {
			apiObjects:  nil,
			policies:    nil,
			expPolicies: nil,
		},
		"if no CertificateRequestPolicies are bound to the user, return ResultUnprocessed": {
			apiObjects: []client.Object{
				&policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
			},
			policies:    nil,
			expPolicies: nil,
		},
		"if single CertificateRequestPolicy exists but not bound, return nothing": {
			apiObjects: []client.Object{},
			policies: []policyapi.CertificateRequestPolicy{policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
			}},
			expPolicies: nil,
		},
		"if multiple CertificateRequestPolicy exists but not bound, return nothing": {
			apiObjects: []client.Object{},
			policies: []policyapi.CertificateRequestPolicy{
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
			},
			expPolicies: nil,
		},
		"if single CertificateRequestPolicy bound at cluster level, return policy": {
			apiObjects: []client.Object{
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
			policies: []policyapi.CertificateRequestPolicy{policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
			}},
			expPolicies: []policyapi.CertificateRequestPolicy{policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
			}},
		},
		"if single CertificateRequestPolicy bound at namespace, return policy": {
			apiObjects: []client.Object{
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
			policies: []policyapi.CertificateRequestPolicy{policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
			}},
			expPolicies: []policyapi.CertificateRequestPolicy{policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
			}},
		},
		"if two CertificateRequestPolicies bound at cluster level, return policies": {
			apiObjects: []client.Object{
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
			policies: []policyapi.CertificateRequestPolicy{
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
			},
		},
		"if two CertificateRequestPolicies bound at namespace level, return policies": {
			apiObjects: []client.Object{
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
			policies: []policyapi.CertificateRequestPolicy{
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
			},
		},
		"if two CertificateRequestPolicies bound at namespace and cluster, return policies": {
			apiObjects: []client.Object{
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
			policies: []policyapi.CertificateRequestPolicy{
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
			},
		},
		"if two CertificateRequestPolicies bound at namespace and cluster and other policies exist, return only bound policies": {
			apiObjects: []client.Object{
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
			policies: []policyapi.CertificateRequestPolicy{
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-c"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-d"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
				policyapi.CertificateRequestPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec:       policyapi.CertificateRequestPolicySpec{IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{}},
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() {
				for _, obj := range test.apiObjects {
					if err := env.AdminClient.Delete(context.TODO(), obj); err != nil {
						// Don't Fatal here as a ditch effort to at least try to clean-up
						// everything.
						t.Errorf("failed to deleted existing object: %s", err)
					}
				}
			})

			for _, obj := range test.apiObjects {
				if err := env.AdminClient.Create(context.TODO(), obj); err != nil {
					t.Fatalf("failed to create new object: %s", err)
				}
			}

			req := &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace},
				Spec: cmapi.CertificateRequestSpec{
					Username: "example",
					IssuerRef: cmmeta.ObjectReference{
						Name:  "test-name",
						Kind:  "test-kind",
						Group: "test-group",
					},
				},
			}
			policies, err := RBACBound(env.AdminClient)(context.TODO(), req, test.policies)
			assert.NoError(t, err)
			assert.Equal(t, test.expPolicies, policies)
		})
	}
}

func Test_Ready(t *testing.T) {
	tests := map[string]struct {
		policies    []policyapi.CertificateRequestPolicy
		expPolicies []policyapi.CertificateRequestPolicy
	}{
		"no given policies should return no policies": {
			policies:    nil,
			expPolicies: nil,
		},
		"single policy with no conditions should return no policies": {
			policies:    []policyapi.CertificateRequestPolicy{},
			expPolicies: nil,
		},
		"single policy with ready condition false should return no policies": {
			policies: []policyapi.CertificateRequestPolicy{
				policyapi.CertificateRequestPolicy{Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady, Status: corev1.ConditionFalse},
				}}},
			},
			expPolicies: nil,
		},
		"single policy with ready condition true should return policy": {
			policies: []policyapi.CertificateRequestPolicy{
				policyapi.CertificateRequestPolicy{Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady, Status: corev1.ConditionTrue},
				}}},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				policyapi.CertificateRequestPolicy{Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady, Status: corev1.ConditionTrue},
				}}},
			},
		},
		"one policy which is ready another not, return single policy": {
			policies: []policyapi.CertificateRequestPolicy{
				policyapi.CertificateRequestPolicy{Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady, Status: corev1.ConditionFalse},
				}}},
				policyapi.CertificateRequestPolicy{Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady, Status: corev1.ConditionTrue},
				}}},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				policyapi.CertificateRequestPolicy{Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady, Status: corev1.ConditionTrue},
				}}},
			},
		},
		"mix of different conditions including ready should return only ready policies": {
			policies: []policyapi.CertificateRequestPolicy{
				policyapi.CertificateRequestPolicy{Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady, Status: corev1.ConditionFalse},
					{Type: "C", Status: corev1.ConditionTrue},
				}}},
				policyapi.CertificateRequestPolicy{Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady, Status: corev1.ConditionTrue},
					{Type: "B", Status: corev1.ConditionTrue},
				}}},
				policyapi.CertificateRequestPolicy{Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady, Status: corev1.ConditionTrue},
					{Type: "A", Status: corev1.ConditionTrue},
				}}},
				policyapi.CertificateRequestPolicy{Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady, Status: corev1.ConditionTrue},
				}}},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				policyapi.CertificateRequestPolicy{Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady, Status: corev1.ConditionTrue},
					{Type: "B", Status: corev1.ConditionTrue},
				}}},
				policyapi.CertificateRequestPolicy{Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady, Status: corev1.ConditionTrue},
					{Type: "A", Status: corev1.ConditionTrue},
				}}},
				policyapi.CertificateRequestPolicy{Status: policyapi.CertificateRequestPolicyStatus{Conditions: []policyapi.CertificateRequestPolicyCondition{
					{Type: policyapi.CertificateRequestPolicyConditionReady, Status: corev1.ConditionTrue},
				}}},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			policies, err := Ready(context.TODO(), nil, test.policies)
			assert.NoError(t, err)
			if !apiequality.Semantic.DeepEqual(test.expPolicies, policies) {
				t.Errorf("unexpected policies returned:\nexp=%#+v\ngot=%#+v", test.expPolicies, policies)
			}
		})
	}
}

func Test_IssuerRefSelector(t *testing.T) {
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
			policies, err := IssuerRefSelector(context.TODO(), baseRequest, test.policies)
			assert.NoError(t, err)
			if !apiequality.Semantic.DeepEqual(test.expPolicies, policies) {
				t.Errorf("unexpected policies returned:\nexp=%#+v\ngot=%#+v", test.expPolicies, policies)
			}
		})
	}
}
