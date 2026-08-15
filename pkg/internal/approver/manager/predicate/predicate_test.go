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
	"path"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	testenv "github.com/cert-manager/approver-policy/test/env"
)

func Test_RBACBound(t *testing.T) {
	env := testenv.RunControlPlane(t, t.Context(),
		testenv.GetenvOrFail(t, "CERT_MANAGER_CRDS"),
		path.Join("..", "..", "..", "..", "..", "deploy", "crds"),
	)

	const (
		requestUser      = "example"
		requestNamespace = "test-namespace"
	)

	if err := env.AdminClient.Create(t.Context(),
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
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
			},
			policies:    nil,
			expPolicies: nil,
		},
		"if single CertificateRequestPolicy exists but not bound, return nothing": {
			apiObjects: []client.Object{},
			policies: []policyapi.CertificateRequestPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				}},
			}},
			expPolicies: nil,
		},
		"if multiple CertificateRequestPolicy exists but not bound, return nothing": {
			apiObjects: []client.Object{},
			policies: []policyapi.CertificateRequestPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
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
			policies: []policyapi.CertificateRequestPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				}},
			}},
			expPolicies: []policyapi.CertificateRequestPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				}},
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
			policies: []policyapi.CertificateRequestPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				}},
			}},
			expPolicies: []policyapi.CertificateRequestPolicy{{
				ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
				Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				}},
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
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
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
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
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
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
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
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-c"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-d"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
			},
			expPolicies: []policyapi.CertificateRequestPolicy{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-a"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-policy-b"},
					Spec: policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{
						IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
					}},
				},
			},
		},
	}

	ctx := t.Context()
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() {
				for _, obj := range test.apiObjects {
					if err := env.AdminClient.Delete(ctx, obj); err != nil {
						// Don't Fatal here as a ditch effort to at least try to clean-up
						// everything.
						t.Errorf("failed to deleted existing object: %s", err)
					}
				}
			})

			for _, obj := range test.apiObjects {
				if err := env.AdminClient.Create(ctx, obj); err != nil {
					t.Fatalf("failed to create new object: %s", err)
				}
			}

			req := &cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Namespace: requestNamespace},
				Spec: cmapi.CertificateRequestSpec{
					Username: "example",
					IssuerRef: cmmeta.IssuerReference{
						Name:  "test-name",
						Kind:  "test-kind",
						Group: "test-group",
					},
				},
			}

			// RBACBound performs SubjectAccessReviews which may get a response based on an out-of-date
			// RoleBinding/ClusterRoleBinding/... cache in the API server. Therefore we retry the assertion
			// for a short period of time to allow for eventual consistency.
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				policies, err := RBACBound(env.AdminClient)(ctx, req, test.policies)
				require.NoError(ct, err)
				require.Equal(ct, test.expPolicies, policies)
			}, 10*time.Second, 1*time.Second)
		})
	}
}
