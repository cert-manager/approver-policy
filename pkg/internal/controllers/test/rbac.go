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

package test

import (
	"context"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/approver/fake"
	"github.com/cert-manager/approver-policy/pkg/internal/approver/allowed"
	"github.com/cert-manager/approver-policy/pkg/internal/approver/constraints"
	"github.com/cert-manager/approver-policy/pkg/registry"
	testenv "github.com/cert-manager/approver-policy/test/env"
)

var _ = Context("RBAC", func() {
	var (
		ctx    = context.Background()
		plugin *fake.FakeApprover

		cancel    func()
		namespace corev1.Namespace
	)

	createPolicy := func() policyapi.CertificateRequestPolicy {
		policy := policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{GenerateName: "approve-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed:  &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"*.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin": policyapi.CertificateRequestPolicyPluginData{
						Values: map[string]string{"key-1": "val-1", "key-2": "val-2"},
					},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policy.Name)
		return policy
	}

	createRole := func(policy policyapi.CertificateRequestPolicy, name string) string {
		role := rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace.Name,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{"policy.cert-manager.io"},
					Resources:     []string{"certificaterequestpolicies"},
					Verbs:         []string{"use"},
					ResourceNames: []string{policy.Name},
				},
			},
		}

		// Optionally generate name if a name wasn't given
		if len(role.Name) == 0 {
			role.GenerateName = "test-policy-use-"
		}
		Expect(env.AdminClient.Create(ctx, &role)).NotTo(HaveOccurred())

		return role.Name
	}
	createRoleBinding := func(name string) {
		roleBinding := rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace.Name,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     "User",
					Name:     testenv.UserClientName,
					APIGroup: "rbac.authorization.k8s.io",
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     name,
			},
		}

		Expect(env.AdminClient.Create(ctx, &roleBinding)).NotTo(HaveOccurred())
	}

	createClusterRole := func(policy policyapi.CertificateRequestPolicy, name string) string {
		clusterRole := rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups:     []string{"policy.cert-manager.io"},
					Resources:     []string{"certificaterequestpolicies"},
					Verbs:         []string{"use"},
					ResourceNames: []string{policy.Name},
				},
			},
		}

		// Optionally generate name if a name wasn't given
		if len(clusterRole.Name) == 0 {
			clusterRole.GenerateName = "test-policy-use-"
		}
		Expect(env.AdminClient.Create(ctx, &clusterRole)).NotTo(HaveOccurred())

		return clusterRole.Name
	}
	createClusterRoleBinding := func(name string) {
		clusterRoleBinding := rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:     "User",
					Name:     testenv.UserClientName,
					APIGroup: "rbac.authorization.k8s.io",
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     name,
			},
		}

		Expect(env.AdminClient.Create(ctx, &clusterRoleBinding)).NotTo(HaveOccurred())
	}

	JustBeforeEach(func() {
		plugin = fake.NewFakeApprover()
		plugin.FakeReconciler = fake.NewFakeReconciler().WithName("test-plugin").WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin.FakeEvaluator = fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
			return approver.EvaluationResponse{Result: approver.ResultNotDenied}, nil
		})

		registry := new(registry.Registry).Store(allowed.Approver(), constraints.Approver(), plugin)
		ctx, cancel, namespace = startControllers(registry)
	})

	JustAfterEach(func() {
		cancel()
	})

	It("if a Role is created which binds the user, the request should be re-reconciled and approved", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		policy := createPolicy()

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name, testenv.UserClientName)
		createRoleBinding("approver-policy-test-rbac")

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name,
			gen.SetCSRDNSNames("example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)

		// Prove that the request is not bound to a policy.
		waitForNoApproveOrDeny(ctx, env.AdminClient, namespace.Name, crName)

		roleName := createRole(policy, "approver-policy-test-rbac")

		// Prove that the request is now bound, and the request was reconciled again.
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, env.AdminClient, namespace.Name, roleName, userCreateCRRoleName)
	})

	It("if a RoleBinding is created which binds the user, the request should be re-reconciled and approved", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		policy := createPolicy()

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name, testenv.UserClientName)
		roleName := createRole(policy, "")

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name,
			gen.SetCSRDNSNames("example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)

		// Prove that the request is not bound to a policy.
		waitForNoApproveOrDeny(ctx, env.AdminClient, namespace.Name, crName)

		createRoleBinding(roleName)

		// Prove that the request is now bound, and the request was reconciled again.
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, env.AdminClient, namespace.Name, roleName, userCreateCRRoleName)
	})

	It("if a ClusterRole is created which binds the user, the request should be re-reconciled and approved", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		policy := createPolicy()

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name, testenv.UserClientName)
		createClusterRoleBinding("approver-policy-test-rbac")

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name,
			gen.SetCSRDNSNames("example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)

		// Prove that the request is not bound to a policy.
		waitForNoApproveOrDeny(ctx, env.AdminClient, namespace.Name, crName)

		clusterRoleName := createClusterRole(policy, "approver-policy-test-rbac")

		// Prove that the request is now bound, and the request was reconciled again.
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, env.AdminClient, namespace.Name, userCreateCRRoleName)
		Expect(env.AdminClient.Delete(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: clusterRoleName}})).NotTo(HaveOccurred())
		Expect(env.AdminClient.Delete(ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "approver-policy-test-rbac"}})).NotTo(HaveOccurred())
	})

	It("if a ClusterRoleBinding is created which binds the user, the request should be re-reconciled and approved", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		policy := createPolicy()

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name, testenv.UserClientName)
		clusterRoleName := createClusterRole(policy, "")

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name,
			gen.SetCSRDNSNames("example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)

		// Prove that the request is not bound to a policy.
		waitForNoApproveOrDeny(ctx, env.AdminClient, namespace.Name, crName)

		createClusterRoleBinding(clusterRoleName)

		// Prove that the request is now bound, and the request was reconciled again.
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, env.AdminClient, namespace.Name, userCreateCRRoleName)
		Expect(env.AdminClient.Delete(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: clusterRoleName}})).NotTo(HaveOccurred())
		Expect(env.AdminClient.Delete(ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: clusterRoleName}})).NotTo(HaveOccurred())
	})
})
