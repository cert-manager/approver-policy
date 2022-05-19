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
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/approver/allowed"
	"github.com/cert-manager/approver-policy/pkg/approver/constraints"
	"github.com/cert-manager/approver-policy/pkg/approver/fake"
	"github.com/cert-manager/approver-policy/pkg/registry"
	testenv "github.com/cert-manager/approver-policy/test/env"
)

var _ = Context("Selector", func() {
	var (
		ctx    = context.Background()
		plugin *fake.FakeApprover

		cancel    func()
		namespace corev1.Namespace
	)

	JustBeforeEach(func() {
		plugin = fake.NewFakeApprover().
			WithReconciler(fake.NewFakeReconciler().WithName("test-plugin")).
			WithEvaluator(fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
				return approver.EvaluationResponse{Result: approver.ResultNotDenied}, nil
			}))

		registry := new(registry.Registry).Store(allowed.Allowed{}, constraints.Constraints{}, plugin)
		ctx, cancel, namespace = startControllers(registry)
	})

	JustAfterEach(func() {
		cancel()
	})

	It("it should select on all CertificateRequests where issuerRef={}, RBAC bound, and plugin return Ready", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "allow-all-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin": policyapi.CertificateRequestPolicyPluginData{},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policy.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name, testenv.UserClientName)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, testenv.UserClientName, policy.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames(),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)
		crName = createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames(),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer-2", Kind: "ClusterIssuer", Group: "cert-manager.io"}),
		)
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, env.AdminClient, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("it should select on all CertificateRequests where issuerRef={name=* kind=* group=*}, RBAC bound, and plugin return Ready", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "allow-all-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{
						Name: pointer.String("*"), Kind: pointer.String("*"), Group: pointer.String("*"),
					},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin": policyapi.CertificateRequestPolicyPluginData{},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policy.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name, testenv.UserClientName)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, testenv.UserClientName, policy.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames(),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)
		crName = createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames(),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer-2", Kind: "ClusterIssuer", Group: "cert-manager.io"}),
		)
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, env.AdminClient, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("it should select on all CertificateRequests where issuerRef={name=my-* kind=*uer group=*}, RBAC bound, and plugin return Ready", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "allow-all-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{
						Name: pointer.String("my-*"), Kind: pointer.String("*uer"), Group: pointer.String("*"),
					},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin": policyapi.CertificateRequestPolicyPluginData{},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policy.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name, testenv.UserClientName)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, testenv.UserClientName, policy.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames(),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)
		crName = createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames(),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer-2", Kind: "ClusterIssuer", Group: "cert-manager.io"}),
		)
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, env.AdminClient, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("it should not select on CertificateRequests where the IssuerRef does not match", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "allow-all-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{
						Name: pointer.String("my-*"), Kind: pointer.String("*uer"), Group: pointer.String("foo"),
					},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin": policyapi.CertificateRequestPolicyPluginData{},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policy.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name, testenv.UserClientName)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, testenv.UserClientName, policy.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames(),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForNoApproveOrDeny(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, env.AdminClient, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("it should not select on CertificateRequests where the IssuerRef matches but the policy is not ready", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: false, Result: ctrl.Result{Requeue: true, RequeueAfter: time.Millisecond * 50}}, nil
		})
		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "allow-all"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{
						Name: pointer.String("my-*"), Kind: pointer.String("*uer"), Group: pointer.String("cert-manager.io"),
					},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin": policyapi.CertificateRequestPolicyPluginData{},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForNotReady(ctx, env.AdminClient, policy.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name, testenv.UserClientName)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, testenv.UserClientName, policy.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames(),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForNoApproveOrDeny(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, env.AdminClient, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("it should not select on CertificateRequests where the IssuerRef matches and policy is ready but not bound to user", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "allow-all-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{
						Name: pointer.String("my-*"), Kind: pointer.String("*uer"), Group: pointer.String("cert-manager.io"),
					},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin": policyapi.CertificateRequestPolicyPluginData{},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policy.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name, testenv.UserClientName)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames(),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForNoApproveOrDeny(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, env.AdminClient, namespace.Name, userCreateCRRoleName)
	})

	It("it should not select on policies where the user is not RBAC bound", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "allow-all-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{
						Name: pointer.String("*"), Kind: pointer.String("*"), Group: pointer.String("*"),
					},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin": policyapi.CertificateRequestPolicyPluginData{},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policy.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name, testenv.UserClientName)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames(),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForNoApproveOrDeny(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, env.AdminClient, namespace.Name, userCreateCRRoleName)
	})
})
