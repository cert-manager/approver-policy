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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest/komega"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/approver/fake"
	"github.com/cert-manager/approver-policy/pkg/internal/approver/allowed"
	"github.com/cert-manager/approver-policy/pkg/internal/approver/constraints"
	"github.com/cert-manager/approver-policy/pkg/registry"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Context("Review", func() {
	var (
		ctx    = context.Background()
		plugin *fake.FakeApprover

		cancel    func()
		namespace corev1.Namespace
	)

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

	It("if a policy approves the request, the CertificateRequest should be approved", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		policy := policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{GenerateName: "approve-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed:  &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"*.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin": {
						Values: map[string]string{"key-1": "val-1", "key-2": "val-2"},
					},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policy.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, policy.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name,
			gen.SetCSRDNSNames("example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("if a policy denies the request, the CertificateRequest should be denied", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		policy := policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed:  &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"foo.example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin": {
						Values: map[string]string{"key-1": "val-1", "key-2": "val-2"},
					},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policy.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, policy.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name,
			gen.SetCSRDNSNames("example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForDenial(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("if a policy plugin denies the request, the CertificateRequest should be denied", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin.FakeEvaluator = fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, policy *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
			return approver.EvaluationResponse{Result: approver.ResultDenied}, nil
		})

		alg := cmapi.ECDSAKeyAlgorithm
		policy := policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed: &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"example.com"}}},
				Constraints: &policyapi.CertificateRequestPolicyConstraints{
					PrivateKey: &policyapi.CertificateRequestPolicyConstraintsPrivateKey{
						Algorithm: &alg,
					},
				},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin": {
						Values: map[string]string{"key-1": "val-1", "key-2": "val-2"},
					},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policy.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, policy.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name,
			gen.SetCSRDNSNames("example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForDenial(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("if a policy initially denies the request but is updated to allow, the second request should be approved", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		policy := policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-then-approve-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed:  &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"foo.example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin": {Values: map[string]string{"key-1": "val-1", "key-2": "val-2"}},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policy.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, policy.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name,
			gen.SetCSRDNSNames("example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForDenial(ctx, env.AdminClient, namespace.Name, crName)

		Expect(env.AdminClient.Get(ctx, client.ObjectKeyFromObject(&policy), &policy)).ToNot(HaveOccurred())
		*policy.Spec.Allowed.DNSNames.Values = append(*policy.Spec.Allowed.DNSNames.Values, "example.com")
		Expect(env.AdminClient.Update(ctx, &policy)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policy.Name)

		crName = createCertificateRequest(ctx, env.UserClient, namespace.Name,
			gen.SetCSRDNSNames("example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("if one policy denies the request but one allows, the request should be approved", func() {
		policyDeny := policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed:  &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
			},
		}
		policyApprove := policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{GenerateName: "approve-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed:  &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"*.example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
			},
		}

		Expect(env.AdminClient.Create(ctx, &policyDeny)).ToNot(HaveOccurred())
		Expect(env.AdminClient.Create(ctx, &policyApprove)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policyDeny.Name)
		waitForReady(ctx, env.AdminClient, policyApprove.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, policyDeny.Name, policyApprove.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames("foo.example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("if two policies deny the request but one allows, it should approve the request", func() {
		policyDeny1 := policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-1-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed:  &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
			},
		}
		policyDeny2 := policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-2-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed:  &policyapi.CertificateRequestPolicyAllowed{CommonName: &policyapi.CertificateRequestPolicyAllowedString{Value: pointer.String("foo.example.com")}},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
			},
		}
		policyApprove := policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{GenerateName: "approve-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed: &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"*.example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
			},
		}

		Expect(env.AdminClient.Create(ctx, &policyDeny1)).ToNot(HaveOccurred())
		Expect(env.AdminClient.Create(ctx, &policyDeny2)).ToNot(HaveOccurred())
		Expect(env.AdminClient.Create(ctx, &policyApprove)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policyDeny1.Name)
		waitForReady(ctx, env.AdminClient, policyDeny2.Name)
		waitForReady(ctx, env.AdminClient, policyApprove.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, policyDeny1.Name, policyDeny2.Name, policyApprove.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames("foo.example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("if one policy denies the request but two allows, it should approve the request", func() {
		policyDeny := policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed:  &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
			},
		}
		policyApprove1 := policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{GenerateName: "approve-1-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed:  &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"foo.example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
			},
		}
		policyApprove2 := policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{GenerateName: "approve-1-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed:  &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"*.example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
			},
		}

		Expect(env.AdminClient.Create(ctx, &policyDeny)).ToNot(HaveOccurred())
		Expect(env.AdminClient.Create(ctx, &policyApprove1)).ToNot(HaveOccurred())
		Expect(env.AdminClient.Create(ctx, &policyApprove2)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policyDeny.Name)
		waitForReady(ctx, env.AdminClient, policyApprove1.Name)
		waitForReady(ctx, env.AdminClient, policyApprove2.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, policyDeny.Name, policyApprove1.Name, policyApprove2.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames("foo.example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("if two policies deny the request, it should deny the request", func() {
		policyDeny1 := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-1-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed:  &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
			},
		}
		policyDeny2 := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-2-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed:  &policyapi.CertificateRequestPolicyAllowed{CommonName: &policyapi.CertificateRequestPolicyAllowedString{Value: pointer.String("foo.example.com")}},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
			},
		}

		Expect(env.AdminClient.Create(ctx, &policyDeny1)).ToNot(HaveOccurred())
		Expect(env.AdminClient.Create(ctx, &policyDeny2)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policyDeny1.Name)
		waitForReady(ctx, env.AdminClient, policyDeny2.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, policyDeny1.Name, policyDeny2.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames("foo.example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForDenial(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("if three policies deny the request, it should deny the request", func() {
		policyDeny1 := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-1-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed:  &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
			},
		}
		policyDeny2 := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-2-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed:  &policyapi.CertificateRequestPolicyAllowed{CommonName: &policyapi.CertificateRequestPolicyAllowedString{Value: pointer.String("foo.example.com")}},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
			},
		}
		policyDeny3 := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-3-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed:  &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"bar.example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{}},
			},
		}

		Expect(env.AdminClient.Create(ctx, &policyDeny1)).ToNot(HaveOccurred())
		Expect(env.AdminClient.Create(ctx, &policyDeny2)).ToNot(HaveOccurred())
		Expect(env.AdminClient.Create(ctx, &policyDeny3)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policyDeny1.Name)
		waitForReady(ctx, env.AdminClient, policyDeny2.Name)
		waitForReady(ctx, env.AdminClient, policyDeny3.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, policyDeny1.Name, policyDeny2.Name, policyDeny3.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames("foo.example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForDenial(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("if one policy denies the request and one allows but is not ready, should deny the request", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			if _, ok := policy.Spec.Plugins["test-plugin"]; !ok {
				return approver.ReconcilerReadyResponse{Ready: false}, nil
			}
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin.FakeEvaluator = fake.NewFakeEvaluator().WithEvaluate(func(_ context.Context, policy *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
			if _, ok := policy.Spec.Plugins["test-plugin"]; !ok {
				return approver.EvaluationResponse{Result: approver.ResultNotDenied}, nil
			}
			return approver.EvaluationResponse{Result: approver.ResultDenied}, nil
		})

		policyApprove := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "approve-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed: &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"foo.example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
			},
		}
		policyDeny := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed: &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"test-plugin": {
					Values: map[string]string{"key-1": "val-1", "key-2": "val-2"},
				}},
			},
		}

		Expect(env.AdminClient.Create(ctx, &policyApprove)).ToNot(HaveOccurred())
		Expect(env.AdminClient.Create(ctx, &policyDeny)).ToNot(HaveOccurred())
		waitForNotReady(ctx, env.AdminClient, policyApprove.Name)
		waitForReady(ctx, env.AdminClient, policyDeny.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, policyApprove.Name, policyDeny.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames("foo.example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForDenial(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("if one policy allows the request and one denies but is not ready, should approve the request", func() {
		plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			if _, ok := policy.Spec.Plugins["test-plugin"]; ok {
				return approver.ReconcilerReadyResponse{Ready: false}, nil
			}
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		policyApprove := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "approve-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed: &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
			},
		}
		policyDeny := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed: &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"foo.example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"test-plugin": {}},
			},
		}

		Expect(env.AdminClient.Create(ctx, &policyApprove)).ToNot(HaveOccurred())
		Expect(env.AdminClient.Create(ctx, &policyDeny)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policyApprove.Name)
		waitForNotReady(ctx, env.AdminClient, policyDeny.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, policyApprove.Name, policyDeny.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames("example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("if two policies allow the request but one of those is not ready, one denies the request, should approve the request", func() {
		plugin.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			if _, ok := policy.Spec.Plugins["test-plugin"]; ok {
				return approver.ReconcilerReadyResponse{Ready: false}, nil
			}
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		policyApprove1 := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "approve-1-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed: &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
			},
		}
		policyApprove2 := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "approve-2-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed: &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"*.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"test-plugin": {}},
			},
		}
		policyDeny := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed: &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"foo.example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
			},
		}

		Expect(env.AdminClient.Create(ctx, &policyApprove1)).ToNot(HaveOccurred())
		Expect(env.AdminClient.Create(ctx, &policyApprove2)).ToNot(HaveOccurred())
		Expect(env.AdminClient.Create(ctx, &policyDeny)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policyApprove1.Name)
		waitForNotReady(ctx, env.AdminClient, policyApprove2.Name)
		waitForReady(ctx, env.AdminClient, policyDeny.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, policyApprove1.Name, policyApprove2.Name, policyDeny.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames("example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForApproval(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	It("if three policies deny the request but all are not ready, should neither approve or deny the request", func() {
		plugin.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: false}, nil
		})

		policyDeny1 := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-1-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed: &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"bar.example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"test-plugin": {}},
			},
		}
		policyDeny2 := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-2-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed: &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"*.bar"}}},
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"test-plugin": {}},
			},
		}
		policyDeny3 := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "deny-3-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Allowed: &policyapi.CertificateRequestPolicyAllowed{DNSNames: &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: &[]string{"foo.example.com"}}},
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{"test-plugin": {}},
			},
		}

		Expect(env.AdminClient.Create(ctx, &policyDeny1)).ToNot(HaveOccurred())
		Expect(env.AdminClient.Create(ctx, &policyDeny2)).ToNot(HaveOccurred())
		Expect(env.AdminClient.Create(ctx, &policyDeny3)).ToNot(HaveOccurred())
		waitForNotReady(ctx, env.AdminClient, policyDeny1.Name)
		waitForNotReady(ctx, env.AdminClient, policyDeny2.Name)
		waitForNotReady(ctx, env.AdminClient, policyDeny3.Name)

		userCreateCRRoleName := bindUserToCreateCertificateRequest(ctx, env.AdminClient, namespace.Name)
		userUsePolicyRoleName := bindUserToUseCertificateRequestPolicies(ctx, env.AdminClient, namespace.Name, policyDeny1.Name, policyDeny2.Name, policyDeny3.Name)

		crName := createCertificateRequest(ctx, env.UserClient, namespace.Name, gen.SetCSRDNSNames("example.com"),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{Name: "my-issuer", Kind: "Issuer", Group: "cert-manager.io"}),
		)
		waitForNoApproveOrDeny(ctx, env.AdminClient, namespace.Name, crName)

		deleteRoleAndRoleBindings(ctx, namespace.Name, userUsePolicyRoleName, userCreateCRRoleName)
	})

	Context("Reconcile consistency", func() {
		It("If the policy is not ready, should have stable resource version", func() {
			plugin.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
				return approver.ReconcilerReadyResponse{Ready: false}, nil
			})

			policyNotReady := policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{GenerateName: "not-ready-"}}
			var policy policyapi.CertificateRequestPolicy

			komega.SetClient(env.AdminClient)
			Expect(env.AdminClient.Create(ctx, &policyNotReady)).ToNot(HaveOccurred())
			waitForNotReady(ctx, env.AdminClient, policyNotReady.Name)
			Expect(env.AdminClient.Get(ctx, client.ObjectKey{Name: policyNotReady.Name}, &policy)).To(Succeed())

			resourceVersion := policy.ResourceVersion
			Consistently(komega.Object(&policy)).Should(HaveField("ObjectMeta.ResourceVersion", Equal(resourceVersion)))
		})

		It("If the policy is ready, should have stable resource version", func() {
			policyReady := policyapi.CertificateRequestPolicy{ObjectMeta: metav1.ObjectMeta{GenerateName: "ready-"}}
			var policy policyapi.CertificateRequestPolicy

			komega.SetClient(env.AdminClient)
			Expect(env.AdminClient.Create(ctx, &policyReady)).ToNot(HaveOccurred())
			waitForReady(ctx, env.AdminClient, policyReady.Name)
			Expect(env.AdminClient.Get(ctx, client.ObjectKey{Name: policyReady.Name}, &policy)).To(Succeed())

			resourceVersion := policy.ResourceVersion
			Consistently(komega.Object(&policy)).Should(HaveField("ObjectMeta.ResourceVersion", Equal(resourceVersion)))
		})
	})
})
