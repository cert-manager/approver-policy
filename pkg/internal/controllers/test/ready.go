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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/approver/fake"
	"github.com/cert-manager/approver-policy/pkg/registry"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Context("Ready", func() {
	var (
		ctx    = context.Background()
		cancel func()

		plugin1, plugin2, plugin3 *fake.FakeApprover

		enqueueChan1, enqueueChan2, enqueueChan3 = make(chan string), make(chan string), make(chan string)
	)

	JustBeforeEach(func() {
		plugin1 = fake.NewFakeApprover()
		plugin1.FakeReconciler = fake.NewFakeReconciler().WithName("test-plugin-1").WithEnqueueChan(func() <-chan string { return enqueueChan1 })
		plugin2 = fake.NewFakeApprover()
		plugin2.FakeReconciler = fake.NewFakeReconciler().WithName("test-plugin-2").WithEnqueueChan(func() <-chan string { return enqueueChan2 })
		plugin3 = fake.NewFakeApprover()
		plugin3.FakeReconciler = fake.NewFakeReconciler().WithName("test-plugin-3").WithEnqueueChan(func() <-chan string { return enqueueChan3 })

		registry := new(registry.Registry).Store(plugin1, plugin2, plugin3)
		ctx, cancel, _ = startControllers(registry)
	})

	JustAfterEach(func() {
		cancel()
	})

	It("if all reconcilers are defined in the policy and return ready, should mark policy as ready", func() {
		plugin1.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin2.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin3.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "allow-all-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin-1": {},
					"test-plugin-2": {},
					"test-plugin-3": {},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policy.Name)
	})

	It("if all reconcilers are defined but 1 returns not ready, should mark policy as not ready", func() {
		plugin1.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin2.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin3.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: false}, nil
		})

		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "allow-all-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin-1": {},
					"test-plugin-2": {},
					"test-plugin-3": {},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForNotReady(ctx, env.AdminClient, policy.Name)
	})

	It("if all reconcilers are defined but 2 return not ready, should mark policy as not ready", func() {
		plugin1.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin2.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: false}, nil
		})
		plugin3.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: false}, nil
		})

		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "allow-all-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin-1": {},
					"test-plugin-2": {},
					"test-plugin-3": {},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForNotReady(ctx, env.AdminClient, policy.Name)
	})

	It("if all reconcilers are defined but 3 return not ready, should mark policy as not ready", func() {
		plugin1.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: false}, nil
		})
		plugin2.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: false}, nil
		})
		plugin3.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: false}, nil
		})

		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "allow-all-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin-1": {},
					"test-plugin-2": {},
					"test-plugin-3": {},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForNotReady(ctx, env.AdminClient, policy.Name)
	})

	It("if some reconcilers are defined but not the one which is not ready, should mark the policy as ready", func() {
		plugin1.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin2.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			if _, ok := policy.Spec.Plugins["plugin-2"]; !ok {
				return approver.ReconcilerReadyResponse{Ready: true}, nil
			}
			return approver.ReconcilerReadyResponse{Ready: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("I"), "should not be called")}}, nil
		})
		plugin3.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "allow-all-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin-1": {},
					"test-plugin-3": {},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policy.Name)
	})

	It("if a reconciler returns not ready, but eventually becomes ready, should mark the policy as not ready, then ready", func() {
		plugin1.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		var i int
		plugin2.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			if i > 5 {
				return approver.ReconcilerReadyResponse{Ready: true}, nil
			}
			i++
			return approver.ReconcilerReadyResponse{Ready: false, Result: ctrl.Result{RequeueAfter: time.Millisecond * 100}}, nil
		})

		plugin3.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "allow-all-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin-1": {},
					"test-plugin-2": {},
					"test-plugin-3": {},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForNotReady(ctx, env.AdminClient, policy.Name)
		waitForReady(ctx, env.AdminClient, policy.Name)
	})

	It("if reconcilers return ready should set ready. After enqueue event, should update to false if next reconcile returns false", func() {
		var i int

		plugin1.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			if i == 0 {
				return approver.ReconcilerReadyResponse{Ready: true}, nil
			}
			return approver.ReconcilerReadyResponse{Ready: false}, nil
		})
		plugin2.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin3.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "allow-all-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin-1": {},
					"test-plugin-2": {},
					"test-plugin-3": {},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForReady(ctx, env.AdminClient, policy.Name)

		i++
		enqueueChan1 <- policy.Name
		waitForNotReady(ctx, env.AdminClient, policy.Name)
	})

	It("if reconcilers return not-ready should set not-ready. After enqueue event, should update to true if next reconcile returns true", func() {
		var i int

		plugin1.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin2.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			if i == 0 {
				return approver.ReconcilerReadyResponse{Ready: false}, nil
			}
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin3.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "allow-all-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin-1": {},
					"test-plugin-2": {},
					"test-plugin-3": {},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForNotReady(ctx, env.AdminClient, policy.Name)

		i++
		enqueueChan2 <- policy.Name
		waitForReady(ctx, env.AdminClient, policy.Name)
	})

	It("if reconcilers return not-ready should set not-ready. After enqueue event but for wrong name, should not change returning not-ready", func() {
		var i int

		plugin1.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin2.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			if i == 0 {
				return approver.ReconcilerReadyResponse{Ready: false}, nil
			}
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin3.FakeReconciler = fake.NewFakeReconciler().WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "allow-all-"},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
				},
				Plugins: map[string]policyapi.CertificateRequestPolicyPluginData{
					"test-plugin-1": {},
					"test-plugin-2": {},
					"test-plugin-3": {},
				},
			},
		}
		Expect(env.AdminClient.Create(ctx, &policy)).ToNot(HaveOccurred())
		waitForNotReady(ctx, env.AdminClient, policy.Name)

		i++
		enqueueChan2 <- "not-the-correct-name"

		Consistently(func() bool {
			Eventually(func() error {
				return env.AdminClient.Get(ctx, client.ObjectKeyFromObject(&policy), &policy)
			}, "10ms", "10s").Should(Succeed())
			for _, condition := range policy.Status.Conditions {
				if condition.ObservedGeneration != policy.Generation {
					return true
				}
				if condition.Type == policyapi.CertificateRequestPolicyConditionReady && condition.Status == metav1.ConditionTrue {
					return true
				}
			}
			return false
		}).WithTimeout(time.Second*10).WithPolling(time.Millisecond*10).Should(BeFalse(), "expected the condition to maintain not-ready")
	})
})
