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
	"sync/atomic"
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

	BeforeEach(func() {
		plugin1 = fake.NewFakeApprover()
		plugin1.FakeReconciler = fake.NewFakeReconciler().WithName("test-plugin-1").WithEnqueueChan(func() <-chan string { return enqueueChan1 })
		plugin2 = fake.NewFakeApprover()
		plugin2.FakeReconciler = fake.NewFakeReconciler().WithName("test-plugin-2").WithEnqueueChan(func() <-chan string { return enqueueChan2 })
		plugin3 = fake.NewFakeApprover()
		plugin3.FakeReconciler = fake.NewFakeReconciler().WithName("test-plugin-3").WithEnqueueChan(func() <-chan string { return enqueueChan3 })
	})

	// start starts the controllers. Each spec calls it after it has set the
	// Ready funcs of the plugins, because the controllers call those funcs
	// from other goroutines as soon as they start.
	start := func() {
		ctx, cancel, _ = startControllers(new(registry.Registry).Store(plugin1, plugin2, plugin3))
	}

	JustAfterEach(func() {
		cancel()
	})

	It("if all reconcilers are defined in the policy and return ready, should mark policy as ready", func() {
		plugin1.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin2.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin3.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		start()

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
		plugin1.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin2.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin3.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: false}, nil
		})

		start()

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
		plugin1.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin2.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: false}, nil
		})
		plugin3.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: false}, nil
		})

		start()

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
		plugin1.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: false}, nil
		})
		plugin2.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: false}, nil
		})
		plugin3.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: false}, nil
		})

		start()

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
		plugin1.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin2.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			if _, ok := policy.Spec.Plugins["plugin-2"]; !ok {
				return approver.ReconcilerReadyResponse{Ready: true}, nil
			}
			return approver.ReconcilerReadyResponse{Ready: false, Errors: field.ErrorList{field.Forbidden(field.NewPath("I"), "should not be called")}}, nil
		})
		plugin3.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		start()

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
		plugin1.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		var i atomic.Int64
		plugin2.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			if i.Load() > 5 {
				return approver.ReconcilerReadyResponse{Ready: true}, nil
			}
			i.Add(1)
			return approver.ReconcilerReadyResponse{Ready: false, Result: ctrl.Result{RequeueAfter: time.Millisecond * 100}}, nil
		})

		plugin3.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		start()

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
		var i atomic.Int64

		plugin1.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			if i.Load() == 0 {
				return approver.ReconcilerReadyResponse{Ready: true}, nil
			}
			return approver.ReconcilerReadyResponse{Ready: false}, nil
		})
		plugin2.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin3.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		start()

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

		i.Add(1)
		enqueueChan1 <- policy.Name
		waitForNotReady(ctx, env.AdminClient, policy.Name)
	})

	It("if reconcilers return not-ready should set not-ready. After enqueue event, should update to true if next reconcile returns true", func() {
		var i atomic.Int64

		plugin1.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin2.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			if i.Load() == 0 {
				return approver.ReconcilerReadyResponse{Ready: false}, nil
			}
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin3.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		start()

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

		i.Add(1)
		enqueueChan2 <- policy.Name
		waitForReady(ctx, env.AdminClient, policy.Name)
	})

	It("if reconcilers return not-ready should set not-ready. After enqueue event but for wrong name, should not change returning not-ready", func() {
		// ready is what plugin 2 reports. The test flips it to true before
		// sending the enqueue event, so that any reconcile of the policy after
		// that point marks it ready.
		var ready atomic.Bool

		plugin1.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin2.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: ready.Load()}, nil
		})
		plugin3.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		start()

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

		ready.Store(true)
		enqueueChan2 <- "not-the-correct-name"

		Consistently(func() bool {
			Eventually(func() error {
				return env.AdminClient.Get(ctx, client.ObjectKeyFromObject(&policy), &policy)
			}, "10ms", "10s").Should(Succeed())
			for _, condition := range policy.Status.Conditions {
				if condition.ObservedGeneration != policy.Generation {
					return true
				}
				if condition.Type == policyapi.ConditionTypeReady && condition.Status == metav1.ConditionTrue {
					return true
				}
			}
			return false
		}).WithTimeout(time.Second*10).WithPolling(time.Millisecond*10).Should(BeFalse(), "expected the condition to maintain not-ready")
	})

	It("should reconcile the policy once for each change, and not again for its own status update", func() {
		// readyCalls counts how many times plugin 1 has been asked about this
		// spec's policy, which is once per reconcile of that policy. Calls for
		// any other policy are not counted.
		const policyName = "reconcile-once-per-change"
		var readyCalls atomic.Int64

		plugin1.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			if policy.Name == policyName {
				readyCalls.Add(1)
			}
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin2.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})
		plugin3.FakeReconciler.WithReady(func(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
			return approver.ReconcilerReadyResponse{Ready: true}, nil
		})

		start()

		// expectReadyCalls waits for the policy to be ready, and then checks
		// that plugin 1 has been called n times and is not called again.
		expectReadyCalls := func(policyName string, n int64) {
			waitForReady(ctx, env.AdminClient, policyName)
			Eventually(readyCalls.Load).WithTimeout(time.Second * 10).WithPolling(time.Millisecond * 10).Should(Equal(n))
			Consistently(readyCalls.Load).WithTimeout(time.Second*2).WithPolling(time.Millisecond*10).Should(Equal(n), "expected no reconcile after the status update")
		}

		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: policyName},
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
		expectReadyCalls(policy.Name, 1)

		By("Changing the spec")
		patch := client.MergeFrom(policy.DeepCopy())
		policy.Spec.Plugins["test-plugin-1"] = policyapi.CertificateRequestPolicyPluginData{Values: map[string]string{"key": "value"}}
		Expect(env.AdminClient.Patch(ctx, &policy, patch)).ToNot(HaveOccurred())
		expectReadyCalls(policy.Name, 2)

		By("Changing a label")
		patch = client.MergeFrom(policy.DeepCopy())
		policy.Labels = map[string]string{"foo": "bar"}
		Expect(env.AdminClient.Patch(ctx, &policy, patch)).ToNot(HaveOccurred())
		expectReadyCalls(policy.Name, 3)

		By("Changing an annotation")
		patch = client.MergeFrom(policy.DeepCopy())
		policy.Annotations = map[string]string{"foo": "bar"}
		Expect(env.AdminClient.Patch(ctx, &policy, patch)).ToNot(HaveOccurred())
		expectReadyCalls(policy.Name, 4)
	})
})
