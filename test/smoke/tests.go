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

package smoke

import (
	"context"
	"crypto/x509"
	"time"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Policy", func() {
	var (
		ctx       context.Context
		cl        client.Client
		namespace corev1.Namespace
		issuer    cmapi.Issuer
		policy    policyapi.CertificateRequestPolicy
	)

	BeforeEach(func() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(context.Background())

		var err error
		cl, err = client.New(cnf.RestConfig, client.Options{
			Scheme: policyapi.GlobalScheme,
		})
		Expect(err).NotTo(HaveOccurred())

		namespace = corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "smoke-test-policy-",
			},
		}
		Expect(cl.Create(ctx, &namespace)).To(Succeed())

		issuer = cmapi.Issuer{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "smoke-test-policy-",
				Namespace:    namespace.Name,
			},
			Spec: cmapi.IssuerSpec{IssuerConfig: cmapi.IssuerConfig{SelfSigned: &cmapi.SelfSignedIssuer{}}},
		}
		Expect(cl.Create(ctx, &issuer)).To(Succeed())

		policy = policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "smoke-test-policy-",
			},
			Spec: policyapi.CertificateRequestPolicySpec{
				Selector: policyapi.CertificateRequestPolicySelector{
					IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{
						Name: ptr.To(issuer.Name),
					},
					Namespace: &policyapi.CertificateRequestPolicySelectorNamespace{
						MatchNames: []string{namespace.Name},
					},
				},
			},
		}

		DeferCleanup(func() {
			Expect(cl.Delete(ctx, &namespace)).To(Succeed())
			Expect(cl.Delete(ctx, &policy)).To(Succeed())

			cancel()
		})
	})

	JustBeforeEach(func() {
		Expect(cl.Create(ctx, &policy)).To(Succeed())

		By("Waiting for CertificateRequestPolicy to become ready")
		Eventually(func() bool {
			Expect(cl.Get(ctx, client.ObjectKey{Name: policy.Name}, &policy)).To(Succeed())
			for _, condition := range policy.Status.Conditions {
				if condition.Type == policyapi.ConditionTypeReady {
					return condition.Status == metav1.ConditionTrue && condition.ObservedGeneration == policy.Generation
				}
			}
			return false
		}).WithTimeout(time.Second * 10).WithPolling(time.Millisecond * 10).Should(BeTrue())
	})

	Context("with allowed CommonName", func() {
		var certificateRequest cmapi.CertificateRequest

		BeforeEach(func() {
			certificateRequest = cmapi.CertificateRequest{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: "smoke-test-policy-",
					Namespace:    namespace.Name,
				},
				Spec: cmapi.CertificateRequestSpec{
					IssuerRef: cmmeta.IssuerReference{Name: issuer.Name, Kind: "Issuer", Group: "cert-manager.io"},
				},
			}

			policy.Spec.Allowed = &policyapi.CertificateRequestPolicyAllowed{
				CommonName: &policyapi.CertificateRequestPolicyAllowedString{Value: ptr.To("*.test.policy")},
			}
		})

		It("should deny request that violates policy", func() {
			csrPEM, _, err := gen.CSR(x509.RSA, gen.SetCSRCommonName("test.foo.policy"))
			Expect(err).NotTo(HaveOccurred())

			certificateRequest.Spec.Request = csrPEM
			Expect(cl.Create(ctx, &certificateRequest)).To(Succeed())

			By("Waiting for CertificateRequest to be denied")
			Eventually(func() bool {
				Expect(cl.Get(ctx, client.ObjectKey{Namespace: namespace.Name, Name: certificateRequest.Name}, &certificateRequest)).To(Succeed())
				return apiutil.CertificateRequestIsDenied(&certificateRequest)
			}).WithTimeout(time.Second * 10).WithPolling(time.Millisecond * 10).Should(BeTrue())
		})

		It("should approve request that passes policy", func() {
			csrPEM, _, err := gen.CSR(x509.RSA, gen.SetCSRCommonName("foo.test.policy"))
			Expect(err).NotTo(HaveOccurred())

			certificateRequest.Spec.Request = csrPEM
			Expect(cl.Create(ctx, &certificateRequest)).To(Succeed())

			By("Waiting for CertificateRequest to be approved")
			Eventually(func() bool {
				Expect(cl.Get(ctx, client.ObjectKey{Namespace: namespace.Name, Name: certificateRequest.Name}, &certificateRequest)).To(Succeed())
				return apiutil.CertificateRequestIsApproved(&certificateRequest)
			}).WithTimeout(time.Second * 10).WithPolling(time.Millisecond * 10).Should(BeTrue())
		})
	})
})
