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

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/unit/gen"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
)

var _ = Describe("Smoke", func() {
	It("should create a CertificateRequestPolicy, RBAC bind to all users, deny and approve a request", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cl, err := client.New(cnf.RestConfig, client.Options{
			Scheme: policyapi.GlobalScheme,
		})
		Expect(err).NotTo(HaveOccurred())

		By("Creating test Namespace")
		namespace := corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "smoke-test-policy-",
			},
		}
		Expect(cl.Create(ctx, &namespace)).NotTo(HaveOccurred())

		By("Creating test SelfSigned Issuer")
		issuer := cmapi.Issuer{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "smoke-test-policy-",
				Namespace:    namespace.Name,
			},
			Spec: cmapi.IssuerSpec{IssuerConfig: cmapi.IssuerConfig{SelfSigned: &cmapi.SelfSignedIssuer{}}},
		}
		Expect(cl.Create(ctx, &issuer)).NotTo(HaveOccurred())

		By("Creating CertificateRequestPolicy for test")
		policy := policyapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "smoke-test-policy-",
			},
			Spec: policyapi.CertificateRequestPolicySpec{
				AllowedCommonName: pointer.String("*.test.policy"),
				IssuerRefSelector: &policyapi.CertificateRequestPolicyIssuerRefSelector{
					Name: pointer.String(issuer.Name),
				},
			},
		}
		Expect(cl.Create(ctx, &policy)).NotTo(HaveOccurred())

		By("Waiting for CertificateRequestPolicy to become ready")
		Eventually(func() bool {
			Expect(cl.Get(ctx, client.ObjectKey{Name: policy.Name}, &policy)).NotTo(HaveOccurred())
			for _, condition := range policy.Status.Conditions {
				if condition.Type == policyapi.CertificateRequestPolicyConditionReady {
					return condition.Status == corev1.ConditionTrue && condition.ObservedGeneration == policy.Generation
				}
			}
			return false
		}, "5s", "100ms").Should(BeTrue())

		By("Binding all authenticated users to the test CertificateRequestPolicy")
		role := rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "smoke-test-policy-",
				Namespace:    namespace.Name,
			},
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{"policy.cert-manager.io"}, Resources: []string{"certificaterequestpolicies"}, ResourceNames: []string{"smoke-test-policy"}, Verbs: []string{"use"}},
			},
		}
		Expect(cl.Create(ctx, &role)).NotTo(HaveOccurred())

		rolebinding := rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "smoke-test-policy-",
				Namespace:    namespace.Name,
			},
			RoleRef: rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: role.Name},
			Subjects: []rbacv1.Subject{
				{Kind: "Group", Name: "system:authenticated", APIGroup: "rbac.authorization.k8s.io"},
			},
		}
		Expect(cl.Create(ctx, &rolebinding)).NotTo(HaveOccurred())

		By("Creating CertificateRequest that violates policy")
		csrPEM, _, err := gen.CSR(x509.RSA, gen.SetCSRCommonName("test.foo.policy"))
		Expect(err).NotTo(HaveOccurred())

		certificateRequest := cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "smoke-test-policy-",
				Namespace:    namespace.Name,
			},
			Spec: cmapi.CertificateRequestSpec{
				Request:   csrPEM,
				IssuerRef: cmmeta.ObjectReference{Name: issuer.Name, Kind: "Issuer", Group: "cert-manager.io"},
			},
		}
		Expect(cl.Create(ctx, &certificateRequest)).NotTo(HaveOccurred())

		By("Waiting for CertificateRequest to be denied")
		Eventually(func() bool {
			Expect(cl.Get(ctx, client.ObjectKey{Namespace: namespace.Name, Name: certificateRequest.Name}, &certificateRequest)).NotTo(HaveOccurred())
			return apiutil.CertificateRequestIsDenied(&certificateRequest)
		}, "5s", "100ms").Should(BeTrue())
		Expect(cl.Delete(ctx, &certificateRequest)).NotTo(HaveOccurred())

		By("Creating CertificateRequest that passes policy")
		csrPEM, _, err = gen.CSR(x509.RSA, gen.SetCSRCommonName("foo.test.policy"))
		Expect(err).NotTo(HaveOccurred())

		certificateRequest = cmapi.CertificateRequest{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "smoke-test-policy-",
				Namespace:    namespace.Name,
			},
			Spec: cmapi.CertificateRequestSpec{
				Request:   csrPEM,
				IssuerRef: cmmeta.ObjectReference{Name: issuer.Name, Kind: "Issuer", Group: "cert-manager.io"},
			},
		}
		Expect(cl.Create(ctx, &certificateRequest)).NotTo(HaveOccurred())

		By("Waiting for CertificateRequest to be approved")
		Eventually(func() bool {
			Expect(cl.Get(ctx, client.ObjectKey{Namespace: namespace.Name, Name: certificateRequest.Name}, &certificateRequest)).NotTo(HaveOccurred())
			return apiutil.CertificateRequestIsApproved(&certificateRequest)
		}, "5s", "100ms").Should(BeTrue())

		By("Cleaning up test resources")
		Expect(cl.Delete(ctx, &namespace)).NotTo(HaveOccurred())
		Expect(cl.Delete(ctx, &policy)).NotTo(HaveOccurred())
		Expect(cl.Delete(ctx, &role)).NotTo(HaveOccurred())
		Expect(cl.Delete(ctx, &rolebinding)).NotTo(HaveOccurred())
		Expect(cl.Delete(ctx, &issuer)).NotTo(HaveOccurred())
		Expect(cl.Delete(ctx, &certificateRequest)).NotTo(HaveOccurred())
	})
})
