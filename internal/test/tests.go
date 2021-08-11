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
	"crypto/x509"
	"time"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/unit/gen"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmpapi "github.com/cert-manager/policy-approver/apis/v1alpha1"
)

var (
	kubeclient     client.Client
	kubeconfigPath string

	role    *rbacv1.ClusterRole
	binding *rbacv1.ClusterRoleBinding
)

var _ = Context("Policy", func() {
	var (
		namespace *corev1.Namespace
	)

	BeforeEach(func() {
		namespace = &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "policy-approver-e2e-",
			},
		}

		role = nil
		binding = nil

		Expect(kubeclient.Create(context.TODO(), namespace)).ToNot(HaveOccurred())
		By("created test namespace " + namespace.Name)
	})

	AfterEach(func() {
		By("deleting test namespace " + namespace.Name)
		Expect(kubeclient.Delete(context.TODO(), namespace)).ToNot(HaveOccurred())

		By("deleting all policies")
		polList := new(cmpapi.CertificateRequestPolicyList)
		Expect(kubeclient.List(context.TODO(), polList)).ToNot(HaveOccurred())

		if len(polList.Items) > 0 {
			Expect(kubeclient.DeleteAllOf(context.TODO(), new(cmpapi.CertificateRequestPolicy))).ToNot(HaveOccurred())
		}

		if role != nil {
			By("deleting role " + role.Name)
			Expect(kubeclient.Delete(context.TODO(), role)).ToNot(HaveOccurred())
		}
		if binding != nil {
			By("deleting binding " + binding.Name)
			Expect(kubeclient.Delete(context.TODO(), binding)).ToNot(HaveOccurred())
		}
	})

	It("if no policies exist, then all requests should be denied", func() {
		csr, _, err := gen.CSR(x509.RSA)
		Expect(err).ToNot(HaveOccurred())

		err = kubeclient.Create(context.TODO(), gen.CertificateRequest("no-policy",
			gen.SetCertificateRequestNamespace(namespace.Name),
			gen.SetCertificateRequestCSR(csr),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
				Name:  "my-issuer",
				Kind:  "Issuer",
				Group: "cert-manager.io",
			}),
		))
		Expect(err).ToNot(HaveOccurred())

		waitForDenial(namespace.Name, "no-policy")
	})

	It("if one policy exist but not bound, then all requests should be denied", func() {
		csr, _, err := gen.CSR(x509.RSA)
		Expect(err).ToNot(HaveOccurred())

		err = kubeclient.Create(context.TODO(), gen.CertificateRequest("no-bind",
			gen.SetCertificateRequestNamespace(namespace.Name),
			gen.SetCertificateRequestCSR(csr),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
				Name:  "my-issuer",
				Kind:  "Issuer",
				Group: "cert-manager.io",
			}),
		))
		Expect(err).ToNot(HaveOccurred())

		err = kubeclient.Create(context.TODO(), &cmpapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "allow-all",
			},
			Spec: cmpapi.CertificateRequestPolicySpec{},
		})
		Expect(err).ToNot(HaveOccurred())

		waitForDenial(namespace.Name, "no-bind")
	})

	It("if allow all policy exists and is bound, all requests should be approved", func() {
		bindAllToPolicy("allow-all")

		err := kubeclient.Create(context.TODO(), &cmpapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "allow-all",
			},
			Spec: cmpapi.CertificateRequestPolicySpec{},
		})
		Expect(err).ToNot(HaveOccurred())

		csr, _, err := gen.CSR(x509.RSA)
		Expect(err).ToNot(HaveOccurred())

		err = kubeclient.Create(context.TODO(), gen.CertificateRequest("bound",
			gen.SetCertificateRequestNamespace(namespace.Name),
			gen.SetCertificateRequestCSR(csr),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
				Name:  "my-issuer",
				Kind:  "Issuer",
				Group: "cert-manager.io",
			}),
		))
		Expect(err).ToNot(HaveOccurred())

		waitForApproval(namespace.Name, "bound")
	})

	It("if policy exists and is bound, only requests that match should be approved", func() {
		bindAllToPolicy("allow-common-name-foo")

		dnsName := "foo"
		err := kubeclient.Create(context.TODO(), &cmpapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "allow-common-name-foo",
			},
			Spec: cmpapi.CertificateRequestPolicySpec{
				AllowedDNSNames: &[]string{dnsName},
			},
		})
		Expect(err).ToNot(HaveOccurred())

		csr, _, err := gen.CSR(x509.RSA, gen.SetCSRDNSNames("bar"))
		Expect(err).ToNot(HaveOccurred())
		err = kubeclient.Create(context.TODO(), gen.CertificateRequest("bad-dns",
			gen.SetCertificateRequestNamespace(namespace.Name),
			gen.SetCertificateRequestCSR(csr),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
				Name:  "my-issuer",
				Kind:  "Issuer",
				Group: "cert-manager.io",
			}),
		))
		Expect(err).ToNot(HaveOccurred())
		waitForDenial(namespace.Name, "bad-dns")

		csr, _, err = gen.CSR(x509.RSA, gen.SetCSRDNSNames("foo"))
		Expect(err).ToNot(HaveOccurred())
		err = kubeclient.Create(context.TODO(), gen.CertificateRequest("good-dns",
			gen.SetCertificateRequestNamespace(namespace.Name),
			gen.SetCertificateRequestCSR(csr),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
				Name:  "my-issuer",
				Kind:  "Issuer",
				Group: "cert-manager.io",
			}),
		))
		Expect(err).ToNot(HaveOccurred())
		waitForApproval(namespace.Name, "good-dns")
	})
})

func waitForApproval(ns, name string) {
	waitFor(ns, name, apiutil.CertificateRequestIsApproved)
}

func waitForDenial(ns, name string) {
	waitFor(ns, name, apiutil.CertificateRequestIsDenied)
}

func waitFor(ns, name string, fn func(*cmapi.CertificateRequest) bool) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := wait.PollUntil(time.Second, func() (done bool, err error) {
		cr := new(cmapi.CertificateRequest)
		err = kubeclient.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, cr)
		Expect(err).ToNot(HaveOccurred())

		return fn(cr), nil
	}, ctx.Done())

	Expect(err).ToNot(HaveOccurred())
}

func bindAllToPolicy(policyName string) {
	role = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy-role",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{"policy.cert-manager.io"},
				Resources:     []string{"certificaterequestpolicies"},
				Verbs:         []string{"user"},
				ResourceNames: []string{policyName},
			},
		},
	}
	Expect(kubeclient.Create(context.TODO(), role)).NotTo(HaveOccurred())

	binding = &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "policy-rolebindin",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "Group",
				Name: "system:authenticated",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "policy-role",
		},
	}
	Expect(kubeclient.Create(context.TODO(), binding)).NotTo(HaveOccurred())
}
