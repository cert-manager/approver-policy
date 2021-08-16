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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	cmpapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	_ "github.com/cert-manager/policy-approver/pkg/approver/attribute"
	"github.com/cert-manager/policy-approver/pkg/internal/controller"
)

const (
	testRoleName        = "test-role"
	testRoleBindingName = "test-role-binding"
)

var _ = Context("Policy", func() {
	var (
		ctx    context.Context
		cancel func()

		userRole  string
		namespace corev1.Namespace
	)

	JustBeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())

		userRole = bindAllUsersToCreateCertificateRequest(ctx, env.AdminClient)

		namespace = corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "test-policy-",
			},
		}
		Expect(env.AdminClient.Create(ctx, &namespace)).NotTo(HaveOccurred())
		By("Created Policy Namespace: " + namespace.Name)

		mgr, err := ctrl.NewManager(env.Config, ctrl.Options{
			Scheme:                        cmpapi.GlobalScheme,
			LeaderElection:                true,
			MetricsBindAddress:            "0",
			LeaderElectionNamespace:       namespace.Name,
			LeaderElectionID:              "cert-manager-policy-approver",
			LeaderElectionReleaseOnCancel: true,
			Logger:                        logf.Log,
		})
		Expect(err).NotTo(HaveOccurred())

		Expect(controller.AddPolicyController(ctx, mgr, controller.Options{Log: logf.Log})).NotTo(HaveOccurred())

		By("Running Policy controller")
		go mgr.Start(ctx)

		By("Waiting for Informers to Sync")
		Expect(mgr.GetCache().WaitForCacheSync(ctx)).Should(BeTrue())

		By("Waiting for Leader Election")
		<-mgr.Elected()
	})

	JustAfterEach(func() {
		Expect(env.AdminClient.Delete(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: userRole}})).ToNot(HaveOccurred())
		Expect(env.AdminClient.Delete(ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: userRole}})).ToNot(HaveOccurred())

		By("Deleting test policy Namespace: " + namespace.Name)
		Expect(env.AdminClient.Delete(ctx, &namespace)).ToNot(HaveOccurred())

		By("deleting all policies")
		var polList cmpapi.CertificateRequestPolicyList
		Expect(env.AdminClient.List(ctx, &polList)).ToNot(HaveOccurred())

		if len(polList.Items) > 0 {
			Expect(env.AdminClient.DeleteAllOf(ctx, new(cmpapi.CertificateRequestPolicy))).ToNot(HaveOccurred())
		}

		By("Cleaning up RBAC")
		var role rbacv1.ClusterRole
		err := env.AdminClient.Get(ctx, client.ObjectKey{Name: testRoleName}, &role)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				Expect(err).ToNot(HaveOccurred())
			}
		} else {
			Expect(env.AdminClient.Delete(ctx, &role)).ToNot(HaveOccurred())
		}

		var binding rbacv1.ClusterRoleBinding
		err = env.AdminClient.Get(ctx, client.ObjectKey{Name: testRoleBindingName}, &binding)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				Expect(err).ToNot(HaveOccurred())
			}
		} else {
			Expect(env.AdminClient.Delete(ctx, &binding)).ToNot(HaveOccurred())
		}

		By("Stopping Policy controller")
		cancel()
	})

	It("if no policies exist, then requests should be neither approved or denied", func() {
		csr, _, err := gen.CSR(x509.RSA)
		Expect(err).ToNot(HaveOccurred())

		err = env.UserClient.Create(ctx, gen.CertificateRequest("no-policy",
			gen.SetCertificateRequestNamespace(namespace.Name),
			gen.SetCertificateRequestCSR(csr),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
				Name:  "my-issuer",
				Kind:  "Issuer",
				Group: "cert-manager.io",
			}),
		))
		Expect(err).ToNot(HaveOccurred())

		Consistently(func() bool {
			cr := new(cmapi.CertificateRequest)
			Expect(env.AdminClient.Get(ctx, client.ObjectKey{Namespace: namespace.Name, Name: "no-policy"}, cr)).ToNot(HaveOccurred())
			return apiutil.CertificateRequestIsApproved(cr) || apiutil.CertificateRequestIsDenied(cr)
		}, "3s").Should(BeFalse())
	})

	It("if one policy exists but not bound, then all requests should be denied", func() {
		csr, _, err := gen.CSR(x509.RSA)
		Expect(err).ToNot(HaveOccurred())

		err = env.UserClient.Create(ctx, gen.CertificateRequest("no-bind",
			gen.SetCertificateRequestNamespace(namespace.Name),
			gen.SetCertificateRequestCSR(csr),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
				Name:  "my-issuer",
				Kind:  "Issuer",
				Group: "cert-manager.io",
			}),
		))
		Expect(err).ToNot(HaveOccurred())

		err = env.AdminClient.Create(ctx, &cmpapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "allow-all",
			},
			Spec: cmpapi.CertificateRequestPolicySpec{},
		})
		Expect(err).ToNot(HaveOccurred())

		waitForDenial(ctx, env.AdminClient, namespace.Name, "no-bind")
	})

	It("if 'allow-all' policy exists and is bound, all requests should be approved", func() {
		bindAllToPolicy(ctx, env.AdminClient, "allow-all")

		err := env.AdminClient.Create(ctx, &cmpapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "allow-all",
			},
			Spec: cmpapi.CertificateRequestPolicySpec{},
		})
		Expect(err).ToNot(HaveOccurred())
		time.Sleep(time.Microsecond * 500)

		csr, _, err := gen.CSR(x509.RSA)
		Expect(err).ToNot(HaveOccurred())

		err = env.UserClient.Create(ctx, gen.CertificateRequest("bound",
			gen.SetCertificateRequestNamespace(namespace.Name),
			gen.SetCertificateRequestCSR(csr),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
				Name:  "my-issuer",
				Kind:  "Issuer",
				Group: "cert-manager.io",
			}),
		))
		Expect(err).ToNot(HaveOccurred())

		waitForApproval(ctx, env.AdminClient, namespace.Name, "bound")
	})

	It("if policy exists and is bound, only requests that match should be approved", func() {
		bindAllToPolicy(ctx, env.AdminClient, "allow-common-name-foo")

		err := env.AdminClient.Create(ctx, &cmpapi.CertificateRequestPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "allow-common-name-foo",
			},
			Spec: cmpapi.CertificateRequestPolicySpec{
				AllowedDNSNames: &[]string{"foo"},
			},
		})
		Expect(err).ToNot(HaveOccurred())

		csr, _, err := gen.CSR(x509.RSA, gen.SetCSRDNSNames("bar"))
		Expect(err).ToNot(HaveOccurred())
		err = env.UserClient.Create(ctx, gen.CertificateRequest("bad-dns",
			gen.SetCertificateRequestNamespace(namespace.Name),
			gen.SetCertificateRequestCSR(csr),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
				Name:  "my-issuer",
				Kind:  "Issuer",
				Group: "cert-manager.io",
			}),
		))
		Expect(err).ToNot(HaveOccurred())
		waitForDenial(ctx, env.AdminClient, namespace.Name, "bad-dns")

		csr, _, err = gen.CSR(x509.RSA, gen.SetCSRDNSNames("foo"))
		Expect(err).ToNot(HaveOccurred())
		err = env.UserClient.Create(ctx, gen.CertificateRequest("good-dns",
			gen.SetCertificateRequestNamespace(namespace.Name),
			gen.SetCertificateRequestCSR(csr),
			gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
				Name:  "my-issuer",
				Kind:  "Issuer",
				Group: "cert-manager.io",
			}),
		))
		Expect(err).ToNot(HaveOccurred())
		waitForApproval(ctx, env.AdminClient, namespace.Name, "good-dns")
	})
})

func waitForApproval(ctx context.Context, cl client.Client, ns, name string) {
	Eventually(func() bool {
		cr := new(cmapi.CertificateRequest)
		Expect(cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, cr)).ToNot(HaveOccurred())
		return apiutil.CertificateRequestIsApproved(cr)
	}).Should(BeTrue())
}

func waitForDenial(ctx context.Context, cl client.Client, ns, name string) {
	Eventually(func() bool {
		cr := new(cmapi.CertificateRequest)
		Expect(cl.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, cr)).ToNot(HaveOccurred())
		return apiutil.CertificateRequestIsDenied(cr)
	}).Should(BeTrue())
}

func bindAllToPolicy(ctx context.Context, cl client.Client, policyName string) {
	role := rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: testRoleName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{"policy.cert-manager.io"},
				Resources:     []string{"certificaterequestpolicies"},
				Verbs:         []string{"use"},
				ResourceNames: []string{policyName},
			},
		},
	}
	Expect(cl.Create(ctx, &role)).NotTo(HaveOccurred())

	binding := rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: testRoleBindingName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "Group",
				Name:     "system:authenticated",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     role.Name,
		},
	}
	Expect(cl.Create(ctx, &binding)).NotTo(HaveOccurred())
}

func bindAllUsersToCreateCertificateRequest(ctx context.Context, cl client.Client) string {
	role := rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-cr-create-",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"cert-manager.io"},
				Resources: []string{"certificaterequests"},
				Verbs:     []string{"create"},
			},
		},
	}
	Expect(cl.Create(ctx, &role)).NotTo(HaveOccurred())

	binding := rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: role.Name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:     "Group",
				Name:     "system:authenticated",
				APIGroup: "rbac.authorization.k8s.io",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     role.Name,
		},
	}
	Expect(cl.Create(ctx, &binding)).NotTo(HaveOccurred())

	return role.Name
}
