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

package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/unit/gen"
	"github.com/stretchr/testify/assert"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2/klogr"
	fakeclock "k8s.io/utils/clock/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/pkg/approver"
	fakeapprover "github.com/cert-manager/policy-approver/pkg/approver/fake"
)

func Test_waitForWebhookCertificateKey(t *testing.T) {
	tests := map[string]struct {
		files    []string
		expError bool
	}{
		"if files never added, expect context error": {
			files:    nil,
			expError: true,
		},
		"if just cert file added, expect context error": {
			files:    []string{"tls.crt"},
			expError: true,
		},
		"if just key file added, expect context error": {
			files:    []string{"tls.key"},
			expError: true,
		},
		"if two random files added, expect context error": {
			files:    []string{"foo", "bar"},
			expError: true,
		},
		"if both files added, expect no error": {
			files:    []string{"tls.crt", "tls.key"},
			expError: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for _, file := range test.files {
				assert.NoError(t, os.WriteFile(filepath.Join(dir, file), []byte("test data"), 0644))
			}

			b := &bootstrapper{
				certDir:                     dir,
				webhookFileCheckRetryPeriod: time.Millisecond * 9,
				log:                         klogr.New(),
			}

			ctx, cancel := context.WithCancel(context.TODO())

			go func() {
				time.Sleep(time.Millisecond * 20)
				cancel()
			}()

			err := b.waitForWebhookCertificateKey(ctx)
			assert.Equalf(t, test.expError, err != nil, "%v", err)
		})
	}
}

func Test_evaluateWebhookCertificateRequest(t *testing.T) {
	var (
		fixedTime     = time.Date(2021, 01, 01, 01, 0, 0, 0, time.UTC)
		fixedmetatime = &metav1.Time{Time: fixedTime}
		fixedclock    = fakeclock.NewFakeClock(fixedTime)

		baseRequest = gen.CertificateRequest("test",
			gen.SetCertificateRequestTypeMeta(metav1.TypeMeta{Kind: "CertificateRequest", APIVersion: "cert-manager.io/v1"}),
			func(cr *cmapi.CertificateRequest) {
				cr.ResourceVersion = "3"
			},
		)
	)

	tests := map[string]struct {
		request   *cmapi.CertificateRequest
		evaluator approver.Evaluator
		expObject runtime.Object
		expError  bool
	}{
		"if request is already approved, ignore": {
			request: gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "bad-name", Kind: "Issuer", Group: "cert-manager.io",
				}),
				gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type: cmapi.CertificateRequestConditionApproved, Status: cmmeta.ConditionTrue,
				}),
			),
			expObject: gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "bad-name", Kind: "Issuer", Group: "cert-manager.io",
				}),
				gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type: cmapi.CertificateRequestConditionApproved, Status: cmmeta.ConditionTrue,
				}),
			),
			expError: false,
		},
		"if request is already denied, ignore": {
			request: gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "bad-name", Kind: "Issuer", Group: "cert-manager.io",
				}),
				gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type: cmapi.CertificateRequestConditionDenied, Status: cmmeta.ConditionTrue,
				}),
			),
			expObject: gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "bad-name", Kind: "Issuer", Group: "cert-manager.io",
				}),
				gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type: cmapi.CertificateRequestConditionDenied, Status: cmmeta.ConditionTrue,
				}),
			),
			expError: false,
		},
		"if request has wrong name, update denied": {
			request: gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "bad-name", Kind: "Issuer", Group: "cert-manager.io",
				}),
			),
			expObject: gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "bad-name", Kind: "Issuer", Group: "cert-manager.io",
				}),
				gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type: cmapi.CertificateRequestConditionDenied, Status: cmmeta.ConditionTrue,
					Reason:             "webhook.policy.cert-manager.io",
					Message:            "certificaterequest has wrong issuer ref",
					LastTransitionTime: fixedmetatime,
				}),
				func(cr *cmapi.CertificateRequest) {
					cr.ResourceVersion = "4"
				},
			),
			expError: false,
		},
		"if request has wrong kind, update denied": {
			request: gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "cert-manager-policy-approver", Kind: "ClusterIssuer", Group: "cert-manager.io",
				}),
			),
			expObject: gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "cert-manager-policy-approver", Kind: "ClusterIssuer", Group: "cert-manager.io",
				}),
				gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type: cmapi.CertificateRequestConditionDenied, Status: cmmeta.ConditionTrue,
					Reason:             "webhook.policy.cert-manager.io",
					Message:            "certificaterequest has wrong issuer ref",
					LastTransitionTime: fixedmetatime,
				}),
				func(cr *cmapi.CertificateRequest) {
					cr.ResourceVersion = "4"
				},
			),
			expError: false,
		},
		"if request has wrong group, update denied": {
			request: gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "cert-manager-policy-approver", Kind: "Issuer", Group: "foo.cert-manager.io",
				}),
			),
			expObject: gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "cert-manager-policy-approver", Kind: "Issuer", Group: "foo.cert-manager.io",
				}),
				gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type: cmapi.CertificateRequestConditionDenied, Status: cmmeta.ConditionTrue,
					Reason:             "webhook.policy.cert-manager.io",
					Message:            "certificaterequest has wrong issuer ref",
					LastTransitionTime: fixedmetatime,
				}),
				func(cr *cmapi.CertificateRequest) {
					cr.ResourceVersion = "4"
				},
			),
			expError: false,
		},
		"if evaluation returns an error, return error": {
			request: gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "cert-manager-policy-approver", Kind: "Issuer", Group: "cert-manager.io",
				}),
			),
			evaluator: fakeapprover.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
				return approver.EvaluationResponse{}, errors.New("this is an error")
			}),
			expObject: gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "cert-manager-policy-approver", Kind: "Issuer", Group: "cert-manager.io",
				}),
			),
			expError: true,
		},
		"if evaluation returns denied, update denied": {
			request: gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "cert-manager-policy-approver", Kind: "Issuer", Group: "cert-manager.io",
				}),
			),
			evaluator: fakeapprover.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
				return approver.EvaluationResponse{Result: approver.ResultDenied, Message: "This is a denied message"}, nil
			}),
			expObject: gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "cert-manager-policy-approver", Kind: "Issuer", Group: "cert-manager.io",
				}),
				gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type: cmapi.CertificateRequestConditionDenied, Status: cmmeta.ConditionTrue,
					Reason:             "webhook.policy.cert-manager.io",
					Message:            "This is a denied message",
					LastTransitionTime: fixedmetatime,
				}),
				func(cr *cmapi.CertificateRequest) {
					cr.ResourceVersion = "4"
				},
			),
			expError: false,
		},
		"if evaluation returns not-denied, update approved": {
			request: gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "cert-manager-policy-approver", Kind: "Issuer", Group: "cert-manager.io",
				}),
			),
			evaluator: fakeapprover.NewFakeEvaluator().WithEvaluate(func(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
				return approver.EvaluationResponse{Result: approver.ResultNotDenied}, nil
			}),
			expObject: gen.CertificateRequestFrom(baseRequest,
				gen.SetCertificateRequestIssuer(cmmeta.ObjectReference{
					Name: "cert-manager-policy-approver", Kind: "Issuer", Group: "cert-manager.io",
				}),
				gen.AddCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
					Type: cmapi.CertificateRequestConditionApproved, Status: cmmeta.ConditionTrue,
					Reason:             "webhook.policy.cert-manager.io",
					Message:            "policy-approver webhook certificate passes policy",
					LastTransitionTime: fixedmetatime,
				}),
				func(cr *cmapi.CertificateRequest) {
					cr.ResourceVersion = "4"
				},
			),
			expError: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			apiutil.Clock = fixedclock

			fakeclient := fakeclient.NewClientBuilder().
				WithScheme(policyapi.GlobalScheme).
				WithRuntimeObjects(test.request).
				Build()

			b := &bootstrapper{
				evaluator: test.evaluator,
				client:    fakeclient,
			}

			err := b.evaluateWebhookCertificateRequest(context.TODO(), klogr.New(), test.request)
			assert.Equalf(t, test.expError, err != nil, "%v", err)

			var cr cmapi.CertificateRequest
			err = fakeclient.Get(context.TODO(), client.ObjectKey{Namespace: gen.DefaultTestNamespace, Name: "test"}, &cr)
			if err != nil {
				t.Errorf("unexpected error getting expected object: %s", err)
			} else if !apiequality.Semantic.DeepEqual(test.expObject, &cr) {
				t.Errorf("unexpected expected object, exp=%#+v got=%#+v", test.expObject, &cr)
			}
		})
	}
}
