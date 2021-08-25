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

package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	apiequality "k8s.io/apimachinery/pkg/api/equality"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/test/unit/gen"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog/v2/klogr"
	fakeclock "k8s.io/utils/clock/testing"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/pkg/approver/manager"
	fakemanager "github.com/cert-manager/policy-approver/pkg/approver/manager/fake"
)

func Test_Reconcile(t *testing.T) {
	const (
		requestName             = "test-bundle"
		requestGeneration int64 = 2
	)

	var (
		fixedTime     = time.Date(2021, 01, 01, 01, 0, 0, 0, time.UTC)
		fixedmetatime = &metav1.Time{Time: fixedTime}
		fixedclock    = fakeclock.NewFakeClock(fixedTime)

		baseRequest = gen.CertificateRequest(requestName,
			gen.SetCertificateRequestTypeMeta(metav1.TypeMeta{
				Kind:       "CertificateRequest",
				APIVersion: "cert-manager.io/v1",
			}),
			func(cr *cmapi.CertificateRequest) {
				cr.ResourceVersion = "999"
			},
			gen.SetCertificateRequestNamespace(gen.DefaultTestNamespace),
		)
	)

	tests := map[string]struct {
		existingObjects []runtime.Object
		manager         manager.Interface

		expResult  ctrl.Result
		expError   bool
		expObjects []runtime.Object
		expEvent   string
	}{
		"if request doesn't exist, no nothing": {
			existingObjects: nil,
			expResult:       ctrl.Result{},
			expError:        false,
			expObjects:      nil,
			expEvent:        "",
		},
		"if manager review returns an error, fire event and return an error": {
			existingObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			manager: fakemanager.NewFakeManager().WithReview(func(context.Context, *cmapi.CertificateRequest) (manager.ReviewResponse, error) {
				return manager.ReviewResponse{Message: "a review error"}, errors.New("this is an error")
			}),
			expResult:  ctrl.Result{},
			expError:   true,
			expObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			expEvent:   "Warning EvaluationError policy-approver failed to review the request and will retry",
		},
		"if manager review returns an empty response, fire event and return a re-queue response": {
			existingObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			manager: fakemanager.NewFakeManager().WithReview(func(context.Context, *cmapi.CertificateRequest) (manager.ReviewResponse, error) {
				return manager.ReviewResponse{}, nil
			}),
			expResult:  ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5},
			expError:   false,
			expObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			expEvent:   "Warning UnknownResponse Policy returned an unknown result. This is a bug. Please check the policy-approver logs and file an issue",
		},
		"if manager review returns an unknown response, fire event and return a re-queue response": {
			existingObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			manager: fakemanager.NewFakeManager().WithReview(func(context.Context, *cmapi.CertificateRequest) (manager.ReviewResponse, error) {
				return manager.ReviewResponse{Result: 5, Message: "unknown result"}, nil
			}),
			expResult:  ctrl.Result{Requeue: true, RequeueAfter: time.Second * 5},
			expError:   false,
			expObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			expEvent:   "Warning UnknownResponse Policy returned an unknown result. This is a bug. Please check the policy-approver logs and file an issue",
		},
		"if manager review returns an unprocessed response, fire event and do nothing": {
			existingObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			manager: fakemanager.NewFakeManager().WithReview(func(context.Context, *cmapi.CertificateRequest) (manager.ReviewResponse, error) {
				return manager.ReviewResponse{Result: manager.ResultUnprocessed, Message: "unprocessed result"}, nil
			}),
			expResult:  ctrl.Result{},
			expError:   false,
			expObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			expEvent:   "Normal Unprocessed Request is not applicable for any policy so ignoring",
		},
		"if manager review returns denied, fire event and update request with denied": {
			existingObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			manager: fakemanager.NewFakeManager().WithReview(func(context.Context, *cmapi.CertificateRequest) (manager.ReviewResponse, error) {
				return manager.ReviewResponse{Result: manager.ResultDenied, Message: "denied due to some violation"}, nil
			}),
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: []runtime.Object{
				gen.CertificateRequestFrom(baseRequest,
					func(cr *cmapi.CertificateRequest) {
						cr.ResourceVersion = "1000"
					},
					gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:               cmapi.CertificateRequestConditionDenied,
						Status:             cmmeta.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "policy.cert-manager.io",
						Message:            "denied due to some violation",
					}),
				)},
			expEvent: "Warning Denied denied due to some violation",
		},
		"if manager review returns true, fire event and update request with approved": {
			existingObjects: []runtime.Object{gen.CertificateRequestFrom(baseRequest)},
			manager: fakemanager.NewFakeManager().WithReview(func(context.Context, *cmapi.CertificateRequest) (manager.ReviewResponse, error) {
				return manager.ReviewResponse{Result: manager.ResultApproved, Message: "policy is happy :)"}, nil
			}),
			expResult: ctrl.Result{},
			expError:  false,
			expObjects: []runtime.Object{
				gen.CertificateRequestFrom(baseRequest,
					func(cr *cmapi.CertificateRequest) {
						cr.ResourceVersion = "1000"
					},
					gen.SetCertificateRequestStatusCondition(cmapi.CertificateRequestCondition{
						Type:               cmapi.CertificateRequestConditionApproved,
						Status:             cmmeta.ConditionTrue,
						LastTransitionTime: fixedmetatime,
						Reason:             "policy.cert-manager.io",
						Message:            "policy is happy :)",
					}),
				)},
			expEvent: "Normal Approved policy is happy :)",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			apiutil.Clock = fixedclock

			fakeclient := fakeclient.NewClientBuilder().
				WithScheme(policyapi.GlobalScheme).
				WithRuntimeObjects(test.existingObjects...).
				Build()

			fakerecorder := record.NewFakeRecorder(1)

			c := &controller{
				client:   fakeclient,
				lister:   fakeclient,
				recorder: fakerecorder,
				manager:  test.manager,
				log:      klogr.New(),
			}

			resp, err := c.Reconcile(context.TODO(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: gen.DefaultTestNamespace, Name: requestName}})
			if (err != nil) != test.expError {
				t.Errorf("unexpected error, exp=%t got=%v", test.expError, err)
			}

			if !apiequality.Semantic.DeepEqual(resp, test.expResult) {
				t.Errorf("unexpected Reconcile response, exp=%v got=%v", test.expResult, resp)
			}

			var event string
			select {
			case event = <-fakerecorder.Events:
			default:
			}
			if event != test.expEvent {
				t.Errorf("unexpected event, exp=%q got=%q", test.expEvent, event)
			}

			for _, expectedObject := range test.expObjects {
				expObj := expectedObject.(client.Object)
				var actual client.Object
				switch expObj.(type) {
				case *cmapi.CertificateRequest:
					actual = &cmapi.CertificateRequest{}
				default:
					t.Errorf("unexpected object kind in expected: %#+v", expObj)
				}

				err := fakeclient.Get(context.TODO(), client.ObjectKeyFromObject(expObj), actual)
				if err != nil {
					t.Errorf("unexpected error getting expected object: %s", err)
				} else if !apiequality.Semantic.DeepEqual(expObj, actual) {
					t.Errorf("unexpected expected object, exp=%#+v got=%#+v", expObj, actual)
				}
			}
		})
	}
}
