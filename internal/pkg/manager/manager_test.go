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

package manager

import (
	"context"
	"testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	cmpapi "github.com/cert-manager/policy-approver/apis/v1alpha1"
	"github.com/cert-manager/policy-approver/registry"
)

func TestEvaluate(t *testing.T) {
	expNoEvaluator := func(t *testing.T) registry.EvaluateFunc {
		return func(policy *cmpapi.CertificateRequestPolicy, cr *cmapi.CertificateRequest) (bool, string, error) {
			t.Fatal("unexpected evaluator call")
			return false, "", nil
		}
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cmpapi.AddToScheme(scheme))

	tests := map[string]struct {
		client    *fakeclient.ClientBuilder
		evaluator func(t *testing.T) registry.EvaluateFunc

		expOK     bool
		expReason PolicyMessage
		expErr    bool
	}{
		//"if no CertificateRequestPolicies exist, return ok": {
		//	client:    fakeclient.NewClientBuilder(),
		//	evaluator: expNoEvaluator,
		//	expOK:     true,
		//	expReason: NoCRPExistMessage,
		//	expErr:    false,
		//},
		"if no CertificateRequestPolicies exist, return not ok": {
			client:    fakeclient.NewClientBuilder(),
			evaluator: expNoEvaluator,
			expOK:     false,
			expReason: MessageNoApplicableCertificateRequestPolicy,
			expErr:    false,
		},
		//"test": {
		//	client: fakeclient.NewClientBuilder().WithLists(
		//		&cmpolicy.CertificateRequestPolicyList{
		//			Items: []cmpolicy.CertificateRequestPolicy{
		//				cmpolicy.CertificateRequestPolicy{
		//					ObjectMeta: metav1.ObjectMeta{
		//						Name: "test",
		//					},
		//				},
		//			},
		//		},
		//	).
		//	evaluator: expNoEvaluator,
		//	expOK:     true,
		//	expReason: NoCRPExistMessage,
		//	expErr:    false,
		//},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client := test.client.WithScheme(scheme).Build()
			m := &Manager{
				Client:     client,
				evaluators: []registry.EvaluateFunc{test.evaluator(t)},
			}

			ok, reason, err := m.Evaluate(context.TODO(), new(cmapi.CertificateRequest))
			if ok != test.expOK {
				t.Errorf("unexpected ok, exp=%t got=%t",
					test.expOK, ok)
			}
			if reason != test.expReason {
				t.Errorf("unexpected reason, exp=%q got=%q",
					test.expReason, reason)
			}
			if (err != nil) != test.expErr {
				t.Errorf("unexpected err, exp=%t got=%v",
					test.expErr, err)
			}
		})
	}
}
