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

package policy

import (
	"context"
	"testing"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	cmpolicy "github.com/cert-manager/policy-approver/api/v1alpha1"
)

func TestEvaluate(t *testing.T) {
	expNoEvaluator := func(t *testing.T) evaluatorFn {
		return func(el *field.ErrorList, policy *cmpolicy.CertificateRequestPolicy, cr *cmapi.CertificateRequest) error {
			t.Fatal("unexpected evaluator call")
			return nil
		}
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cmpolicy.AddToScheme(scheme))

	tests := map[string]struct {
		client    *fakeclient.ClientBuilder
		evaluator func(t *testing.T) evaluatorFn

		expOK     bool
		expReason string
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
			expReason: MissingBindingMessage,
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
			p := &Policy{
				Client:    client,
				evaluator: test.evaluator(t),
			}

			ok, reason, err := p.Evaluate(context.TODO(), new(cmapi.CertificateRequest))
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
