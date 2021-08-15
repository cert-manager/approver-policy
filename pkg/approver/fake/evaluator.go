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

package fake

import (
	"context"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"

	cmpapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/pkg/approver"
)

var _ approver.Evaluator = &FakeEvaluator{}

// FakeEvaluator is a testing evaluator designed to mock evaluators with a
// determined response.
type FakeEvaluator struct {
	evaluateFunc func(context.Context, *cmpapi.CertificateRequestPolicy, *cmapi.CertificateRequest) (bool, string, error)
}

func NewFakeEvaluator() *FakeEvaluator {
	return new(FakeEvaluator)
}

func (f *FakeEvaluator) WithEvaluate(fn func(context.Context, *cmpapi.CertificateRequestPolicy, *cmapi.CertificateRequest) (bool, string, error)) *FakeEvaluator {
	f.evaluateFunc = fn
	return f
}

func (f *FakeEvaluator) Evaluate(ctx context.Context, crp *cmpapi.CertificateRequestPolicy, cr *cmapi.CertificateRequest) (bool, string, error) {
	return f.evaluateFunc(ctx, crp, cr)
}
