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

	"github.com/spf13/pflag"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/cert-manager/approver-policy/pkg/approver"
)

var _ approver.Interface = &FakeApprover{}

// FakeApprover is a testing approver designed to mock approvers with a
// pre-determined response.
type FakeApprover struct {
	registerFlagsFn func(*pflag.FlagSet)
	prepareFn       func(context.Context, manager.Manager) error
	*FakeEvaluator
	*FakeWebhook
	*FakeReconciler
}

func NewFakeApprover() *FakeApprover {
	return &FakeApprover{
		FakeEvaluator:  NewFakeEvaluator(),
		FakeWebhook:    NewFakeWebhook(),
		FakeReconciler: NewFakeReconciler(),
	}
}

func (f *FakeApprover) WithEvaluator(evaluator *FakeEvaluator) *FakeApprover {
	f.FakeEvaluator = evaluator
	return f
}

func (f *FakeApprover) WithReconciler(reconciler *FakeReconciler) *FakeApprover {
	f.FakeReconciler = reconciler
	return f
}

func (f *FakeApprover) WithRegisterFlags(fn func(*pflag.FlagSet)) *FakeApprover {
	f.registerFlagsFn = fn
	return f
}

func (f *FakeApprover) WithPrepare(fn func(context.Context, manager.Manager) error) *FakeApprover {
	f.prepareFn = fn
	return f
}

func (f *FakeApprover) RegisterFlags(pf *pflag.FlagSet) {
	f.registerFlagsFn(pf)
}

func (f *FakeApprover) Prepare(ctx context.Context, mgr manager.Manager) error {
	return f.prepareFn(ctx, mgr)
}
