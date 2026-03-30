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

package registry

import (
	"context"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
)

// fakeApprover is a minimal implementation of approver.Interface for testing.
type fakeApprover struct {
	name string
}

func (f *fakeApprover) Name() string { return f.name }
func (f *fakeApprover) RegisterFlags(_ *pflag.FlagSet) {}
func (f *fakeApprover) Prepare(_ context.Context, _ logr.Logger, _ manager.Manager) error {
	return nil
}
func (f *fakeApprover) Evaluate(_ context.Context, _ *policyapi.CertificateRequestPolicy, _ *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
	return approver.EvaluationResponse{}, nil
}
func (f *fakeApprover) Validate(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
	return approver.WebhookValidationResponse{Allowed: true, Errors: field.ErrorList{}}, nil
}
func (f *fakeApprover) Ready(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
	return approver.ReconcilerReadyResponse{Ready: true}, nil
}
func (f *fakeApprover) EnqueueChan() <-chan string { return nil }

func TestRegistry_Store(t *testing.T) {
	tests := map[string]struct {
		approvers    []approver.Interface
		expectLen    int
		expectPanic  bool
		panicMessage string
	}{
		"storing a single approver should succeed": {
			approvers: []approver.Interface{&fakeApprover{name: "test-1"}},
			expectLen: 1,
		},
		"storing multiple approvers should succeed": {
			approvers: []approver.Interface{
				&fakeApprover{name: "test-1"},
				&fakeApprover{name: "test-2"},
				&fakeApprover{name: "test-3"},
			},
			expectLen: 3,
		},
		"storing approvers with duplicate names should panic": {
			approvers:    []approver.Interface{&fakeApprover{name: "duplicate"}},
			expectPanic:  true,
			panicMessage: "approver already registered with same name: duplicate",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r := &Registry{}

			if test.expectPanic {
				// Pre-store an approver with the same name to trigger the panic.
				r.Store(&fakeApprover{name: "duplicate"})
				assert.PanicsWithValue(t, test.panicMessage, func() {
					r.Store(test.approvers...)
				})
				return
			}

			r.Store(test.approvers...)
			assert.Equal(t, test.expectLen, len(r.Approvers()))
		})
	}
}

func TestRegistry_Store_Chaining(t *testing.T) {
	r := &Registry{}
	result := r.Store(&fakeApprover{name: "a"})
	assert.Equal(t, r, result, "Store should return the registry for chaining")
}

func TestRegistry_Approvers(t *testing.T) {
	r := &Registry{}
	a1 := &fakeApprover{name: "approver-1"}
	a2 := &fakeApprover{name: "approver-2"}
	r.Store(a1, a2)

	result := r.Approvers()
	assert.Equal(t, 2, len(result))
	assert.Equal(t, "approver-1", result[0].Name())
	assert.Equal(t, "approver-2", result[1].Name())
}

func TestRegistry_Evaluators(t *testing.T) {
	r := &Registry{}
	r.Store(&fakeApprover{name: "eval-1"}, &fakeApprover{name: "eval-2"})

	evaluators := r.Evaluators()
	assert.Equal(t, 2, len(evaluators))
}

func TestRegistry_Webhooks(t *testing.T) {
	r := &Registry{}
	r.Store(&fakeApprover{name: "wh-1"}, &fakeApprover{name: "wh-2"})

	webhooks := r.Webhooks()
	assert.Equal(t, 2, len(webhooks))
}

func TestRegistry_Reconcilers(t *testing.T) {
	r := &Registry{}
	r.Store(&fakeApprover{name: "rec-1"}, &fakeApprover{name: "rec-2"})

	reconcilers := r.Reconcilers()
	assert.Equal(t, 2, len(reconcilers))
}

func TestRegistry_EmptyRegistry(t *testing.T) {
	r := &Registry{}

	assert.Empty(t, r.Approvers())
	assert.Empty(t, r.Evaluators())
	assert.Empty(t, r.Webhooks())
	assert.Empty(t, r.Reconcilers())
}

func TestRegistry_Store_IncrementalAdd(t *testing.T) {
	r := &Registry{}
	r.Store(&fakeApprover{name: "first"})
	assert.Equal(t, 1, len(r.Approvers()))

	r.Store(&fakeApprover{name: "second"})
	assert.Equal(t, 2, len(r.Approvers()))

	result := r.Reconcilers()
	assert.Equal(t, 2, len(result))
	assert.Equal(t, ctrl.Result{}, approver.ReconcilerReadyResponse{Ready: true}.Result)
}
