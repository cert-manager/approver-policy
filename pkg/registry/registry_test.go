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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/approver/fake"
)

func TestRegistry_Store(t *testing.T) {
	tests := map[string]struct {
		preStored    []approver.Interface
		approvers    []approver.Interface
		expectLen    int
		expectPanic  bool
		panicMessage string
	}{
		"storing a single approver should succeed": {
			approvers: []approver.Interface{newFakeApprover("test-1")},
			expectLen: 1,
		},
		"storing multiple approvers should succeed": {
			approvers: []approver.Interface{
				newFakeApprover("test-1"),
				newFakeApprover("test-2"),
				newFakeApprover("test-3"),
			},
			expectLen: 3,
		},
		"storing approvers with duplicate names should panic": {
			preStored:    []approver.Interface{newFakeApprover("duplicate")},
			approvers:    []approver.Interface{newFakeApprover("duplicate")},
			expectPanic:  true,
			panicMessage: "approver already registered with same name: duplicate",
		},
		"storing duplicate names in a single call should panic": {
			approvers: []approver.Interface{
				newFakeApprover("same-name"),
				newFakeApprover("same-name"),
			},
			expectPanic:  true,
			panicMessage: "approver already registered with same name: same-name",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			r := &Registry{}

			for _, a := range test.preStored {
				r.Store(a)
			}

			if test.expectPanic {
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
	result := r.Store(newFakeApprover("a"))
	assert.Equal(t, r, result, "Store should return the registry for chaining")
}

func TestRegistry_Approvers(t *testing.T) {
	r := &Registry{}
	a1 := newFakeApprover("approver-1")
	a2 := newFakeApprover("approver-2")
	r.Store(a1, a2)

	result := r.Approvers()
	assert.Equal(t, 2, len(result))
	assert.Equal(t, "approver-1", result[0].Name())
	assert.Equal(t, "approver-2", result[1].Name())
}

func TestRegistry_Evaluators(t *testing.T) {
	r := &Registry{}
	r.Store(newFakeApprover("eval-1"), newFakeApprover("eval-2"))

	evaluators := r.Evaluators()
	assert.Equal(t, 2, len(evaluators))
}

func TestRegistry_Webhooks(t *testing.T) {
	r := &Registry{}
	r.Store(newFakeApprover("wh-1"), newFakeApprover("wh-2"))

	webhooks := r.Webhooks()
	assert.Equal(t, 2, len(webhooks))
}

func TestRegistry_Reconcilers(t *testing.T) {
	r := &Registry{}
	r.Store(newFakeApprover("rec-1"), newFakeApprover("rec-2"))

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
	r.Store(newFakeApprover("first"))
	assert.Equal(t, 1, len(r.Approvers()))

	r.Store(newFakeApprover("second"))
	assert.Equal(t, 2, len(r.Approvers()))
	assert.Equal(t, 2, len(r.Reconcilers()))
}

func newFakeApprover(name string) approver.Interface {
	return fake.NewFakeApprover().WithReconciler(fake.NewFakeReconciler().WithName(name))
}
