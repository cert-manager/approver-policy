/*
Copyright 2023 The cert-manager Authors.

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

package validation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_Cache_Get verifies that valid expressions are compiled and cached (same
// pointer on repeated Get), and that invalid expressions return a cached error.
func Test_Cache_Get(t *testing.T) {
	c := NewCache()

	type args struct {
		policyName string
		expr       string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "valid-expression", args: args{policyName: "policy-1", expr: "self.endsWith(cr.namespace + '.svc')"}},
		{name: "invalid-expression", args: args{policyName: "policy-1", expr: "foo"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.Get(tt.args.policyName, tt.args.expr)

			if tt.wantErr {
				assert.Error(t, err)
				_, sameErr := c.Get(tt.args.policyName, tt.args.expr)
				assert.Same(t, err, sameErr)
			} else {
				assert.NoError(t, err)
				same, _ := c.Get(tt.args.policyName, tt.args.expr)
				assert.Same(t, got, same)
			}
		})
	}
}

// Test_Cache_Compile verifies that Compile returns a validator (or error)
// without caching: repeated calls for the same expression return distinct
// validators, and a compile error is returned directly rather than stored.
// This is the admission-time path that must not grow the lifecycle cache for
// dry-run or rejected requests.
func Test_Cache_Compile(t *testing.T) {
	c := NewCache()

	v1, err := c.Compile("self == 'test'")
	assert.NoError(t, err)
	assert.NotNil(t, v1)

	v2, err := c.Compile("self == 'test'")
	assert.NoError(t, err)
	assert.NotNil(t, v2)

	assert.NotSame(t, v1, v2, "Compile must not cache: each call returns a fresh validator")

	v, err := c.Compile("foo")
	assert.Error(t, err)
	assert.Nil(t, v, "Compile must return a nil validator on compilation error")
}

// Test_Cache_Compile_DoesNotPopulate verifies that Compile does not leave an
// entry that a later Get would return, so admission-time validity checks never
// populate the lifecycle cache.
func Test_Cache_Compile_DoesNotPopulate(t *testing.T) {
	c := NewCache()

	compiled, err := c.Compile("self == 'x'")
	assert.NoError(t, err)

	got, err := c.Get("policy-1", "self == 'x'")
	assert.NoError(t, err)

	assert.NotSame(t, compiled, got, "Get after Compile must compile a fresh, cached validator")
}

// Test_Cache_Get_IsolatedByOwner verifies that the same expression compiled
// under different CRP owners produces separate cache entries, so that removing
// one owner's validators does not affect another's.
func Test_Cache_Get_IsolatedByOwner(t *testing.T) {
	c := NewCache()

	v1, err := c.Get("policy-a", "self == 'x'")
	assert.NoError(t, err)

	v2, err := c.Get("policy-b", "self == 'x'")
	assert.NoError(t, err)

	assert.NotSame(t, v1, v2, "same expression under different owners must produce separate entries")
}

// Test_Cache_Remove verifies that Remove discards all cached validators for
// an owner, so that a subsequent Get compiles a fresh validator rather than
// returning the stale one. This is the mechanism used on CRP deletion.
func Test_Cache_Remove(t *testing.T) {
	c := NewCache()

	v1, err := c.Get("policy-1", "self == 'x'")
	assert.NoError(t, err)

	c.Remove("policy-1")

	v2, err := c.Get("policy-1", "self == 'x'")
	assert.NoError(t, err)

	assert.NotSame(t, v1, v2, "after Remove, a fresh validator must be compiled")
}

// Test_Cache_Remove_OnlyAffectsTarget verifies that removing one owner's
// validators leaves other owners' cached validators intact.
func Test_Cache_Remove_OnlyAffectsTarget(t *testing.T) {
	c := NewCache()

	vA, err := c.Get("policy-a", "self == 'x'")
	assert.NoError(t, err)

	_, err = c.Get("policy-b", "self == 'y'")
	assert.NoError(t, err)

	c.Remove("policy-b")

	vA2, err := c.Get("policy-a", "self == 'x'")
	assert.NoError(t, err)

	assert.Same(t, vA, vA2, "Remove must not affect other owners")
}

// Test_Cache_Remove_ThenRepopulate simulates a CRP update: the webhook clears
// the cache via Remove and recompiles only the current expressions. After
// Remove, a subsequent Get for the same expression must return a new validator
// (not the previously cached one), confirming the old entry was discarded.
func Test_Cache_Remove_ThenRepopulate(t *testing.T) {
	c := NewCache()

	// Populate the cache with two expressions, as if the original CRP had both.
	v1a, err := c.Get("policy-1", "self == 'a'")
	assert.NoError(t, err)
	// Expression 'b' represents a rule that will be removed in the updated CRP.
	_, err = c.Get("policy-1", "self == 'b'")
	assert.NoError(t, err)

	// Simulate CRP update: webhook calls Remove before recompiling.
	c.Remove("policy-1")

	// Re-populate with only expression 'a', as if the updated CRP dropped 'b'.
	v1aNew, err := c.Get("policy-1", "self == 'a'")
	assert.NoError(t, err)

	// NotSame asserts the two values have different pointer addresses,
	// proving a fresh validator was compiled rather than returning the old one.
	assert.NotSame(t, v1a, v1aNew, "after Remove+re-Get, validator must be freshly compiled")
}
