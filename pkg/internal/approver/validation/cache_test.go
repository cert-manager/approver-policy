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

func Test_Cache_Get(t *testing.T) {
	c := NewCache()

	type args struct {
		expr string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "valid-expression", args: args{expr: "self.endsWith(cr.namespace + '.svc')"}},
		{name: "invalid-expression", args: args{expr: "foo"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.Get(tt.args.expr)

			if tt.wantErr {
				assert.Error(t, err)
				// Cache should return same error for same expression
				_, sameErr := c.Get(tt.args.expr)
				assert.Same(t, err, sameErr)
			} else {
				assert.NoError(t, err)
				// Cache should return same validator for same expression
				same, _ := c.Get(tt.args.expr)
				assert.Same(t, got, same)
			}
		})
	}
}

// Test_Cache_Get_Evicts verifies that the cache is bounded: once more than
// `size` distinct expressions have been compiled, the least-recently-used entry
// is evicted, so a later Get for it compiles a fresh validator. This is the
// mechanism that bounds memory under adversarial input (CWE-770).
func Test_Cache_Get_Evicts(t *testing.T) {
	c := newCache(2)

	a1, err := c.Get("self == 'a'")
	assert.NoError(t, err)
	_, err = c.Get("self == 'b'")
	assert.NoError(t, err)

	// Compiling a third expression overflows the size-2 cache and evicts the
	// least-recently-used entry, "self == 'a'".
	_, err = c.Get("self == 'c'")
	assert.NoError(t, err)

	a2, err := c.Get("self == 'a'")
	assert.NoError(t, err)
	assert.NotSame(t, a1, a2, "evicted expression must be recompiled, not served from cache")
}

// Test_Cache_Get_KeepsRecentlyUsed verifies the eviction order is by recency:
// touching an entry via Get protects it from eviction, while a colder entry is
// evicted instead.
func Test_Cache_Get_KeepsRecentlyUsed(t *testing.T) {
	c := newCache(2)

	a1, err := c.Get("self == 'a'")
	assert.NoError(t, err)
	b1, err := c.Get("self == 'b'")
	assert.NoError(t, err)

	// Touch "self == 'a'" so it becomes the most-recently-used; "self == 'b'"
	// is now the eviction candidate.
	a2, err := c.Get("self == 'a'")
	assert.NoError(t, err)
	assert.Same(t, a1, a2, "recently-used entry must remain cached")

	// Overflow the cache: "self == 'b'" should be evicted, "self == 'a'" kept.
	_, err = c.Get("self == 'c'")
	assert.NoError(t, err)

	a3, err := c.Get("self == 'a'")
	assert.NoError(t, err)
	assert.Same(t, a1, a3, "most-recently-used entry must survive eviction")

	b2, err := c.Get("self == 'b'")
	assert.NoError(t, err)
	assert.NotSame(t, b1, b2, "least-recently-used entry must be evicted")
}
