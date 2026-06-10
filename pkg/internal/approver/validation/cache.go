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

import "k8s.io/utils/lru"

// DefaultCacheSize is the maximum number of compiled CEL validators held by a
// Cache before the least-recently-used entry is evicted.
//
// CertificateRequestPolicy resources are admin-managed and low-churn, so the
// number of distinct expressions in any real cluster is small; this bound
// exists only to cap memory under adversarial input (CWE-770), where a
// principal able to author policies — including via dry-run requests that are
// never persisted — could otherwise submit unbounded unique expressions.
const DefaultCacheSize = 1024

// Cache maintains a bounded, lazily-populated cache of compiled validators.
// The implementation is a simple LRU cache meaning:
//
//  1. Whenever a validator is requested, it first checks the cache.
//  2. If a compiled validator exists for the supplied CEL expression, it is returned.
//  3. Otherwise a new validator is created, compiled, added to the cache, and returned.
//
// The cache holds at most [DefaultCacheSize] entries; the least-recently-used
// entry is evicted when that limit is exceeded. Bounding the size — rather than
// tying entries to policy lifecycle — keeps the cache a self-contained concern:
// it needs no knowledge of CertificateRequestPolicy creation, update or
// deletion, and an entry for a deleted or rewritten policy simply ages out.
type Cache interface {
	// Get returns a compiled validator for the supplied CEL expression.
	// Any compilation errors will be returned to the caller.
	//
	// The supplied CEL expression must output a bool.
	Get(expr string) (Validator, error)
}

type cache struct {
	// lru is safe for concurrent use; it guards its own state with a mutex.
	lru *lru.Cache
}

type cacheEntry struct {
	validator *validator
	err       error
}

func (c *cache) Get(expr string) (Validator, error) {
	// First check if cache contains a validator for the expression.
	if o, ok := c.lru.Get(expr); ok {
		ce := o.(*cacheEntry)
		return ce.validator, ce.err
	}

	// Expression did not exist in cache. Create a new validator, compile it
	// and add the result to the cache (including a compilation error, so
	// invalid expressions are not recompiled on every request).
	// Theoretically this could lead to the same expression being compiled
	// multiple times, but guarding against that would require locking and
	// increase complexity.
	v := &validator{expression: expr}
	err := v.compile()
	if err != nil {
		v = nil
	}
	c.lru.Add(expr, &cacheEntry{validator: v, err: err})
	return v, err
}

// NewCache is a constructor for a bounded cache of compiled CEL expression
// validators, holding at most [DefaultCacheSize] entries.
func NewCache() Cache {
	return newCache(DefaultCacheSize)
}

// newCache constructs a cache bounded to size entries. Exposed separately from
// NewCache so tests can exercise eviction without compiling DefaultCacheSize
// expressions.
func newCache(size int) *cache {
	return &cache{lru: lru.New(size)}
}
