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

import "sync"

// Cache maintains a cache of compiled validators.
// The current implementation is a simple lazy cache meaning:
//
// 1. Whenever a validator is requested, it first checks the cache.
// 2. If a compiled validator exists for the supplied CEL expression, it is returned.
// 3. If the validator doesn't exist in the cache, a new validator is created, compiled, added to the cache, and returned.
type Cache interface {
	// Get returns a compiled validator for the supplied CEL expression.
	// Any compilation errors will be returned to the caller.
	//
	// The supplied CEL expression must output a bool.
	Get(expr string) (Validator, error)
}

type cache struct {
	m sync.Map
}

type cacheEntry struct {
	validator *validator
	err       error
}

func (c *cache) Get(expr string) (Validator, error) {
	// First check if cache contains validator for expression
	o, ok := c.m.Load(expr)
	if ok {
		ce := o.(*cacheEntry)
		return ce.validator, ce.err
	}

	// Expression did not exist in cache. Create a new validator, compile it
	// and add the result to cache.
	// Theoretically this could lead to the same expression being compiled multiple times,
	// but guarding against that would require locking and increase complexity.
	v := &validator{expression: expr}
	err := v.compile()
	if err != nil {
		v = nil
	}
	o, _ = c.m.LoadOrStore(expr, &cacheEntry{validator: v, err: err})
	ce := o.(*cacheEntry)
	return ce.validator, ce.err
}

// NewCache is a constructor for cache of compiled CEL expression validators.
func NewCache() Cache {
	return &cache{}
}
