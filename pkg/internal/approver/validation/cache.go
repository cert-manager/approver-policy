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
	"sync"
)

// Cache maintains compiled CEL validators keyed by CertificateRequestPolicy
// name and expression string, analogous to how the Kubernetes
// apiextensions-apiserver ties compiled validators to the CRD
// customResourceStrategy (see package doc for details and upstream links).
//
// Compiled programs are tied to the CRP lifecycle: populated on demand during
// evaluation via [Cache.Get] and discarded via [Cache.Remove] when the CRP is
// updated or deleted. Eviction is best-effort: because the expression string
// is part of the cache key, a stale entry can never be returned for the wrong
// input, so correctness never depends on it — Remove only bounds memory.
//
// CertificateRequestPolicy is cluster-scoped so the name is globally unique.
type Cache interface {
	// Get returns a compiled validator for the given CEL expression, cached
	// for the lifetime of the named CertificateRequestPolicy. policyName must
	// be non-empty; callers that only need to check whether an expression
	// compiles, without retaining it, should use [Cache.Compile] instead.
	Get(policyName string, expr string) (Validator, error)

	// Compile compiles the CEL expression and returns the validator without
	// caching it. It is used for admission-time validity checks, where the
	// result is transient and must not grow the lifecycle cache — for example
	// dry-run or rejected CREATE requests, which are never persisted and so
	// would otherwise leak entries that no delete event ever cleans up.
	Compile(expr string) (Validator, error)

	// Remove discards all compiled validators for the named
	// CertificateRequestPolicy. It is best-effort memory cleanup (see the type
	// documentation); correctness does not depend on it.
	Remove(policyName string)
}

type cache struct {
	m sync.Map // string (CRP name) -> *crpEntry
}

type crpEntry struct {
	mu         sync.Mutex
	validators map[string]*cacheEntry
}

type cacheEntry struct {
	validator *validator
	err       error
}

func (c *cache) Compile(expr string) (Validator, error) {
	v := &validator{expression: expr}
	if err := v.compile(); err != nil {
		return nil, err
	}
	return v, nil
}

func (c *cache) Get(policyName string, expr string) (Validator, error) {
	// Load before LoadOrStore so the common cache-hit path does not allocate a
	// throwaway crpEntry (and its map) on every call.
	entry, ok := c.m.Load(policyName)
	if !ok {
		entry, _ = c.m.LoadOrStore(policyName, &crpEntry{
			validators: make(map[string]*cacheEntry),
		})
	}
	ce := entry.(*crpEntry)

	ce.mu.Lock()
	defer ce.mu.Unlock()

	if cached, ok := ce.validators[expr]; ok {
		return cached.validator, cached.err
	}

	v := &validator{expression: expr}
	err := v.compile()
	if err != nil {
		v = nil
	}
	ce.validators[expr] = &cacheEntry{validator: v, err: err}
	return v, err
}

func (c *cache) Remove(policyName string) {
	c.m.Delete(policyName)
}

// NewCache is a constructor for cache of compiled CEL expression validators.
func NewCache() Cache {
	return &cache{}
}
