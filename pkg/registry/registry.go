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
	"sync"

	"github.com/cert-manager/approver-policy/pkg/approver"
)

var (
	// Shared is a registry of approvers. This is intended as a global
	// shared registry.
	Shared = &Registry{}
)

// Registry is a store of Approvers. Consumers can store approvers, and load
// all registered approvers. Approvers must be uniquely named.
type Registry struct {
	lock      sync.RWMutex
	approvers []approver.Interface
}

// Store will store an Approver into the shared approver registry.
func (r *Registry) Store(approvers ...approver.Interface) *Registry {
	r.lock.Lock()
	defer r.lock.Unlock()
	for _, existing := range r.approvers {
		for _, toStore := range approvers {
			if existing.Name() == toStore.Name() {
				panic("approver already registered with same name: " + toStore.Name())
			}
		}
	}
	r.approvers = append(r.approvers, approvers...)
	return r
}

// Approvers returns the list of Approvers that have been registered to the
// shared registry.
func (r *Registry) Approvers() []approver.Interface {
	r.lock.RLock()
	defer r.lock.RUnlock()
	return r.approvers
}

// Evaluators returns the list of Evaluators that have been registered as
// Approvers to the registry.
func (r *Registry) Evaluators() []approver.Evaluator {
	r.lock.RLock()
	defer r.lock.RUnlock()
	var evaluators []approver.Evaluator
	for _, approver := range r.approvers {
		evaluators = append(evaluators, approver)
	}
	return evaluators
}

// Webhooks returns the list of Webhooks that have been registered as Approvers
// to the registry.
func (r *Registry) Webhooks() []approver.Webhook {
	r.lock.RLock()
	defer r.lock.RUnlock()
	var webhooks []approver.Webhook
	for _, approver := range r.approvers {
		webhooks = append(webhooks, approver)
	}
	return webhooks
}

// Reconcilers returns the list of Reconcilers that have been registered as
// Approvers to the registry.
func (r *Registry) Reconcilers() []approver.Reconciler {
	r.lock.RLock()
	defer r.lock.RUnlock()
	var reconcilers []approver.Reconciler
	for _, reconciler := range r.approvers {
		reconcilers = append(reconcilers, reconciler)
	}
	return reconcilers
}
