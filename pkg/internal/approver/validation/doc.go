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

// Package validation compiles and evaluates CEL expressions used in
// CertificateRequestPolicy validation rules.
//
// # Design
//
// Compiled CEL programs are stored in a [Cache] keyed by
// CertificateRequestPolicy name and expression string. Programs for a given
// policy are discarded when the policy is deleted, bounding memory to the
// number of persisted policies.
//
// This lifecycle-bound approach mirrors how the Kubernetes
// apiextensions-apiserver manages compiled CEL validators for CustomResourceDefinitions:
//
//   - Each CRD version has a [customResourceStrategy] that holds a tree of
//     compiled CEL [Validator] structs (via [cel.NewValidator]), stored as
//     struct fields rather than in a separate cache.
//   - The strategy is [constructed] when a CRD is created or updated, and
//     garbage-collected when the CRD is deleted.
//   - The number of compiled programs is therefore naturally bounded by the
//     number of CRDs in the cluster.
//
// approver-policy differs in that CEL expressions are opaque string values
// inside CertificateRequestPolicy custom resources, not part of a CRD schema.
// The controller compiles them lazily on first encounter rather than eagerly
// at CRP create/update time. However, the lifecycle-bound storage principle
// is the same: compiled programs are owned by their CRP and cleaned up on
// deletion.
//
// The lifecycle cache is populated only while evaluating CertificateRequests
// against a persisted policy, keyed by (policy name, expression). The admission
// webhook instead uses [Cache.Compile], which checks that an expression
// compiles without storing it, so requests that are never persisted — dry-run
// or subsequently-rejected CREATEs — cannot leave behind entries that no delete
// event would ever clean up. This closes the unbounded-growth vector that
// motivated the design. See CWE-770.
//
// Eviction (on CRP update via the webhook, on CRP delete via the controller)
// is best-effort: because the expression string is part of the cache key, a
// stale entry can never be returned for the wrong input, so correctness never
// depends on eviction. In a multi-replica deployment each admission request is
// served by a single replica and the delete reconciler runs only on the
// elected leader, so a deleted or updated policy's old entries may linger on
// other replicas until the process restarts. Steady-state memory is therefore
// bounded by the live policies plus a bounded tail of not-yet-evicted entries,
// rather than growing without limit as the previous global cache did.
//
// [customResourceStrategy]: https://github.com/kubernetes/kubernetes/blob/9e570c412469/staging/src/k8s.io/apiextensions-apiserver/pkg/registry/customresource/strategy.go#L63
// [Validator]: https://github.com/kubernetes/kubernetes/blob/9e570c412469/staging/src/k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel/validation.go#L84
// [cel.NewValidator]: https://github.com/kubernetes/kubernetes/blob/9e570c412469/staging/src/k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel/validation.go#L108
// [constructed]: https://github.com/kubernetes/kubernetes/blob/9e570c412469/staging/src/k8s.io/apiextensions-apiserver/pkg/apiserver/customresource_handler.go#L835
package validation
