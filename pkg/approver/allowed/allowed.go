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

package allowed

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/spf13/pflag"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/registry"
)

// Load the allowed approver.
func init() {
	registry.Shared.Store(Allowed{})
}

// Allowed is a base approver-policy Approver that is responsible for ensuring
// incoming requests may only request all or some of the X.509 attributes that
// are allowed by the policy. Requests which do not request all of the
// attributes which they are allowed to in the policy are permitted. It is
// expected that allowed must _always_ be registered for all
// approver-policy builds.
type Allowed struct{}

// Name of Approver is "allowed"
func (a Allowed) Name() string {
	return "allowed"
}

// RegisterFlags is a no-op, Allowed doesn't need any flags.
func (a Allowed) RegisterFlags(_ *pflag.FlagSet) {
	return
}

// Prepare is a no-op, Allowed doesn't need to prepare anything.
func (a Allowed) Prepare(_ context.Context, _ logr.Logger, _ manager.Manager) error {
	return nil
}

// Ready always returns ready, Allowed doesn't have any dependencies to
// block readiness.
func (a Allowed) Ready(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
	return approver.ReconcilerReadyResponse{Ready: true}, nil
}

// Allowed never needs to manually enqueue policies.
func (a Allowed) EnqueueChan() <-chan string {
	return nil
}
