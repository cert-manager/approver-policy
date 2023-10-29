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

package constraints

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/spf13/pflag"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/registry"
)

// Load the constraints approver.
func init() {
	registry.Shared.Store(Approver())
}

// Approver returns an instance on the constraints approver.
func Approver() approver.Interface {
	return constraints{}
}

// constraints is a base approver-policy Approver that is responsible for
// ensuring incoming requests satisfy the constraints defined on
// CertificateRequestPolicies. It is expected that constraints must _always_ be
// registered for all approver-policy builds.
type constraints struct{}

// Name of Approver is "constraints"
func (c constraints) Name() string {
	return "constraints"
}

// RegisterFlags is a no-op, constraints doesn't need any flags.
func (c constraints) RegisterFlags(_ *pflag.FlagSet) {
	return
}

// Prepare is a no-op, constraints doesn't need to prepare anything.
func (c constraints) Prepare(_ context.Context, _ logr.Logger, _ manager.Manager) error {
	return nil
}

// Ready always returns ready, constraints doesn't have any dependencies to
// block readiness.
func (c constraints) Ready(_ context.Context, _ *policyapi.CertificateRequestPolicy) (approver.ReconcilerReadyResponse, error) {
	return approver.ReconcilerReadyResponse{Ready: true}, nil
}

// constraints never needs to manually enqueue policies.
func (c constraints) EnqueueChan() <-chan string {
	return nil
}
