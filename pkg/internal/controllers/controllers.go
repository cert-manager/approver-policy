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

package controllers

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/cert-manager/policy-approver/pkg/approver"
)

// Options hold options for the internal policy-approver controllers.
type Options struct {
	// Log is the shared logger used by controllers.
	Log logr.Logger

	// Manager is the controller-runtime manager that controllers will be added
	// to.
	Manager manager.Manager

	// Evaluators is the list of registered Approver Evaluators that  will be
	// used to build the approver manager.
	Evaluators []approver.Evaluator

	// Reconcilers is the list of registered Approver Reconcilers that  will be
	// used to manager CertificateRequestPolicy Ready conditions.
	Reconcilers []approver.Reconciler
}

// AddControllers adds all internal controllers.
func AddControllers(ctx context.Context, opts Options) error {
	if err := addCertificateRequestController(ctx, opts); err != nil {
		return fmt.Errorf("failed to add certificaterequest controller: %w", err)
	}

	if err := addCertificateRequestPolicyController(ctx, opts); err != nil {
		return fmt.Errorf("failed to add certificaterequestpolicy controller: %w", err)
	}

	return nil
}
