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

package webhook

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/registry"
)

// Options are options for running the wehook.
type Options struct {
	// Log is a shared logger for the shared webhook.
	Log logr.Logger

	// Webhooks is the list of registered Webhooks that will be used to build the
	// shared webhook server.
	Webhooks []approver.Webhook

	// Manager is the shared controller-runtime manager used by this
	// approver-policy instance. The webhook will register its endpoints and
	// runnables against.
	Manager manager.Manager
}

// Register the approver-policy Webhook endpoints against the
// controller-manager Manager.
func Register(ctx context.Context, opts Options) error {
	log := opts.Log.WithName("webhook")

	var registerdPlugins []string
	for _, approver := range registry.Shared.Approvers() {
		if name := approver.Name(); name != "allowed" && name != "constraints" {
			registerdPlugins = append(registerdPlugins, name)
		}
	}

	log.Info("registering webhook endpoints")
	validator := &validator{
		log:               log.WithName("validation"),
		lister:            opts.Manager.GetCache(),
		webhooks:          opts.Webhooks,
		registeredPlugins: registerdPlugins,
	}

	err := builder.WebhookManagedBy(opts.Manager).
		For(&policyapi.CertificateRequestPolicy{}).
		WithValidator(validator).
		Complete()
	if err != nil {
		return fmt.Errorf("error registering webhook: %v", err)
	}

	if err := opts.Manager.AddReadyzCheck("validator", opts.Manager.GetWebhookServer().StartedChecker()); err != nil {
		return fmt.Errorf("error adding readyz check: %v", err)
	}

	return nil
}
