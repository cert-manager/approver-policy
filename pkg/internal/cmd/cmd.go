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

package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"

	policyapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/pkg/internal/cmd/options"
	"github.com/cert-manager/policy-approver/pkg/internal/controllers"
	"github.com/cert-manager/policy-approver/pkg/internal/webhook"
	"github.com/cert-manager/policy-approver/pkg/registry"
)

const (
	helpOutput = "A cert-manager CertificateRequest approver that bases decisions on CertificateRequestPolicies"
)

// NewCommand returns an new command instance of policy-approver.
func NewCommand(ctx context.Context) *cobra.Command {
	opts := new(options.Options)

	cmd := &cobra.Command{
		Use:   "policy-approver",
		Short: helpOutput,
		Long:  helpOutput,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Complete()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			log := opts.Logr.WithName("main")

			mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
				Scheme:                        policyapi.GlobalScheme,
				LeaderElectionNamespace:       opts.LeaderElectionNamespace,
				LeaderElection:                true,
				LeaderElectionID:              "policy.cert-manager.io",
				LeaderElectionReleaseOnCancel: true,
				ReadinessEndpointName:         "/readyz",
				HealthProbeBindAddress:        opts.ReadyzAddress,
				MetricsBindAddress:            opts.MetricsAddress,
				Logger:                        opts.Logr.WithName("controller"),
			})
			if err != nil {
				return fmt.Errorf("unable to create controller manager: %w", err)
			}

			for _, approver := range registry.Shared.Approvers() {
				log.Info("preparing approver", "approver", approver.Name())
				if err := approver.Prepare(ctx, mgr); err != nil {
					return fmt.Errorf("failed to prepare approver %q: %w", approver.Name(), err)
				}
			}

			if err := controllers.AddControllers(ctx, controllers.Options{
				Log:        opts.Logr.WithName("controller"),
				Manager:    mgr,
				Evaluators: registry.Shared.Evaluators(),
			}); err != nil {
				return fmt.Errorf("failed to add controllers: %w", err)
			}

			webhook.Register(mgr, webhook.Options{
				Log:      opts.Logr,
				Webhooks: registry.Shared.Webhooks(),
			})

			log.Info("starting policy-approver...")
			return mgr.Start(ctx)
		},
	}

	opts.Prepare(cmd, registry.Shared.Approvers()...)

	return cmd
}
