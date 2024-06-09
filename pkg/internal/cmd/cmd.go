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
	"crypto/tls"
	"fmt"
	"time"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
	servertls "github.com/cert-manager/cert-manager/pkg/server/tls"
	"github.com/cert-manager/cert-manager/pkg/server/tls/authority"
	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/internal/cmd/options"
	"github.com/cert-manager/approver-policy/pkg/internal/controllers"
	"github.com/cert-manager/approver-policy/pkg/internal/metrics"
	"github.com/cert-manager/approver-policy/pkg/internal/webhook"
	"github.com/cert-manager/approver-policy/pkg/registry"
)

const (
	helpOutput = "A cert-manager CertificateRequest approver that bases decisions on CertificateRequestPolicies"
)

// NewCommand returns an new command instance of approver-policy.
func NewCommand(ctx context.Context) *cobra.Command {
	opts := new(options.Options)

	cmd := &cobra.Command{
		Use:   "approver-policy",
		Short: helpOutput,
		Long:  helpOutput,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Complete()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			logf.Log = opts.Logr.WithName("apiutil")
			log := opts.Logr.WithName("main")

			mlog := opts.Logr.WithName("controller-manager")

			ctrl.SetLogger(mlog)

			certificateSource := &servertls.DynamicSource{
				DNSNames: []string{fmt.Sprintf("%s.%s.svc", opts.Webhook.ServiceName, opts.Webhook.CASecretNamespace)},
				Authority: &authority.DynamicAuthority{
					SecretNamespace: opts.Webhook.CASecretNamespace,
					SecretName:      "cert-manager-approver-policy-tls",
					RESTConfig:      opts.RestConfig,
					CADuration:      time.Hour * 24,
					LeafDuration:    time.Hour,
				},
			}

			mgr, err := ctrl.NewManager(opts.RestConfig, ctrl.Options{
				Scheme:                        policyapi.GlobalScheme,
				LeaderElection:                true,
				LeaderElectionID:              "policy.cert-manager.io",
				LeaderElectionReleaseOnCancel: true,
				LeaderElectionResourceLock:    "leases",
				LeaderElectionNamespace:       opts.LeaderElectionNamespace,
				ReadinessEndpointName:         "/readyz",
				HealthProbeBindAddress:        opts.ReadyzAddress,
				Metrics: server.Options{
					BindAddress: opts.MetricsAddress,
				},
				WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
					Port: opts.Webhook.Port,
					Host: opts.Webhook.Host,
					TLSOpts: []func(*tls.Config){
						func(cfg *tls.Config) {
							cfg.GetCertificate = certificateSource.GetCertificate
						},
					},
				}),
				Logger: mlog,
			})
			if err != nil {
				return fmt.Errorf("unable to create controller manager: %w", err)
			}

			if err := mgr.Add(certificateSource); err != nil {
				return err
			}

			metrics.RegisterMetrics(ctx, opts.Logr.WithName("metrics"), mgr.GetCache())

			if err := webhook.Register(ctx, webhook.Options{
				Log:      opts.Logr,
				Webhooks: registry.Shared.Webhooks(),
				Manager:  mgr,
			}); err != nil {
				return fmt.Errorf("failed to register webhook: %w", err)
			}

			log.Info("preparing approvers...")
			for _, approver := range registry.Shared.Approvers() {
				log.Info("preparing approver...", "approver", approver.Name())
				if err := approver.Prepare(ctx, opts.Logr, mgr); err != nil {
					return fmt.Errorf("failed to prepare approver %q: %w", approver.Name(), err)
				}
			}
			log.Info("all approvers ready...")

			if err := controllers.AddControllers(ctx, controllers.Options{
				Log:         opts.Logr.WithName("controller"),
				Manager:     mgr,
				Evaluators:  registry.Shared.Evaluators(),
				Reconcilers: registry.Shared.Reconcilers(),
			}); err != nil {
				return fmt.Errorf("failed to add controllers: %w", err)
			}

			log.Info("starting approver-policy...")
			return mgr.Start(ctx)
		},
	}

	opts.Prepare(cmd, registry.Shared.Approvers()...)

	return cmd
}
