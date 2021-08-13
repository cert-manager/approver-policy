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
	"os"

	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"

	cmpapi "github.com/cert-manager/policy-approver/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/internal/cmd/options"
	"github.com/cert-manager/policy-approver/internal/pkg/controller"
	"github.com/cert-manager/policy-approver/internal/pkg/manager"
)

const (
	helpOutput = "A cert-manager policy approver which bases decisions on CertificateRequestPolicies"
)

func NewCommand(ctx context.Context) *cobra.Command {
	opts := new(options.Options)

	cmd := &cobra.Command{
		Use:   "policy-approver",
		Short: helpOutput,
		Long:  helpOutput,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Complete()
			log := opts.Log

			mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
				Scheme:                  cmpapi.GlobalScheme,
				MetricsBindAddress:      opts.MetricsAddress,
				HealthProbeBindAddress:  opts.ProbeAddress,
				LeaderElectionNamespace: opts.LeaderElectionNamespace,
				LeaderElection:          true,
				LeaderElectionID:        "policy.cert-manager.io",
				Logger:                  log,
			})
			if err != nil {
				log.Error(err, "unable to start manager")
				os.Exit(1)
			}

			c := controller.New(
				ctrl.Log, mgr.GetClient(),
				mgr.GetEventRecorderFor("policy-approver"),
				manager.New(mgr.GetClient(), opts.ApproveWhenNoPolicies),
			)
			if err := c.SetupWithManager(mgr); err != nil {
				log.Error(err, "unable to create controller", "controller", "CertificateRequestPolicy")
				os.Exit(1)
			}

			if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
				log.Error(err, "unable to set up health check")
				os.Exit(1)
			}
			if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
				log.Error(err, "unable to set up ready check")
				os.Exit(1)
			}

			log.Info("starting manager")
			return mgr.Start(ctx)
		},
	}

	opts.AddFlags(cmd)

	return cmd
}
