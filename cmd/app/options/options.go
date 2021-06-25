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

package options

import (
	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	"flag"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

type Options struct {
	MetricsAddress string
	ProbeAddress   string

	ApproveWhenNoPolicies bool

	LeaderElectionNamespace string

	zapOptions *zap.Options
	Log        logr.Logger
}

func New() *Options {
	return new(Options)
}

func (o *Options) AddFlags(cmd *cobra.Command) *Options {
	fs := flag.NewFlagSet("policy-approver", flag.ExitOnError)

	o.zapOptions = &zap.Options{
		Development: false,
	}
	o.zapOptions.BindFlags(fs)

	fs.StringVar(&o.MetricsAddress, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	fs.StringVar(&o.ProbeAddress, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	fs.BoolVar(&o.ApproveWhenNoPolicies, "approve-when-no-policies", false, "When no CertificateRequestPolicies exist in the cluster, approve all requests.")
	fs.StringVar(&o.LeaderElectionNamespace, "leader-election-namespace", "cert-manager", "leader election namespace to use for the controller manager")

	cmd.PersistentFlags().AddGoFlagSet(fs)

	return o
}

func (o *Options) Complete() {
	o.Log = zap.New(zap.UseFlagOptions(o.zapOptions))
}
