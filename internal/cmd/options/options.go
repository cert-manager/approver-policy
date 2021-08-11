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
	"flag"
	"fmt"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/klogr"
)

// Options are the main options for the policy-approver. Populated via
// processing command line flags.
type Options struct {
	// logLevel is the verbosity level the driver will write logs at.
	logLevel string

	// kubeConfigFlags is used for generating a Kubernetes rest config via CLI
	// flags.
	kubeConfigFlags *genericclioptions.ConfigFlags

	// MetricsAddress is the TCP address for exposing HTTP Prometheus metrics
	// which will be served on the HTTP path '/metrics'. The value "0" will
	// disable exposing metrics.
	MetricsAddress string

	// ReadyzAddress is the TCP address for exposing the HTTP readiness probe
	// which will be served on the HTTP path '/readyz'.
	ReadyzAddress string

	// ApproveWhenNoPolicies configures policy-approver to approve all
	// CertificateRequests if no CertificateRequestPolicies resources exist.
	ApproveWhenNoPolicies bool

	// LeaderElectionNamespace is the namespace in which leader election should
	// be leased in to form leader election.
	LeaderElectionNamespace string

	// RestConfig is the shared based rest config to connect to the Kubernetes
	// API.
	RestConfig *rest.Config

	// Logr is the shared base logger.
	Logr logr.Logger
}

func New() *Options {
	return new(Options)
}

func (o *Options) Prepare(cmd *cobra.Command) *Options {
	o.addFlags(cmd)
	return o
}

func (o *Options) Complete() error {
	klog.InitFlags(nil)
	log := klogr.New()
	flag.Set("v", o.logLevel)
	o.Logr = log

	var err error
	o.RestConfig, err = o.kubeConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to build kubernetes rest config: %s", err)
	}

	return nil
}

func (o *Options) addFlags(cmd *cobra.Command) {
	var nfs cliflag.NamedFlagSets

	o.addAppFlags(nfs.FlagSet("App"))
	o.kubeConfigFlags = genericclioptions.NewConfigFlags(true)
	o.kubeConfigFlags.AddFlags(nfs.FlagSet("Kubernetes"))

	usageFmt := "Usage:\n  %s\n"
	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStderr(), nfs, 0)
		return nil
	})

	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStdout(), nfs, 0)
	})

	fs := cmd.Flags()
	for _, f := range nfs.FlagSets {
		fs.AddFlagSet(f)
	}
}

func (o *Options) addAppFlags(fs *pflag.FlagSet) {
	fs.StringVarP(&o.logLevel, "log-level", "v", "1",
		"Log level (1-5).")

	fs.StringVar(&o.MetricsAddress, "metrics-address", ":9402",
		`Port to expose Prometheus metrics on 0.0.0.0 on path '/metrics'. The value "0" will disable exposing metrics.`)

	fs.StringVar(&o.ReadyzAddress, "readiness-probe-address", ":6060",
		`TCP address for exposing HTTP Prometheus metrics which will be served on the HTTP path '/metrics'. The value "0" will
	 disable exposing metrics.`)

	fs.BoolVar(&o.ApproveWhenNoPolicies, "approve-when-no-policies", false,
		"TCP address for exposing the HTTP readiness probe which will be served on the HTTP path '/readyz'.")

	fs.StringVar(&o.LeaderElectionNamespace, "leader-election-namespace", "cert-manager",
		"leader election namespace to use for the controller manager")

	return
}
