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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/klog/v2"

	"github.com/cert-manager/approver-policy/pkg/approver"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

// Options are the main options for the approver-policy. Populated via
// processing command line flags.
type Options struct {
	// kubeConfigFlags is used for generating a Kubernetes rest config via CLI
	// flags.
	kubeConfigFlags *genericclioptions.ConfigFlags

	// MetricsAddress is the TCP address for exposing HTTP Prometheus metrics
	// which will be served on the HTTP path '/metrics'. The value "0" will
	// disable exposing metrics.
	MetricsAddress string

	// LeaderElectionNamespace is the Namespace to lease the controller replica
	// leadership election.
	LeaderElectionNamespace string

	// ReadyzAddress is the TCP address for exposing the HTTP readiness probe
	// which will be served on the HTTP path '/readyz'.
	ReadyzAddress string

	// RestConfig is the shared base rest config to connect to the Kubernetes
	// API.
	RestConfig *rest.Config

	// log are options controlling logging
	log logOptions

	// Webhook are options specific to the Kubernetes Webhook.
	Webhook

	// Logr is the shared base logger.
	Logr logr.Logger
}

type logOptions struct {
	format logFormat
	level  int
}

const (
	logFormatText logFormat = "text"
	logFormatJSON logFormat = "json"
)

type logFormat string

// String is used both by fmt.Print and by Cobra in help text
func (e *logFormat) String() string {
	if len(*e) == 0 {
		return string(logFormatText)
	}
	return string(*e)
}

// Set must have pointer receiver to avoid changing the value of a copy
func (e *logFormat) Set(v string) error {
	switch v {
	case "text", "json":
		*e = logFormat(v)
		return nil
	default:
		return errors.New(`must be one of "text" or "json"`)
	}
}

// Type is only used in help text
func (e *logFormat) Type() string {
	return "string"
}

// Webhook holds options specific to running the approver-policy Webhook
// service.
type Webhook struct {
	// Host is the host that the Webhook will be served on.
	Host string

	// Port is the TCP port that the Webhook will be served on.
	Port int

	// ServiceName is the service that exposes the Webhook server.
	ServiceName string

	// CASecretName is the namespace that the approver-policy
	// webhook CA certificate Secret is stored.
	CASecretNamespace string

	// CASecretName is the name of the Secret use to store
	// the approver-policy webhook CA certificate.
	CASecretName string

	// CADuration for webhook server DynamicSource CA.
	// DynamicSource is upstream cert-manager's CA Provider.
	// Defaults to 1 year.
	CADuration time.Duration

	// LeafDuration for webhook server TLS certificates.
	// Defaults to 7 days.
	LeafDuration time.Duration
}

func New() *Options {
	return new(Options)
}

func (o *Options) Prepare(cmd *cobra.Command, approvers ...approver.Interface) *Options {
	o.addFlags(cmd, approvers...)
	return o
}

func (o *Options) Complete() error {
	opts := &slog.HandlerOptions{
		// To avoid a breaking change in application configuration,
		// we negate the (configured) logr verbosity level to get the corresponding slog level
		Level: slog.Level(-o.log.level),
	}
	var handler slog.Handler = slog.NewTextHandler(os.Stdout, opts)
	if o.log.format == logFormatJSON {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	slog.SetDefault(slog.New(handler))

	log := logr.FromSlogHandler(handler)
	klog.SetLogger(log)
	o.Logr = log

	var err error
	o.RestConfig, err = o.kubeConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to build kubernetes rest config: %s", err)
	}

	return nil
}

func (o *Options) addFlags(cmd *cobra.Command, approvers ...approver.Interface) {
	var nfs cliflag.NamedFlagSets

	o.addAppFlags(nfs.FlagSet("App"))
	o.addLoggingFlags(nfs.FlagSet("Logging"))
	o.addWebhookFlags(nfs.FlagSet("Webhook"))
	o.kubeConfigFlags = genericclioptions.NewConfigFlags(true)
	o.kubeConfigFlags.AddFlags(nfs.FlagSet("Kubernetes"))

	for _, approver := range approvers {
		approver.RegisterFlags(nfs.FlagSet(approver.Name()))
	}

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
	fs.StringVar(&o.LeaderElectionNamespace, "leader-election-namespace", "",
		"Namespace to lease leader election for controller replica set.")

	fs.StringVar(&o.MetricsAddress, "metrics-bind-address", ":9402",
		`TCP address for exposing HTTP Prometheus metrics which will be served on the HTTP path '/metrics'. The value "0" will
	 disable exposing metrics.`)

	fs.StringVar(&o.ReadyzAddress, "readiness-probe-bind-address", ":6060",
		"TCP address for exposing the HTTP readiness probe which will be served on the HTTP path '/readyz'.")
}

func (o *Options) addLoggingFlags(fs *pflag.FlagSet) {
	fs.Var(&o.log.format,
		"log-format",
		"Log format (text or json)")

	fs.IntVarP(&o.log.level,
		"log-level", "v", 1,
		"Log level (1-5).")
}

func (o *Options) addWebhookFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Webhook.Host,
		"webhook-host", "0.0.0.0",
		"Host to serve webhook.")

	fs.IntVar(&o.Webhook.Port,
		"webhook-port", 6443,
		"Port to serve webhook.")

	fs.StringVar(&o.Webhook.ServiceName,
		"webhook-service-name", "cert-manager-approver-policy",
		"Name of the Kubernetes Service that exposes the Webhook's server.")

	fs.StringVar(&o.Webhook.CASecretNamespace,
		"webhook-ca-secret-namespace", "cert-manager",
		"Namespace that the approver-policy webhook CA certificate Secret is stored.")

	fs.StringVar(&o.Webhook.CASecretName,
		"webhook-ca-secret-name", "cert-manager-approver-policy-tls",
		"Name of Secret used to store the approver-policy webhook CA certificate Secret.")

	fs.DurationVar(&o.Webhook.CADuration,
		"webhook-ca-duration", time.Hour*24*365,
		"Duration for webhook server DynamicSource CA. Defaults to 1 year.")

	fs.DurationVar(&o.Webhook.LeafDuration,
		"webhook-leaf-cert-duration", time.Hour*24*7,
		"Duration for webhook server TLS certificates. Defaults to 7 days.")

	var deprecatedCertDir string
	fs.StringVar(&deprecatedCertDir,
		"webhook-certificate-dir", "/tmp",
		"Directory where the Webhook certificate and private key are located. "+
			"Certificate and private key must be named 'tls.crt' and 'tls.key' "+
			"respectively.")

	if err := fs.MarkDeprecated("webhook-certificate-dir", "webhook-certificate-dir is deprecated"); err != nil {
		panic(err)
	}
}
