/*
Copyright 2026 The cert-manager Authors.

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

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
)

func main() {
	ctx := context.Background()

	cmd := &cobra.Command{
		Use:           "startupapicheck",
		Short:         "Check that approver-policy started successfully",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	// Allow `-v` without a value (same UX as cert-manager startupapicheck / cmctl).
	cmd.PersistentFlags().CountP("v", "v", "verbose logging; can be repeated")
	cmd.PersistentFlags().Lookup("v").NoOptDefVal = "1"

	cmd.AddCommand(newCmdCheck())

	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func newCmdCheck() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check approver-policy components",
	}
	cmd.AddCommand(newCmdCheckAPI())
	return cmd
}

type checkAPIOptions struct {
	wait     time.Duration
	interval time.Duration
	verbose  int
}

func newCmdCheckAPI() *cobra.Command {
	o := &checkAPIOptions{}

	cmd := &cobra.Command{
		Use:   "api",
		Short: "Check if the approver-policy API is ready",
		Long: `This check attempts to perform a dry-run create of a
CertificateRequestPolicy resource in order to verify that CRDs are installed
and the approver-policy validating webhook is reachable by the Kubernetes API server.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.verbose, _ = cmd.Root().PersistentFlags().GetCount("v")
			return o.run(cmd.Context(), cmd.OutOrStdout())
		},
	}

	cmd.Flags().DurationVar(&o.wait, "wait", 0, "Wait until the approver-policy API is ready (default 0s = poll once)")
	cmd.Flags().DurationVar(&o.interval, "interval", 5*time.Second, "Time between checks when waiting, must include unit, e.g. 1m or 10s")

	return cmd
}

func (o *checkAPIOptions) run(ctx context.Context, out io.Writer) error {
	cfg, err := config.GetConfig()
	if err != nil {
		return fmt.Errorf("while getting kubeconfig: %w", err)
	}

	scheme := runtime.NewScheme()
	if err := policyapi.AddToScheme(scheme); err != nil {
		return fmt.Errorf("while configuring scheme: %w", err)
	}

	dryRun := true
	cl, err := client.New(cfg, client.Options{
		Scheme: scheme,
		DryRun: &dryRun,
	})
	if err != nil {
		return fmt.Errorf("while creating client: %w", err)
	}

	start := time.Now()
	var lastError error
	pollErr := wait.PollUntilContextCancel(ctx, o.interval, true, func(ctx context.Context) (bool, error) {
		if err := checkAPI(ctx, cl); err != nil {
			if o.verbose > 0 {
				fmt.Fprintf(os.Stderr, "Not ready: %v\n", err)
			}
			lastError = err

			if o.wait > 0 && time.Since(start) > o.wait {
				return false, context.DeadlineExceeded
			}
			if o.wait == 0 {
				return false, context.DeadlineExceeded
			}
			return false, nil
		}
		return true, nil
	})

	if pollErr != nil {
		if errors.Is(pollErr, context.DeadlineExceeded) && o.wait > 0 && o.verbose > 0 {
			fmt.Fprintf(os.Stderr, "Timed out after %s: %v\n", o.wait, lastError)
		}
		if lastError != nil {
			return lastError
		}
		return pollErr
	}

	fmt.Fprintln(out, "The approver-policy API is ready")
	return nil
}

func checkAPI(ctx context.Context, cl client.Client) error {
	crp := &policyapi.CertificateRequestPolicy{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "startupapicheck-",
		},
		Spec: policyapi.CertificateRequestPolicySpec{
			Selector: policyapi.CertificateRequestPolicySelector{
				IssuerRef: &policyapi.CertificateRequestPolicySelectorIssuerRef{},
			},
		},
	}
	return cl.Create(ctx, crp)
}
