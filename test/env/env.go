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

package env

import (
	"context"
	"testing"
	"time"

	webhooktesting "github.com/cert-manager/cert-manager/test/webhook"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
)

const (
	UserClientName = "me@example.com"
)

func init() {
	wait.ForeverTestTimeout = time.Second * 60

	// Since we are going to be creating CRDs in the API server, we need to
	// register these types.
	utilruntime.Must(extapi.AddToScheme(policyapi.GlobalScheme))
}

// Environment is a struct for holding the active and running
// controller-runtime envtest Environment, as well as approver-policy specific
// helper resources for running tests.
type Environment struct {
	// Environment holds the controller-runtime envtest Environment
	*envtest.Environment

	// AdminClient is a client that is authenticated as admin which has
	// permissions to do anything.
	AdminClient client.Client

	// UserClient is a client that is authenticated as the user "me@example.com",
	// groups ["group-1", "group-2"].
	UserClient client.Client
}

// RunControlPlane runs a local API server and makes it ready for running tests
// against. Also runs the cert-manager webhook for operating over cert-manager
// resources. Expects CRD directories to both cert-manager, as well as
// approver-policy. This *MUST* be provided.
// Returns a controller-runtime envtest which is ready to be run against.
func RunControlPlane(t *testing.T, ctx context.Context, crdDirs ...string) *Environment {
	env := &envtest.Environment{
		AttachControlPlaneOutput: false,
		CRDDirectoryPaths:        crdDirs,
		ErrorIfCRDPathMissing:    true,
	}

	t.Logf("starting API server...")
	if _, err := env.Start(); err != nil {
		t.Fatalf("failed to start control plane: %v", err)
	}
	t.Logf("running API server at %q", env.Config.Host)

	// Register cleanup func to stop the api-server after the test has finished.
	t.Cleanup(func() {
		t.Log("stopping API server")
		if err := env.Stop(); err != nil {
			t.Fatalf("failed to shut down control plane: %v", err)
		}
	})

	t.Log("writing cert-manager webhook kubeconfig")
	kubeconifgPath := writeKubeconfig(t, env.Config, "cert-manager-webhook-kubeconfig.yaml")
	t.Logf("cert-manager webhook kubeconfig written to %q", kubeconifgPath)

	webhookOpts, stopWebhook := webhooktesting.StartWebhookServer(t, []string{"--kubeconfig=" + kubeconifgPath})
	t.Logf("running cert-manager webhook on %q", webhookOpts.URL)

	// Register cleanup func to stop the cert-manager webhook after the test has
	// finished.
	t.Cleanup(func() {
		t.Log("stopping cert-manager webhook")
		stopWebhook()
	})

	adminClient, err := client.New(env.Config, client.Options{Scheme: policyapi.GlobalScheme})
	if err != nil {
		t.Fatal(err)
	}

	// Install validating/mutating webhook configurations, not using
	// WebhookInstallOptions as it patches the CA to be its own
	validationObject := getCMValidatingWebhookConfig(webhookOpts.URL, webhookOpts.CAPEM)
	mutatationObject := getCMMutatingWebhookConfig(webhookOpts.URL, webhookOpts.CAPEM)
	for _, crd := range []client.Object{validationObject, mutatationObject} {
		if err := adminClient.Create(ctx, crd); err != nil {
			t.Fatalf("%s: %s", crd.GetName(), err)
		}
	}

	user, err := env.AddUser(envtest.User{Name: UserClientName, Groups: []string{"group-1", "group-2"}}, env.Config)
	if err != nil {
		t.Fatalf("failed to create user %q: %s", UserClientName, err)
	}

	userClient, err := client.New(user.Config(), client.Options{
		Scheme: policyapi.GlobalScheme,
	})
	if err != nil {
		t.Fatal(err)
	}

	return &Environment{
		Environment: env,
		AdminClient: adminClient,
		UserClient:  userClient,
	}
}
