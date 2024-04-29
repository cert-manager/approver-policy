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
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"text/template"

	"k8s.io/client-go/rest"
)

const (
	// kubeconfigTmpl is a template for generating Kubernetes kubeconfig files
	// using client authentication against a single cluster.
	kubeconfigTmpl = `
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: {{ .APIServerCA }}
    server: {{ .APIServerHost }}
  name: test-apiserver
contexts:
- context:
    cluster: test-apiserver
    user: cert-manager-webhook
  name: cert-manager-webhook
current-context: cert-manager-webhook
kind: Config
preferences: {}
users:
- name: cert-manager-webhook
  user:
    client-certificate-data: {{ .ClientCertificate }}
    client-key-data: {{ .ClientKey }}
`
)

// GetenvOrFail returns the specified environment variable, or fails if the
// variable is undefined or empty.
func GetenvOrFail(t *testing.T, name string) string {
	value := os.Getenv(name)
	if len(value) == 0 {
		t.Errorf("FAIL: failing test as %q is not defined", name)
	}
	return value
}

// writeKubeconfig writes a Kubeconfig file using the Kubernetes REST config.
// Writes file to the given name under a temporary directory which  is removed
// at the end of the test. Expects the REST client to use certificate
// authentication.
func writeKubeconfig(t *testing.T, restConfig *rest.Config, name string) string {
	tmpl, err := template.New("kubeconfig").Parse(kubeconfigTmpl)
	if err != nil {
		t.Fatal(err)
	}

	var buff bytes.Buffer
	if err := tmpl.Execute(&buff, &struct {
		APIServerCA       string
		APIServerHost     string
		ClientCertificate string
		ClientKey         string
	}{
		APIServerCA:       base64.StdEncoding.EncodeToString(restConfig.CAData),
		APIServerHost:     restConfig.Host,
		ClientCertificate: base64.StdEncoding.EncodeToString(restConfig.CertData),
		ClientKey:         base64.StdEncoding.EncodeToString(restConfig.KeyData),
	}); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, buff.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}
