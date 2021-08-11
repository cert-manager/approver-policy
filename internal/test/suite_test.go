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

package test

import (
	"flag"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"go.uber.org/zap/zapcore"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/cert-manager/policy-approver/apis"
)

func init() {
	flag.StringVar(&kubeconfigPath, "kubeconfig", "", "path to Kubeconfig")
}

func TestPolicyApprover(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func(done Done) {
	flag.Parse()
	if len(kubeconfigPath) == 0 {
		panic("-kubeconfig not defined")
	}

	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.Level(zapcore.Level(4))))

	By("Creating a kubernetes client")
	clientConfigFlags := genericclioptions.NewConfigFlags(true)
	clientConfigFlags.KubeConfig = &kubeconfigPath
	config, err := clientConfigFlags.ToRESTConfig()
	Expect(err).NotTo(HaveOccurred())

	kubeclient, err = client.New(config, client.Options{Scheme: apis.Scheme})
	Expect(err).NotTo(HaveOccurred())
	close(done)
}, 180)

var _ = AfterSuite(func() {
})
