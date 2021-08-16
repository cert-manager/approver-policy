module github.com/cert-manager/policy-approver

go 1.15

require (
	github.com/go-logr/logr v0.4.0
	github.com/jetstack/cert-manager v1.3.0
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.14.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	k8s.io/api v0.21.3
	k8s.io/apimachinery v0.21.3
	k8s.io/cli-runtime v0.21.3
	k8s.io/client-go v0.21.3
	k8s.io/component-base v0.21.3
	k8s.io/klog/v2 v2.8.0
	sigs.k8s.io/controller-runtime v0.9.6
)
