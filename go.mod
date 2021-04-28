module github.com/cert-manager/policy-approver

go 1.15

require (
	github.com/go-logr/logr v0.3.0
	github.com/jetstack/cert-manager v1.3.0
	github.com/spf13/cobra v1.0.0
	k8s.io/api v0.19.2
	k8s.io/apimachinery v0.19.2
	k8s.io/client-go v0.19.2
	sigs.k8s.io/controller-runtime v0.7.2
)
