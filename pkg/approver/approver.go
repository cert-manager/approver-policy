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

package approver

import (
	"context"

	"github.com/spf13/pflag"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// Interface is an Approver.
// An Approver implements an Evaluator and Webhook.
type Interface interface {
	// Name is name of this Approver. Name must be unique to the policy-approver
	// instance.
	Name() string

	// RegisterFlags can be used by Approvers for registering CLI flags which are
	// required for configuring that Approver on this policy-approver instance.
	RegisterFlags(*pflag.FlagSet)

	// Prepare can be used by Approvers for registering extra Kubernetes
	// controllers, adding health checks, or other controller-runtime runnables.
	Prepare(context.Context, manager.Manager) error

	// Evaluator is responsible for executing evaluations on whether a request
	// should be denied or not.
	Evaluator

	// Webhook implements admission functions for CertificateRequestPolicy
	// resources.
	Webhook
}
