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

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"

	cmpapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
)

// Interface is an Approver. Implements Evaluator.
type Interface interface {
	Evaluator
}

// Evaluator is responsible for making decisions on whether a
// CertificateRequest should be approved given a CertificateRequestPolicy.
// Evaluators should register within the register if they wish to be evaluated
// by the evaluator manager.
type Evaluator interface {
	// Evaluate determines whether the given request passes evaluation based on
	// the given policy.
	// Evaluate should return "true" if the request is approved, "false"
	// otherwise.
	// An occupying message may be returned to give context to give the approval
	// decision.
	// An error should only be returned if there was an error in the evaluator
	// attempting to evaluate the request over the policy itself. A policy
	// manager may re-evaluate an evaluation if an error is returned.
	Evaluate(context.Context, *cmpapi.CertificateRequestPolicy, *cmapi.CertificateRequest) (bool, string, error)
}
