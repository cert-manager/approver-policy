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

package registry

import (
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"

	cmpapi "github.com/cert-manager/policy-approver/apis/v1alpha1"
)

// EvaluateFunc is a function which is used by an evaluator to asses whether a
// request passes evaluation given the request and policy.
// EvaluateFunc should return "true" if the request is approved, "false"
// otherwise.
// An occupying message may be returned to give context to give the approval
// decision.
// An error should only be returned if there was an error in the evaluator
// attempting to evaluate the request over the policy itself. A policy manager
// may re-evaluate an evaluation if an error is returned.
type EvaluateFunc func(policy *cmpapi.CertificateRequestPolicy, cr *cmapi.CertificateRequest) (bool, string, error)

// Registry is a store of evaluator's EvaluateFuncs.
type Registry []EvaluateFunc

// evaluatorRegistry is a registry of evaluators which will be run against a
// CetificateRequest for every CertificateRequestPolicy which is qualifies for.
var evaluatorRegistry = []EvaluateFunc{}

// Load will load an Evaluator Function into the Policy Evaluator registry.
// Every evaluator function will run against a CetificateRequest for every
// CertificateRequestPolicy which is qualifies for.
func Load(fn EvaluateFunc) {
	evaluatorRegistry = append(evaluatorRegistry, fn)
}

// List returns the list of EvaluateFuncs which have been registered.
func List() Registry {
	return evaluatorRegistry
}
