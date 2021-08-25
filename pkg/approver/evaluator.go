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

// All Approvers include a single Evaluator. An Evaluator is responsible for
// making decisions on whether a CertificateRequest violates a
// CertificateRequestPolicy. An Evaluator will either determine the
// CertificateRequest as Denied, or NotDenied.

package approver

import (
	"context"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"

	policyapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
)

// EvaluationResult is the result of an evaluator evaluating a
// CertificateRequest based on the given CertificateRequestPolicy.
type EvaluationResult bool

const (
	// ResultDenied is the result of an evaluation where the evaluator denies the
	// request.
	ResultDenied EvaluationResult = false

	// ResultPassed is the result of an evaluation where the evaluator didn't
	// deny the request, and passed evaluation.
	ResultNotDenied EvaluationResult = true
)

// EvaluationResponse is the response to an evaluation request.
type EvaluationResponse struct {
	// Result is the actionable result code from running the evaluation.
	Result EvaluationResult

	// Message is optional context as to why the evaluator has given the result
	// it has.
	Message string
}

// Evaluator is responsible for making decisions on whether a
// CertificateRequest should be denied given a CertificateRequestPolicy.
// Evaluators should register within the registry if they wish to be evaluated
// by the approver manager.
type Evaluator interface {
	// Evaluate determines whether the given request passes evaluation based on
	// the given policy.
	// Evaluate should return ResultDenied if the request is denied given the
	// policy. Evaluate should return ResultNotDenied if the request hasn't been
	// denied.
	// An occupying message may be returned to give context to the denied
	// decision.
	// An error should only be returned if there was an error in the evaluator
	// attempting to evaluate the request over the policy itself. A policy
	// manager may re-evaluate an evaluation if an error is returned.
	Evaluate(context.Context, *policyapi.CertificateRequestPolicy, *cmapi.CertificateRequest) (EvaluationResponse, error)
}
