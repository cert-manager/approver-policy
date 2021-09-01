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

package manager

import (
	"context"
	"fmt"
	"sort"
	"strings"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/pkg/approver"
	"github.com/cert-manager/policy-approver/pkg/approver/manager/predicate"
)

var _ Interface = &manager{}

// manager is an implementation of an Approver Manager. It will manage
// filtering CertificiateRequestPolicies based on predicates, and evaluating
// CertificateRequests using the registered evaluators.
type manager struct {
	lister     client.Reader
	predicates []predicate.Predicate
	evaluators []approver.Evaluator
}

// policyMessage holds the name of the CertificateRequestPolicy and aggregated
// message when running the evaluators against the CertificateRequest.
type policyMessage struct {
	// name is the name of the CertificateRequestPolicy which resulted gave the
	// response by the evaluators.
	name string

	// message is the aggregated messages returned from the evaluators for this
	// policy.
	message string
}

// New constructs a new approver Manager that evaluates whether
// CertificateRequests should be approved or denied, managing registered
// evaluators.
// CertificateRequestPolicies will be filtered on Review for evaluation with the predicates:
// - CertificateRequestPolicy is ready
// - CertificateRequestPolicy IssuerRefSelector matches the CertificateRequest
//   IssuerRef
// - CertificateRequestPolicy is bound to the user that appears in the
//   CertificateRequest
func New(lister client.Reader, client client.Client, evaluators []approver.Evaluator) Interface {
	return &manager{
		lister:     lister,
		predicates: []predicate.Predicate{predicate.Ready, predicate.IssuerRefSelector, predicate.RBACBound(client)},
		evaluators: evaluators,
	}
}

// Review will evaluate whether the incoming CertificateRequest should be
// approved. All evaluators will be called with CertificateRequestPolicys that
// have passed all of the predicates.
func (m *manager) Review(ctx context.Context, cr *cmapi.CertificateRequest) (ReviewResponse, error) {
	policyList := new(policyapi.CertificateRequestPolicyList)
	if err := m.lister.List(ctx, policyList); err != nil {
		return ReviewResponse{}, err
	}

	// If no CertificateRequestPolicies exist in the cluster, return
	// ResultUnprocessed. A CertificateRequest may be re-evaluated at a later
	// time if a CertificateRequestPolicy is created.
	if len(policyList.Items) == 0 {
		return ReviewResponse{Result: ResultUnprocessed, Message: "No CertificateRequestPolicies exist"}, nil
	}

	var (
		policies = policyList.Items
		err      error
	)
	for _, predicate := range m.predicates {
		policies, err = predicate(ctx, cr, policies)
		if err != nil {
			return ReviewResponse{}, fmt.Errorf("failed to perform predicate on policies: %w", err)
		}
	}

	// If no policies are appropriate, return ResultUnprocessed.
	if len(policies) == 0 {
		return ReviewResponse{
			Result:  ResultUnprocessed,
			Message: "No CertificateRequestPolicies bound or applicable",
		}, nil
	}

	// policyMessages hold the aggregated messages of each evaluator response,
	// keyed by the policy name that was executed.
	var policyMessages []policyMessage

	// Run every evaluators against ever policy which is bound to the requesting
	// user.
	for _, policy := range policies {
		var (
			evaluatorDenied   bool
			evaluatorMessages []string
		)

		for _, evaluator := range m.evaluators {
			response, err := evaluator.Evaluate(ctx, &policy, cr)
			if err != nil {
				// if a single evaluator errors, then return early without trying
				// others.
				return ReviewResponse{}, err
			}

			if len(response.Message) > 0 {
				evaluatorMessages = append(evaluatorMessages, response.Message)
			}

			// evaluatorDenied will be set to true if any evaluator denies. We don't
			// break early so that we can capture the responses from _all_
			// evaluators.
			if response.Result == approver.ResultDenied {
				evaluatorDenied = true
			}
		}

		// If no evaluator denied the request, return with approved response.
		if !evaluatorDenied {
			return ReviewResponse{
				Result:  ResultApproved,
				Message: fmt.Sprintf("Approved by CertificateRequestPolicy: %q", policy.Name),
			}, nil
		}

		// Collect evaluator messages that were executed for this policy.
		policyMessages = append(policyMessages, policyMessage{name: policy.Name, message: strings.Join(evaluatorMessages, ", ")})
	}

	// Sort messages by policy name and build message string.
	sort.SliceStable(policyMessages, func(i, j int) bool {
		return policyMessages[i].name < policyMessages[j].name
	})
	var messages []string
	for _, policyMessage := range policyMessages {
		messages = append(messages, fmt.Sprintf("[%s: %s]", policyMessage.name, policyMessage.message))
	}

	// Return with all policies that we consulted, and their errors to why the
	// request was denied.
	return ReviewResponse{
		Result:  ResultDenied,
		Message: fmt.Sprintf("No policy approved this request: %s", strings.Join(messages, " ")),
	}, nil
}
