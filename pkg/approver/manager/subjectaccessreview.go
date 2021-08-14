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

package evaluator

import (
	"context"
	"strings"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmpapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/pkg/approver"
)

// subjectaccessreview is a manager that calls evaluators with
// CertificateRequestPolicys that have been RBAC bound to the user who appears
// in the passed CertificateRequest to Evaluate.
type subjectaccessreview struct {
	client client.Client

	evaluators []approver.Evaluator
}

// NewSubjectAccessReview constructs a new approver Manager which evaluates
// whether CertificateRequests should be approved or denied, managing
// registered evaluators.
func NewSubjectAccessReview(client client.Client, evaluators []approver.Evaluator) *subjectaccessreview {
	return &subjectaccessreview{
		client:     client,
		evaluators: evaluators,
	}
}

// Review will evaluate whether the incoming CertificateRequest should be
// approved. All evaluators will be called with CertificateRequestPolicys that
// have been RBAC bound to the user included in the CertificateRequest.
func (s *subjectaccessreview) Review(ctx context.Context, cr *cmapi.CertificateRequest) (bool, string, error) {
	crps := new(cmpapi.CertificateRequestPolicyList)
	if err := s.client.List(ctx, crps); err != nil {
		return false, "", err
	}

	policyErrors := make(map[string]string)
	extra := make(map[string]authzv1.ExtraValue)
	for k, v := range cr.Spec.Extra {
		extra[k] = v
	}

	// Check namespaced scope, then cluster scope
	for _, ns := range []string{cr.Namespace, ""} {
		for _, crp := range crps.Items {

			// Don't check the same CertificateRequestPolicy more than once
			if _, ok := policyErrors[crp.Name]; ok {
				continue
			}

			// Perform subject access review for this CertificateRequestPolicy
			rev := &authzv1.SubjectAccessReview{
				Spec: authzv1.SubjectAccessReviewSpec{
					User:   cr.Spec.Username,
					Groups: cr.Spec.Groups,
					Extra:  extra,
					UID:    cr.Spec.UID,

					ResourceAttributes: &authzv1.ResourceAttributes{
						Group:     "policy.cert-manager.io",
						Resource:  "certificaterequestpolicies",
						Name:      crp.Name,
						Namespace: ns,
						Verb:      "use",
					},
				},
			}
			if err := s.client.Create(ctx, rev); err != nil {
				return false, MessageError, err
			}

			// Don't perform evaluation if this CertificateRequestPolicy is not bound
			if !rev.Status.Allowed {
				continue
			}

			allEvaluatorsApproved := true
			var evaluatorMessages []string
			for _, evaluator := range s.evaluators {
				approved, message, err := evaluator.Evaluate(ctx, &crp, cr)
				if err != nil {
					// if a single evaluator fails, then return early without
					// trying others
					return false, MessageError, err
				}

				// messages will only be returned when the CertificateRequest
				// is not approved
				evaluatorMessages = append(evaluatorMessages, message)

				// allApprovedApproved will be set to false if any evaluators
				// do not approve
				if !approved {
					allEvaluatorsApproved = false
				}
			}

			if allEvaluatorsApproved {
				return true, approvedMessage(crp.Name), nil
			}

			// Collect policy errors by the CertificateRequestPolicy name, so errors
			// can be bubbled to the CertificateRequest condition
			policyErrors[crp.Name] = strings.Join(evaluatorMessages, ", ")
		}
	}

	// If no policies bound, error
	if len(policyErrors) == 0 {
		return false, MessageNoApplicableCertificateRequestPolicy, nil
	}

	// Return with all policies that we consulted, and their errors to why the
	// request was denied.
	return false, deniedMessage(policyErrors), nil
}
