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
	"strings"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmpapi "github.com/cert-manager/policy-approver/apis/v1alpha1"
	_ "github.com/cert-manager/policy-approver/internal/pkg/base"
	"github.com/cert-manager/policy-approver/registry"
)

// Manager is responsible for evaluating whether incoming CertificateRequests
// should be approved or denied, checking CertificateRequestPolicys against
// evaluators which have been registries. Policies will be chosen based on
// their suitability for a particular request, namely whether they are bound to
// a policy via RBAC.
type Manager struct {
	client.Client
	approveWhenNoPolicies bool

	evaluators registry.Registry
}

// New constructs a new policy Manager which will use all currently loaded
// policy evaluators to manage the approval condition of CertificateRequests.
func New(client client.Client, approveWhenNoPolicies bool) *Manager {
	return &Manager{
		Client:                client,
		approveWhenNoPolicies: approveWhenNoPolicies,
		evaluators:            registry.List(),
	}
}

// Evaluate will evaluate whether the incoming CertificateRequest should be
// approved.
// - Consumers should consider a true response meaning the CertificateRequest
//   is **approved**.
// - Consumers should consider a false response and no error to mean the
//   CertificateRequest is **denied**.
// - Consumers should treat any error response as marking the
//   CertificateRequest as neither approved nor denied, and may consider
//   re-evaluation at a later time.
func (m *Manager) Evaluate(ctx context.Context, cr *cmapi.CertificateRequest) (bool, PolicyMessage, error) {
	crps := new(cmpapi.CertificateRequestPolicyList)
	if err := m.List(ctx, crps); err != nil {
		return false, "", err
	}

	// If no CertificateRequestPolicys exist, exit early approved if configured
	// to do so
	if m.approveWhenNoPolicies && len(crps.Items) == 0 {
		return true, MessageNoExistingCertificateRequestPolicy, nil
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
			if err := m.Create(ctx, rev); err != nil {
				return false, MessageError, err
			}

			// Don't perform evaluation if this CertificateRequestPolicy is not bound
			if !rev.Status.Allowed {
				continue
			}

			allEvaluatorsApproved := true
			var evaluatorMessages []string
			for _, evaluator := range m.evaluators {
				approved, message, err := evaluator(&crp, cr)
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
