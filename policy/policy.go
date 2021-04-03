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

package policy

import (
	"context"
	"fmt"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	authzv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmpolicy "github.com/cert-manager/policy-approver/api/v1alpha1"
)

var (
	ErrorMessage          = "Evaluation error"
	NoCRPExistMessage     = "No CertificateRequestPolicies exist"
	MissingBindingMessage = "No CertificateRequestPolicies bound"
)

// Policy is responsible for evaluating whether incoming CertificateRequests
// should be approved, checking CertificateRequestPolicys.
type Policy struct {
	client.Client
}

func New(client client.Client) *Policy {
	return &Policy{
		Client: client,
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
//   reevaluation at a later time.
func (p *Policy) Evaluate(ctx context.Context, cr *cmapi.CertificateRequest) (bool, string, error) {
	crps := new(cmpolicy.CertificateRequestPolicyList)
	if err := p.List(ctx, crps); err != nil {
		return false, "", err
	}

	// If no CertificateRequestPolicys exist, exit early approved
	if len(crps.Items) == 0 {
		return true, NoCRPExistMessage, nil
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
			if err := p.Create(ctx, rev); err != nil {
				return false, ErrorMessage, err
			}

			// Don't perform evaluation if this CertificateRequestPolicy is not bound
			if !rev.Status.Allowed {
				continue
			}

			var el field.ErrorList
			if err := EvaluateCertificateRequest(&el, &crp, cr); err != nil {
				return false, ErrorMessage, err
			}

			// If no evaluation errors resulting from this policy, return approved
			// with the name of the CertificateRequestPolicy.
			if len(el) == 0 {
				return true, fmt.Sprintf("Approved by CertificateRequestPolicy %q", crp.Name), nil
			}

			// Collect policy errors by the CertificateRequestPolicy name, so errors
			// can be bubbled to the CertificateRequest condition
			policyErrors[crp.Name] = el.ToAggregate().Error()
		}
	}

	// If policies exist, but none are bound
	if len(policyErrors) == 0 {
		return false, MissingBindingMessage, nil
	}

	// Return with all policies that we consulted, and their errors to why the
	// request was denied.
	return false, fmt.Sprintf("No policy approved this request: %v", policyErrors), nil
}
