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

package predicate

import (
	"context"
	"fmt"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/internal/util"
)

// Predicate is a func called by the Approver Manager to filter the set of
// CertificateRequestPolicies that should be evaluated on the
// CertificateRequest. Returned list of CertificateRequestPolicies pass the
// predicate or filter.
type Predicate func(context.Context, *cmapi.CertificateRequest, []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error)

// Ready is a Predicate that returns the subset of given policies that have a
// Ready condition set to True.
func Ready(_ context.Context, _ *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
	var readyPolicies []policyapi.CertificateRequestPolicy

	for _, policy := range policies {
		for _, condition := range policy.Status.Conditions {
			if condition.Type == policyapi.CertificateRequestPolicyConditionReady && condition.Status == corev1.ConditionTrue {
				readyPolicies = append(readyPolicies, policy)
			}
		}
	}

	return readyPolicies, nil
}

// SelectorIssuerRef is a Predicate that returns the subset of given policies
// that have an `spec.selector.issuerRef` matching the `spec.issuerRef` in the
// request. PredicateSelectorIssuerRef will match on strings using wilcards
// "*". Empty selector is equivalent to "*" and will match on anything.
func SelectorIssuerRef(_ context.Context, cr *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
	var matchingPolicies []policyapi.CertificateRequestPolicy

	// cert-manager applies controller defaults for issuer Kind and Group,
	// which means that default values are NOT materialized in resources
	// if omitted.
	// So in order to make policies addressing these default values effective,
	// we must apply cert-manager defaults on request when matching policies.
	issKind := nonEmptyOrDefault(cr.Spec.IssuerRef.Kind, cmapi.IssuerKind)
	issGroup := nonEmptyOrDefault(cr.Spec.IssuerRef.Group, "cert-manager.io")
	issName := cr.Spec.IssuerRef.Name

	for _, policy := range policies {
		issRefSel := policy.Spec.Selector.IssuerRef
		// If the issuerRef selector is nil, we match the policy and continue
		// early.
		if issRefSel == nil {
			matchingPolicies = append(matchingPolicies, policy)
			continue
		}

		if issRefSel.Name != nil && !util.WildcardMatches(*issRefSel.Name, issName) {
			continue
		}
		if issRefSel.Kind != nil && !util.WildcardMatches(*issRefSel.Kind, issKind) {
			continue
		}
		if issRefSel.Group != nil && !util.WildcardMatches(*issRefSel.Group, issGroup) {
			continue
		}
		matchingPolicies = append(matchingPolicies, policy)
	}

	return matchingPolicies, nil
}

// SelectorNamespace is a Predicate that returns the subset of given policies
// that have an `spec.selector.namespace` matching the `metadata.namespace` of
// the request. SelectorNamespace will match with `namespace.matchNames` on
// namespaces using wilcards "*". Empty selector is equivalent to "*" and will
// match on any Namespace.
func SelectorNamespace(lister client.Reader) Predicate {
	return func(ctx context.Context, request *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
		var matchingPolicies []policyapi.CertificateRequestPolicy

		// namespaceLabels are the labels of the namespace the request is in. We
		// use a pointer here so we can lazily fetch the namespace as necessary.
		var namespaceLabels *map[string]string

		for _, policy := range policies {
			nsSel := policy.Spec.Selector.Namespace

			// Namespace Selector is nil so we always match.
			if nsSel == nil {
				matchingPolicies = append(matchingPolicies, policy)
				continue
			}

			// (matched ref 1): If no strings are in matchNames, then we mark as
			// matched here. This is to ensure the `matched` bool is `true` for the
			// condition later on.
			matched := len(nsSel.MatchNames) == 0

			// Match by name.
			for _, matchName := range nsSel.MatchNames {
				if util.WildcardMatches(matchName, request.Namespace) {
					matched = true
					break
				}
			}

			// (matched ref 2): If we haven't matched here then we can continue to
			// the next policy early, and not bother checking the label selector.
			// `matched` will be true if:
			// 1. we had matchNames defined and they matched, or
			// 2. we didn't define any matchNames and so `matched` was already `true`
			//    (from matched ref 1).
			if !matched {
				continue
			}

			// Match by Label Selector.
			if nsSel.MatchLabels != nil {

				if namespaceLabels == nil {
					var namespace corev1.Namespace
					if err := lister.Get(ctx, client.ObjectKey{Name: request.Namespace}, &namespace); err != nil {
						return nil, fmt.Errorf("failed to get request's namespace to determine namespace selector: %w", err)
					}
					namespaceLabels = &namespace.Labels
				}

				selector, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
					MatchLabels: nsSel.MatchLabels,
				})
				if err != nil {
					return nil, fmt.Errorf("failed to parse namespace label selector: %w", err)
				}
				// If the selector doesn't match, then we continue to the next policy.
				if !selector.Matches(labels.Set(*namespaceLabels)) {
					continue
				}
			}

			matchingPolicies = append(matchingPolicies, policy)
		}

		return matchingPolicies, nil
	}
}

// RBACBoundPolicies is a Predicate that returns the subset of
// CertificateRequestPolicies that have been RBAC bound to the user in the
// CertificateRequest. Achieved using SubjectAccessReviews.
func RBACBound(client client.Client) Predicate {
	return func(ctx context.Context, cr *cmapi.CertificateRequest, policies []policyapi.CertificateRequestPolicy) ([]policyapi.CertificateRequestPolicy, error) {
		extra := make(map[string]authzv1.ExtraValue)
		for k, v := range cr.Spec.Extra {
			extra[k] = v
		}

		var boundPolicies []policyapi.CertificateRequestPolicy
		for _, policy := range policies {
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
						Name:      policy.Name,
						Namespace: cr.Namespace,
						Verb:      "use",
					},
				},
			}
			if err := client.Create(ctx, rev); err != nil {
				return nil, fmt.Errorf("failed to create subjectaccessreview: %w", err)
			}

			// If the user is bound to this policy then append.
			if rev.Status.Allowed {
				boundPolicies = append(boundPolicies, policy)
			}
		}

		return boundPolicies, nil
	}
}

func nonEmptyOrDefault(s, d string) string {
	if len(s) == 0 {
		return d
	}
	return s
}
