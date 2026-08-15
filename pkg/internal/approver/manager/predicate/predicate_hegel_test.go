/*
Copyright 2026 The cert-manager Authors.

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
	"fmt"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/internal/util"

	"hegel.dev/go/hegel"
)

// expectFiltered fails unless got is exactly the policies for which keep
// returns true, in input order.
func expectFiltered(ht *hegel.T, policies []policyapi.CertificateRequestPolicy, got []policyapi.CertificateRequestPolicy, keep func(policyapi.CertificateRequestPolicy) bool) {
	var want []policyapi.CertificateRequestPolicy
	for _, p := range policies {
		if keep(p) {
			want = append(want, p)
		}
	}
	if !apiequality.Semantic.DeepEqual(want, got) {
		ht.Fatalf("unexpected filtered policies:\nin=%#v\nwant=%#v\ngot=%#v", policies, want, got)
	}
}

// TestReadyProperty: Ready keeps exactly the policies whose conditions
// contain Ready=True, preserving order. Condition types are unique per
// policy, as enforced on the real API by the conditions field's
// listType=map / listMapKey=type markers.
func TestReadyProperty(t *testing.T) {
	condGen := hegel.Composite(func(tc hegel.TestCase) []metav1.Condition {
		var conds []metav1.Condition
		for _, typ := range []string{policyapi.ConditionTypeReady, "Other"} {
			if hegel.Draw(tc, hegel.Booleans()) {
				conds = append(conds, metav1.Condition{
					Type: typ,
					Status: hegel.Draw(tc, hegel.SampledFrom([]metav1.ConditionStatus{
						metav1.ConditionTrue, metav1.ConditionFalse, metav1.ConditionUnknown,
					})),
				})
			}
		}
		return conds
	})

	hegel.Test(t, func(ht *hegel.T) {
		var policies []policyapi.CertificateRequestPolicy
		for i, conds := range hegel.Draw(ht, hegel.Lists(condGen).MaxSize(4)) {
			policies = append(policies, policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("p-%d", i)},
				Status:     policyapi.CertificateRequestPolicyStatus{Conditions: conds},
			})
		}

		got, err := Ready(t.Context(), nil, policies)
		if err != nil {
			ht.Fatalf("unexpected error: %v", err)
		}
		expectFiltered(ht, policies, got, func(p policyapi.CertificateRequestPolicy) bool {
			for _, c := range p.Status.Conditions {
				if c.Type == policyapi.ConditionTypeReady && c.Status == metav1.ConditionTrue {
					return true
				}
			}
			return false
		})
	}, hegel.WithTestCases(1000))
}

// TestSelectorIssuerRefProperties: a policy is kept iff each set selector
// field wildcard-matches the request's issuerRef, with the request's Kind
// and Group first defaulted to "Issuer"/"cert-manager.io" when empty — the
// same defaults cert-manager's controllers apply. A nil issuerRef selector
// keeps the policy unconditionally. WildcardMatches itself is verified
// against a regexp oracle in pkg/internal/util.
func TestSelectorIssuerRefProperties(t *testing.T) {
	names := []string{"", "test-name", "other", "my-issuer"}
	kinds := []string{"", "Issuer", "ClusterIssuer", "test-kind"}
	groups := []string{"", "cert-manager.io", "example.io"}
	patterns := []string{"", "*", "test-*", "Issuer", "ClusterIssuer", "cert-manager.io", "test-name", "other-*"}

	drawSel := func(tc hegel.TestCase) *policyapi.CertificateRequestPolicySelectorIssuerRef {
		if hegel.Draw(tc, hegel.Booleans()) {
			return nil
		}
		sel := &policyapi.CertificateRequestPolicySelectorIssuerRef{}
		if hegel.Draw(tc, hegel.Booleans()) {
			sel.Name = ptr.To(hegel.Draw(tc, hegel.SampledFrom(patterns)))
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			sel.Kind = ptr.To(hegel.Draw(tc, hegel.SampledFrom(patterns)))
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			sel.Group = ptr.To(hegel.Draw(tc, hegel.SampledFrom(patterns)))
		}
		return sel
	}

	hegel.Test(t, func(ht *hegel.T) {
		request := &cmapi.CertificateRequest{Spec: cmapi.CertificateRequestSpec{
			IssuerRef: cmmeta.IssuerReference{
				Name:  hegel.Draw(ht, hegel.SampledFrom(names)),
				Kind:  hegel.Draw(ht, hegel.SampledFrom(kinds)),
				Group: hegel.Draw(ht, hegel.SampledFrom(groups)),
			},
		}}
		var policies []policyapi.CertificateRequestPolicy
		for i, sel := range hegel.Draw(ht, hegel.Lists(hegel.Composite(drawSel)).MaxSize(4)) {
			policies = append(policies, policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("p-%d", i)},
				Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{IssuerRef: sel}},
			})
		}

		got, err := SelectorIssuerRef(t.Context(), request, policies)
		if err != nil {
			ht.Fatalf("unexpected error: %v", err)
		}

		defaulted := func(s, d string) string {
			if s == "" {
				return d
			}
			return s
		}
		name := request.Spec.IssuerRef.Name
		kind := defaulted(request.Spec.IssuerRef.Kind, "Issuer")
		group := defaulted(request.Spec.IssuerRef.Group, "cert-manager.io")
		expectFiltered(ht, policies, got, func(p policyapi.CertificateRequestPolicy) bool {
			sel := p.Spec.Selector.IssuerRef
			if sel == nil {
				return true
			}
			return (sel.Name == nil || util.WildcardMatches(*sel.Name, name)) &&
				(sel.Kind == nil || util.WildcardMatches(*sel.Kind, kind)) &&
				(sel.Group == nil || util.WildcardMatches(*sel.Group, group))
		})
	}, hegel.WithTestCases(2000))
}

// TestSelectorNamespaceProperties: a policy is kept iff its namespace
// selector matches the request's namespace by name (any wildcard matchName,
// or no matchNames at all) and, if matchLabels is set, the namespace's
// labels satisfy the selector. The namespace is only fetched when a policy
// that passed the name match has matchLabels set; if the namespace does not
// exist, the first such policy turns the whole call into an error.
func TestSelectorNamespaceProperties(t *testing.T) {
	nsNames := []string{"test-namespace", "other-namespace"}
	namePatterns := []string{"*", "test-*", "test-namespace", "other-namespace", "no-match"}
	// Ordered pairs, not a map: labels are chosen with draws, and draw
	// order must be deterministic across replays for shrinking to work.
	labelKV := [][2]string{{"foo", "bar"}, {"team", "x"}}

	drawSel := func(tc hegel.TestCase) *policyapi.CertificateRequestPolicySelectorNamespace {
		if hegel.Draw(tc, hegel.Booleans()) {
			return nil
		}
		sel := &policyapi.CertificateRequestPolicySelectorNamespace{
			MatchNames: hegel.Draw(tc, hegel.Lists(hegel.SampledFrom(namePatterns)).MaxSize(2)),
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			sel.MatchLabels = map[string]string{}
			for _, kv := range labelKV {
				if hegel.Draw(tc, hegel.Booleans()) {
					sel.MatchLabels[kv[0]] = kv[1]
				}
			}
		}
		return sel
	}

	hegel.Test(t, func(ht *hegel.T) {
		requestNS := hegel.Draw(ht, hegel.SampledFrom(nsNames))
		nsExists := hegel.Draw(ht, hegel.Booleans())
		nsLabels := map[string]string{}
		for _, kv := range labelKV {
			if hegel.Draw(ht, hegel.Booleans()) {
				nsLabels[kv[0]] = kv[1]
			}
		}

		var policies []policyapi.CertificateRequestPolicy
		for i, sel := range hegel.Draw(ht, hegel.Lists(hegel.Composite(drawSel)).MaxSize(4)) {
			policies = append(policies, policyapi.CertificateRequestPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("p-%d", i)},
				Spec:       policyapi.CertificateRequestPolicySpec{Selector: policyapi.CertificateRequestPolicySelector{Namespace: sel}},
			})
		}

		builder := fakeclient.NewClientBuilder().WithScheme(policyapi.GlobalScheme)
		if nsExists {
			builder = builder.WithRuntimeObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: requestNS, Labels: nsLabels}})
		}
		request := &cmapi.CertificateRequest{ObjectMeta: metav1.ObjectMeta{Namespace: requestNS}}

		got, err := SelectorNamespace(builder.Build())(t.Context(), request, policies)

		nameMatch := func(sel *policyapi.CertificateRequestPolicySelectorNamespace) bool {
			if len(sel.MatchNames) == 0 {
				return true
			}
			return util.WildcardContains(sel.MatchNames, requestNS)
		}
		labelsMatch := func(sel *policyapi.CertificateRequestPolicySelectorNamespace) bool {
			for k, v := range sel.MatchLabels {
				if nsLabels[k] != v {
					return false
				}
			}
			return true
		}
		// wantErr: walking policies in order, the first one that passes the
		// name match and needs labels triggers the namespace fetch — which
		// fails if the namespace does not exist.
		wantErr := false
		if !nsExists {
			for _, p := range policies {
				sel := p.Spec.Selector.Namespace
				if sel != nil && nameMatch(sel) && sel.MatchLabels != nil {
					wantErr = true
					break
				}
			}
		}
		if wantErr {
			if err == nil {
				ht.Fatalf("expected missing-namespace error, got policies %#v", got)
			}
			return
		}
		if err != nil {
			ht.Fatalf("unexpected error: %v", err)
		}
		expectFiltered(ht, policies, got, func(p policyapi.CertificateRequestPolicy) bool {
			sel := p.Spec.Selector.Namespace
			return sel == nil || (nameMatch(sel) && labelsMatch(sel))
		})
	}, hegel.WithTestCases(2000))
}
