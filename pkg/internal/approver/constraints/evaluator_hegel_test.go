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

package constraints

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"

	"hegel.dev/go/hegel"
)

// TestEvaluateConstraintsProperties checks Evaluate against a direct
// restatement of the constraints contract. For any combination of request
// duration, key type and policy constraints, the expected outcome is
// recomputable:
//
//   - maxDuration is violated when set and the request duration is absent or
//     greater; minDuration likewise for absent or smaller
//   - privateKey.algorithm is violated on key-type mismatch; maxSize/minSize
//     compare against the key's bit size (Ed25519 has size -1: any minSize
//     from the CRD's valid range violates, no maxSize >= -1 does)
//   - the request is denied iff at least one constraint is violated, and the
//     denial message names exactly the violated fields
func TestEvaluateConstraintsProperties(t *testing.T) {
	// Pre-generate one CSR per key type: key generation dominates runtime and
	// key size/type is all Evaluate looks at.
	type key struct {
		alg  cmapi.PrivateKeyAlgorithm
		size int
		csr  []byte
	}
	keys := []key{
		{cmapi.RSAKeyAlgorithm, 2048, csrFrom(t, x509.RSA)},
		{cmapi.ECDSAKeyAlgorithm, 256, csrFrom(t, x509.ECDSA)},
		{cmapi.Ed25519KeyAlgorithm, -1, csrFrom(t, x509.Ed25519)},
	}
	durations := []time.Duration{time.Minute, time.Hour, 24 * time.Hour, 48 * time.Hour}
	sizes := []int{200, 256, 2048, 4000}
	algs := []cmapi.PrivateKeyAlgorithm{cmapi.RSAKeyAlgorithm, cmapi.ECDSAKeyAlgorithm, cmapi.Ed25519KeyAlgorithm}

	drawDuration := func(ht *hegel.T) *metav1.Duration {
		if hegel.Draw(ht, hegel.Booleans()) {
			return nil
		}
		return &metav1.Duration{Duration: hegel.Draw(ht, hegel.SampledFrom(durations))}
	}

	hegel.Test(t, func(ht *hegel.T) {
		k := keys[hegel.Draw(ht, hegel.Integers(0, len(keys)-1))]
		reqDuration := drawDuration(ht)
		request := gen.CertificateRequest("",
			gen.SetCertificateRequestCSR(k.csr),
			gen.SetCertificateRequestDuration(reqDuration),
		)

		if hegel.Draw(ht, hegel.Integers(0, 9)) == 0 {
			// No constraints at all: always NotDenied.
			resp, err := Approver().Evaluate(t.Context(), &policyapi.CertificateRequestPolicy{}, request)
			if err != nil {
				ht.Fatalf("unexpected error: %v", err)
			}
			if resp.Result != approver.ResultNotDenied {
				ht.Fatalf("nil constraints denied request: %s", resp.Message)
			}
			return
		}

		consts := &policyapi.CertificateRequestPolicyConstraints{
			MinDuration: drawDuration(ht),
			MaxDuration: drawDuration(ht),
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			pk := &policyapi.CertificateRequestPolicyConstraintsPrivateKey{}
			if hegel.Draw(ht, hegel.Booleans()) {
				pk.Algorithm = ptr.To(hegel.Draw(ht, hegel.SampledFrom(algs)))
			}
			if hegel.Draw(ht, hegel.Booleans()) {
				pk.MinSize = ptr.To(hegel.Draw(ht, hegel.SampledFrom(sizes)))
			}
			if hegel.Draw(ht, hegel.Booleans()) {
				pk.MaxSize = ptr.To(hegel.Draw(ht, hegel.SampledFrom(sizes)))
			}
			consts.PrivateKey = pk
		}
		policy := &policyapi.CertificateRequestPolicy{Spec: policyapi.CertificateRequestPolicySpec{Constraints: consts}}

		var violated []string
		if consts.MaxDuration != nil && (reqDuration == nil || reqDuration.Duration > consts.MaxDuration.Duration) {
			violated = append(violated, "maxDuration")
		}
		if consts.MinDuration != nil && (reqDuration == nil || reqDuration.Duration < consts.MinDuration.Duration) {
			violated = append(violated, "minDuration")
		}
		if pk := consts.PrivateKey; pk != nil {
			if pk.Algorithm != nil && *pk.Algorithm != k.alg {
				violated = append(violated, "algorithm")
			}
			if pk.MaxSize != nil && *pk.MaxSize < k.size {
				violated = append(violated, "maxSize")
			}
			if pk.MinSize != nil && *pk.MinSize > k.size {
				violated = append(violated, "minSize")
			}
		}

		resp, err := Approver().Evaluate(t.Context(), policy, request)
		if err != nil {
			ht.Fatalf("unexpected error: %v", err)
		}
		if len(violated) == 0 {
			if resp.Result != approver.ResultNotDenied {
				ht.Fatalf("no constraint violated but request denied: %s", resp.Message)
			}
			return
		}
		if resp.Result != approver.ResultDenied {
			ht.Fatalf("constraints %v violated but request not denied", violated)
		}
		for _, f := range violated {
			if !strings.Contains(resp.Message, f+":") {
				ht.Fatalf("denial message does not name violated field %q: %s", f, resp.Message)
			}
		}
		for _, f := range []string{"maxDuration", "minDuration", "algorithm", "maxSize", "minSize"} {
			named := strings.Contains(resp.Message, f+":")
			isViolated := false
			for _, v := range violated {
				if v == f {
					isViolated = true
				}
			}
			if named && !isViolated {
				ht.Fatalf("denial message names %q which is not violated: %s", f, resp.Message)
			}
		}
	}, hegel.WithTestCases(2000))
}

// TestEvaluateConstraintsMalformedCSR pins the error path: privateKey
// constraints on a request whose CSR does not decode must return an error
// (evaluation could not complete), not a denial.
func TestEvaluateConstraintsMalformedCSR(t *testing.T) {
	policy := &policyapi.CertificateRequestPolicy{Spec: policyapi.CertificateRequestPolicySpec{
		Constraints: &policyapi.CertificateRequestPolicyConstraints{
			PrivateKey: &policyapi.CertificateRequestPolicyConstraintsPrivateKey{},
		},
	}}
	request := gen.CertificateRequest("", gen.SetCertificateRequestCSR([]byte("not a csr")))
	if _, err := Approver().Evaluate(t.Context(), policy, request); err == nil {
		t.Fatal("expected error for undecodable CSR")
	}
}
