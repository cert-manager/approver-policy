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

package allowed

import (
	"crypto/x509"
	"maps"
	"net"
	"net/url"
	"slices"
	"strings"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/test/unit/gen"
	"k8s.io/utils/ptr"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"

	"hegel.dev/go/hegel"
)

// drawnRequest is a generated CertificateRequest together with the attribute
// values that went into it, so properties can build policies from the same
// values without re-parsing the CSR.
type drawnRequest struct {
	request *cmapi.CertificateRequest

	commonName   string
	dnsNames     []string
	ipAddresses  []string
	uris         []string
	emails       []string
	orgs         []string
	countries    []string
	orgUnits     []string
	localities   []string
	provinces    []string
	streets      []string
	postalCodes  []string
	serialNumber string
	isCA         bool
	usages       []cmapi.KeyUsage
}

// slices returns the request's non-empty slice-valued attributes keyed by the
// name used in reporting, paired with a setter that installs an allow-list
// entry for that attribute on a policy.
func (d *drawnRequest) fields() map[string]struct {
	values []string
	set    func(*policyapi.CertificateRequestPolicyAllowed, *policyapi.CertificateRequestPolicyAllowedStringSlice)
} {
	sub := func(f func(*policyapi.CertificateRequestPolicyAllowedX509Subject, *policyapi.CertificateRequestPolicyAllowedStringSlice)) func(*policyapi.CertificateRequestPolicyAllowed, *policyapi.CertificateRequestPolicyAllowedStringSlice) {
		return func(a *policyapi.CertificateRequestPolicyAllowed, s *policyapi.CertificateRequestPolicyAllowedStringSlice) {
			if a.Subject == nil {
				a.Subject = &policyapi.CertificateRequestPolicyAllowedX509Subject{}
			}
			f(a.Subject, s)
		}
	}
	return map[string]struct {
		values []string
		set    func(*policyapi.CertificateRequestPolicyAllowed, *policyapi.CertificateRequestPolicyAllowedStringSlice)
	}{
		"dnsNames": {d.dnsNames, func(a *policyapi.CertificateRequestPolicyAllowed, s *policyapi.CertificateRequestPolicyAllowedStringSlice) {
			a.DNSNames = s
		}},
		"ipAddresses": {d.ipAddresses, func(a *policyapi.CertificateRequestPolicyAllowed, s *policyapi.CertificateRequestPolicyAllowedStringSlice) {
			a.IPAddresses = s
		}},
		"uris": {d.uris, func(a *policyapi.CertificateRequestPolicyAllowed, s *policyapi.CertificateRequestPolicyAllowedStringSlice) {
			a.URIs = s
		}},
		"emailAddresses": {d.emails, func(a *policyapi.CertificateRequestPolicyAllowed, s *policyapi.CertificateRequestPolicyAllowedStringSlice) {
			a.EmailAddresses = s
		}},
		"organizations": {d.orgs, sub(func(a *policyapi.CertificateRequestPolicyAllowedX509Subject, s *policyapi.CertificateRequestPolicyAllowedStringSlice) {
			a.Organizations = s
		})},
		"countries": {d.countries, sub(func(a *policyapi.CertificateRequestPolicyAllowedX509Subject, s *policyapi.CertificateRequestPolicyAllowedStringSlice) {
			a.Countries = s
		})},
		"organizationalUnits": {d.orgUnits, sub(func(a *policyapi.CertificateRequestPolicyAllowedX509Subject, s *policyapi.CertificateRequestPolicyAllowedStringSlice) {
			a.OrganizationalUnits = s
		})},
		"localities": {d.localities, sub(func(a *policyapi.CertificateRequestPolicyAllowedX509Subject, s *policyapi.CertificateRequestPolicyAllowedStringSlice) {
			a.Localities = s
		})},
		"provinces": {d.provinces, sub(func(a *policyapi.CertificateRequestPolicyAllowedX509Subject, s *policyapi.CertificateRequestPolicyAllowedStringSlice) {
			a.Provinces = s
		})},
		"streetAddresses": {d.streets, sub(func(a *policyapi.CertificateRequestPolicyAllowedX509Subject, s *policyapi.CertificateRequestPolicyAllowedStringSlice) {
			a.StreetAddresses = s
		})},
		"postalCodes": {d.postalCodes, sub(func(a *policyapi.CertificateRequestPolicyAllowedX509Subject, s *policyapi.CertificateRequestPolicyAllowedStringSlice) {
			a.PostalCodes = s
		})},
	}
}

// drawRequest draws attribute values (canonical forms only, so that the value
// written into the CSR is byte-identical to the value the evaluator extracts)
// and builds the CertificateRequest carrying a real signed CSR.
func drawRequest(ht *hegel.T, t *testing.T) *drawnRequest {
	names := hegel.Lists(hegel.SampledFrom([]string{
		"example.com", "foo.bar", "*.example.com", "x", "sub.domain.example.com",
	})).MaxSize(2)
	words := func(pool ...string) []string {
		return hegel.Draw(ht, hegel.Lists(hegel.SampledFrom(pool)).MaxSize(2))
	}

	d := &drawnRequest{
		commonName:   hegel.Draw(ht, hegel.SampledFrom([]string{"", "hello-world", "*.example.com", "aaa"})),
		dnsNames:     hegel.Draw(ht, names),
		ipAddresses:  words("1.1.1.1", "10.0.0.1", "2001:db8::1"),
		uris:         words("spiffe://cluster.local/ns/foo/sa/bar", "https://example.com/x"),
		emails:       words("foo@example.com", "bar@example.com"),
		orgs:         words("company-1", "company-2"),
		countries:    words("UK", "DE"),
		orgUnits:     words("org-1", "org-2"),
		localities:   words("loc-1", "loc-2"),
		provinces:    words("prov-1", "prov-2"),
		streets:      words("street-1", "street-2"),
		postalCodes:  words("post-1", "post-2"),
		serialNumber: hegel.Draw(ht, hegel.SampledFrom([]string{"", "serial-1"})),
		isCA:         hegel.Draw(ht, hegel.Booleans()),
	}
	for _, u := range hegel.Draw(ht, hegel.Lists(hegel.SampledFrom([]cmapi.KeyUsage{
		cmapi.UsageClientAuth, cmapi.UsageServerAuth, cmapi.UsageCRLSign,
	})).MaxSize(2)) {
		d.usages = append(d.usages, u)
	}

	mods := []gen.CSRModifier{
		gen.SetCSRCommonName(d.commonName),
		gen.SetCSRDNSNames(d.dnsNames...),
	}
	var ips []net.IP
	for _, s := range d.ipAddresses {
		ips = append(ips, net.ParseIP(s))
	}
	mods = append(mods, gen.SetCSRIPAddresses(ips...))
	var uris []*url.URL
	for _, s := range d.uris {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		uris = append(uris, u)
	}
	mods = append(mods, gen.SetCSRURIs(uris...), gen.SetCSREmails(d.emails))
	mods = append(mods, noErrModifier(func(csr *x509.CertificateRequest) {
		csr.Subject.Organization = d.orgs
		csr.Subject.Country = d.countries
		csr.Subject.OrganizationalUnit = d.orgUnits
		csr.Subject.Locality = d.localities
		csr.Subject.Province = d.provinces
		csr.Subject.StreetAddress = d.streets
		csr.Subject.PostalCode = d.postalCodes
		csr.Subject.SerialNumber = d.serialNumber
	}))

	d.request = gen.CertificateRequest("",
		gen.SetCertificateRequestCSR(csrFrom(t, mods...)),
		gen.SetCertificateRequestIsCA(d.isCA),
		gen.SetCertificateRequestKeyUsages(d.usages...),
	)
	return d
}

// identityPolicy builds the policy that allows exactly the request's
// attributes: each present attribute gets an allow-list containing its exact
// values, isCA and usages mirror the request.
func identityPolicy(d *drawnRequest) *policyapi.CertificateRequestPolicy {
	allowed := &policyapi.CertificateRequestPolicyAllowed{}
	if d.commonName != "" {
		allowed.CommonName = &policyapi.CertificateRequestPolicyAllowedString{Value: ptr.To(d.commonName)}
	}
	if d.serialNumber != "" {
		allowed.Subject = &policyapi.CertificateRequestPolicyAllowedX509Subject{}
		allowed.Subject.SerialNumber = &policyapi.CertificateRequestPolicyAllowedString{Value: ptr.To(d.serialNumber)}
	}
	for _, f := range d.fields() {
		if len(f.values) == 0 {
			continue
		}
		f.set(allowed, &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: ptr.To(append([]string(nil), f.values...))})
	}
	if d.isCA {
		allowed.IsCA = ptr.To(true)
	}
	if len(d.usages) > 0 {
		allowed.Usages = ptr.To(append([]cmapi.KeyUsage(nil), d.usages...))
	}
	return &policyapi.CertificateRequestPolicy{Spec: policyapi.CertificateRequestPolicySpec{Allowed: allowed}}
}

// TestEvaluateIdentityPolicyNotDenied: a policy that allows exactly the
// attributes a request carries must not deny that request, whatever
// combination of attributes is present. This is the completeness half of the
// evaluator's contract.
func TestEvaluateIdentityPolicyNotDenied(t *testing.T) {
	a := Approver().(allowed)
	hegel.Test(t, func(ht *hegel.T) {
		d := drawRequest(ht, t)
		resp, err := a.Evaluate(t.Context(), identityPolicy(d), d.request)
		if err != nil {
			ht.Fatalf("unexpected error: %v", err)
		}
		if resp.Result != approver.ResultNotDenied {
			ht.Fatalf("identity policy denied its own request: %s", resp.Message)
		}
	}, hegel.WithTestCases(500))
}

// TestEvaluateRemovedAttributeDenied: starting from the identity policy,
// withdrawing the allowance for one attribute the request actually carries
// must flip the result to Denied, and the denial message must name that
// attribute's field. This is the soundness half: no attribute is ignored.
func TestEvaluateRemovedAttributeDenied(t *testing.T) {
	a := Approver().(allowed)
	hegel.Test(t, func(ht *hegel.T) {
		d := drawRequest(ht, t)

		type target struct {
			name string
			drop func(*policyapi.CertificateRequestPolicyAllowed)
		}
		var targets []target
		if d.commonName != "" {
			targets = append(targets, target{"commonName", func(al *policyapi.CertificateRequestPolicyAllowed) { al.CommonName = nil }})
		}
		if d.serialNumber != "" {
			targets = append(targets, target{"serialNumber", func(al *policyapi.CertificateRequestPolicyAllowed) { al.Subject.SerialNumber = nil }})
		}
		if d.isCA {
			targets = append(targets, target{"isCA", func(al *policyapi.CertificateRequestPolicyAllowed) { al.IsCA = nil }})
		}
		if len(d.usages) > 0 {
			targets = append(targets, target{"usages", func(al *policyapi.CertificateRequestPolicyAllowed) { al.Usages = nil }})
		}
		// Iterate the field map in sorted order: the drawn index below must
		// refer to the same field on every replay for shrinking to work.
		fields := d.fields()
		for _, name := range slices.Sorted(maps.Keys(fields)) {
			f := fields[name]
			if len(f.values) == 0 {
				continue
			}
			set := f.set
			targets = append(targets, target{name, func(al *policyapi.CertificateRequestPolicyAllowed) { set(al, nil) }})
		}
		ht.Assume(len(targets) > 0)

		pick := hegel.Draw(ht, hegel.Integers(0, len(targets)-1))

		policy := identityPolicy(d)
		targets[pick].drop(policy.Spec.Allowed)

		resp, err := a.Evaluate(t.Context(), policy, d.request)
		if err != nil {
			ht.Fatalf("unexpected error: %v", err)
		}
		if resp.Result != approver.ResultDenied {
			ht.Fatalf("dropped allowance for %q but request was not denied", targets[pick].name)
		}
		if !strings.Contains(resp.Message, targets[pick].name) {
			ht.Fatalf("denial message does not name %q: %s", targets[pick].name, resp.Message)
		}
	}, hegel.WithTestCases(500))
}

// TestEvaluateWildcardPolicyNotDenied: the fully permissive policy (every
// attribute allowed by "*", isCA true, usages ["*"]) must not deny any
// well-formed request.
func TestEvaluateWildcardPolicyNotDenied(t *testing.T) {
	a := Approver().(allowed)
	star := &policyapi.CertificateRequestPolicyAllowedString{Value: ptr.To("*")}
	starSlice := &policyapi.CertificateRequestPolicyAllowedStringSlice{Values: ptr.To([]string{"*"})}
	policy := &policyapi.CertificateRequestPolicy{Spec: policyapi.CertificateRequestPolicySpec{
		Allowed: &policyapi.CertificateRequestPolicyAllowed{
			CommonName:     star,
			DNSNames:       starSlice,
			IPAddresses:    starSlice,
			URIs:           starSlice,
			EmailAddresses: starSlice,
			IsCA:           ptr.To(true),
			Usages:         ptr.To([]cmapi.KeyUsage{"*"}),
			Subject: &policyapi.CertificateRequestPolicyAllowedX509Subject{
				Organizations:       starSlice,
				Countries:           starSlice,
				OrganizationalUnits: starSlice,
				Localities:          starSlice,
				Provinces:           starSlice,
				StreetAddresses:     starSlice,
				PostalCodes:         starSlice,
				SerialNumber:        star,
			},
		},
	}}
	hegel.Test(t, func(ht *hegel.T) {
		d := drawRequest(ht, t)
		resp, err := a.Evaluate(t.Context(), policy, d.request)
		if err != nil {
			ht.Fatalf("unexpected error: %v", err)
		}
		if resp.Result != approver.ResultNotDenied {
			ht.Fatalf("wildcard policy denied request: %s", resp.Message)
		}
	}, hegel.WithTestCases(300))
}

// TestEvaluateNeverPanicsOnMalformedCSR: whatever bytes arrive in
// spec.request — truncated, bit-flipped or arbitrary PEM payloads — Evaluate
// must return a response or an error, never panic. CertificateRequests are
// created by arbitrary cluster users, so this is a trust boundary.
func TestEvaluateNeverPanicsOnMalformedCSR(t *testing.T) {
	a := Approver().(allowed)
	valid := csrFrom(t, gen.SetCSRCommonName("hello"), gen.SetCSRDNSNames("example.com"))
	policy := &policyapi.CertificateRequestPolicy{Spec: policyapi.CertificateRequestPolicySpec{
		Allowed: &policyapi.CertificateRequestPolicyAllowed{
			CommonName: &policyapi.CertificateRequestPolicyAllowedString{Value: ptr.To("*")},
		},
	}}

	hegel.Test(t, func(ht *hegel.T) {
		csr := append([]byte(nil), valid...)
		switch hegel.Draw(ht, hegel.Integers(0, 2)) {
		case 0: // truncate
			csr = csr[:hegel.Draw(ht, hegel.Integers(0, len(csr)))]
		case 1: // flip some bytes
			for range hegel.Draw(ht, hegel.Integers(1, 8)) {
				i := hegel.Draw(ht, hegel.Integers(0, len(csr)-1))
				csr[i] ^= byte(hegel.Draw(ht, hegel.Integers(1, 255)))
			}
		case 2: // arbitrary bytes
			csr = hegel.Draw(ht, hegel.Binary(0, 200))
		}
		request := gen.CertificateRequest("", gen.SetCertificateRequestCSR(csr))

		defer func() {
			if r := recover(); r != nil {
				ht.Fatalf("Evaluate panicked on csr %x: %v", csr, r)
			}
		}()
		if _, err := a.Evaluate(t.Context(), policy, request); err != nil {
			return // rejected: fine
		}
	}, hegel.WithTestCases(1000))
}
