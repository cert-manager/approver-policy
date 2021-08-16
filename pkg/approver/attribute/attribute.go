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

package attribute

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"net/url"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	utilpki "github.com/jetstack/cert-manager/pkg/util/pki"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	cmpapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/pkg/approver"
	"github.com/cert-manager/policy-approver/pkg/approver/attribute/internal"
	"github.com/cert-manager/policy-approver/pkg/registry"
)

// Load the attribute evaluator checks.
func init() {
	registry.Shared.Store(attribute{})
}

var _ approver.Interface = attribute{}

// attribute is the "default" Approver that is responsible for the base fields
// on the CertificateRequestPolicy. It is expected that attribute must _always_
// be registered for all policy-approvers.
type attribute struct{}

type checkStrategy int

const (
	checkString checkStrategy = iota
	checkStringSlice
	checkBool
	checkIPs
	checkURLs
	checkUsages
	checkMinDur
	checkMaxDur
	checkMinSize
	checkMaxSize
	checkKeyAlg
)

// check holds the json path to this field, the policy enforced on the field,
// and the requested value.
type check struct {
	path     string
	policy   interface{}
	request  interface{}
	strategy checkStrategy
}

// Evaluate evaluates whether the given CertificateRequest passes the 'chain
// checks' of the CertificateRequestPolicy.
// If this request is denied by these checks then a string explanation is
// returned.
// An error signals that the policy couldn't be evaluated to completion.
func (b attribute) Evaluate(_ context.Context, policy *cmpapi.CertificateRequestPolicy, cr *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
	chain, err := buildChecks(policy, cr)
	if err != nil {
		return approver.EvaluationResponse{}, err
	}

	// el will contain a list of policy violations for fields, if there are
	// items in the list, then the CR is not approved
	var el field.ErrorList

	path := field.NewPath("spec")
	for _, check := range chain {
		switch check.strategy {
		case checkString:
			internal.String(&el, path.Child(check.path), check.policy.(*string), check.request.(string))
		case checkStringSlice:
			internal.StringSlice(&el, path.Child(check.path), check.policy.(*[]string), check.request.([]string))
		case checkBool:
			internal.Bool(&el, path.Child(check.path), check.policy.(*bool), check.request.(bool))
		case checkIPs:
			internal.IPSlice(&el, path.Child(check.path), check.policy.(*[]string), check.request.([]net.IP))
		case checkURLs:
			internal.URLSlice(&el, path.Child(check.path), check.policy.(*[]string), check.request.([]*url.URL))
		case checkUsages:
			internal.KeyUsageSlice(&el, path.Child(check.path), check.policy.(*[]cmapi.KeyUsage), check.request.([]cmapi.KeyUsage))
		case checkMinDur:
			internal.MinDuration(&el, path.Child(check.path), check.policy.(*metav1.Duration), check.request.(*metav1.Duration))
		case checkMaxDur:
			internal.MaxDuration(&el, path.Child(check.path), check.policy.(*metav1.Duration), check.request.(*metav1.Duration))
		case checkMinSize:
			internal.MinSize(&el, path.Child(check.path), check.policy.(*int), check.request.(int))
		case checkMaxSize:
			internal.MaxSize(&el, path.Child(check.path), check.policy.(*int), check.request.(int))
		case checkKeyAlg:
			internal.KeyAlgorithm(&el, path.Child(check.path), check.policy.(*cmapi.PrivateKeyAlgorithm), check.request.(cmapi.PrivateKeyAlgorithm))
		default:
			return approver.EvaluationResponse{}, fmt.Errorf("unrecognised strategy %v: %s", check.strategy, check.path)
		}
	}

	// If there are errors, then return not approved and the aggregated errors
	if len(el) > 0 {
		return approver.EvaluationResponse{Result: approver.ResultDenied, Message: el.ToAggregate().Error()}, nil
	}

	// If no evaluation errors resulting from this policy, return not denied
	return approver.EvaluationResponse{Result: approver.ResultNotDenied}, nil
}

func buildChecks(policy *cmpapi.CertificateRequestPolicy, cr *cmapi.CertificateRequest) ([]check, error) {
	// decode CSR from CertificateRequest
	csr, err := utilpki.DecodeX509CertificateRequestBytes(cr.Spec.Request)
	if err != nil {
		return nil, err
	}

	var chain []check

	// If spec.allowedSubject is not nil, check all subjects.
	if policy := policy.Spec.AllowedSubject; policy != nil {
		subject := csr.Subject

		chain = append(chain, []check{
			{"allowedSubject.allowedOrganizations", policy.AllowedOrganizations, subject.Organization, checkStringSlice},
			{"allowedSubject.allowedCountries", policy.AllowedCountries, subject.Country, checkStringSlice},
			{"allowedSubject.allowedOrganizationalUnits", policy.AllowedOrganizationalUnits, subject.OrganizationalUnit, checkStringSlice},
			{"allowedSubject.allowedLocalities", policy.AllowedLocalities, subject.Locality, checkStringSlice},
			{"allowedSubject.allowedProvinces", policy.AllowedProvinces, subject.Province, checkStringSlice},
			{"allowedSubject.allowedStreetAddresses", policy.AllowedStreetAddresses, subject.StreetAddress, checkStringSlice},
			{"allowedSubject.allowedPostalCodes", policy.AllowedPostalCodes, subject.PostalCode, checkStringSlice},
			{"allowedSubject.allowedSerialNumber", policy.AllowedSerialNumber, subject.SerialNumber, checkStringSlice},
		}...)
	}

	// Adds checks for all fields in CertificateRequestPolicy spec
	chain = append(chain, []check{
		{"allowedCommonName", policy.Spec.AllowedCommonName, csr.Subject.CommonName, checkString},
		{"minDuration", policy.Spec.MinDuration, cr.Spec.Duration, checkMinDur},
		{"maxDuration", policy.Spec.MaxDuration, cr.Spec.Duration, checkMaxDur},
		{"allowedDNSNames", policy.Spec.AllowedDNSNames, csr.DNSNames, checkStringSlice},
		{"allowedIPAddresses", policy.Spec.AllowedIPAddresses, csr.IPAddresses, checkIPs},
		{"allowedURIs", policy.Spec.AllowedURIs, csr.URIs, checkURLs},
		{"allowedEmailAddresses", policy.Spec.AllowedEmailAddresses, csr.EmailAddresses, checkStringSlice},
		{"allowedIsCA", policy.Spec.AllowedIsCA, cr.Spec.IsCA, checkBool},
		// TODO: append x509 encoded usages
		{"allowedKeyUsages", policy.Spec.AllowedUsages, cr.Spec.Usages, checkUsages},
	}...)

	// If spec.allowedPrivateKey is not nil, check private key.
	if policy := policy.Spec.AllowedPrivateKey; policy != nil {
		alg, size, err := parsePublicKey(csr.PublicKey)
		if err != nil {
			return nil, err
		}

		chain = append(chain, []check{
			{"allowedPrivateKey.allowedAlgorithm", policy.AllowedAlgorithm, alg, checkKeyAlg},
			{"allowedPrivateKey.minSize", policy.MinSize, size, checkMinSize},
			{"allowedPrivateKey.maxSize", policy.MaxSize, size, checkMaxSize},
		}...)
	}

	return chain, nil
}

var (
	parseKeyError = errors.New("failed to parse public key")
)

// parsePublicKey will return the algorithm and size of the given public key.
// If the public key cannot be decoded, returns error.
func parsePublicKey(pub interface{}) (cmapi.PrivateKeyAlgorithm, int, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		rsapub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return "", -1, parseKeyError
		}
		return cmapi.RSAKeyAlgorithm, rsapub.Size(), nil
	case *ecdsa.PublicKey:
		ecdsapub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return "", -1, parseKeyError
		}
		return cmapi.ECDSAKeyAlgorithm, ecdsapub.Curve.Params().BitSize, nil
	default:
		return "", -1, parseKeyError
	}
}
