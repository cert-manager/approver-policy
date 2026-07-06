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

package allowed

import (
	"context"

	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"k8s.io/apimachinery/pkg/util/validation/field"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
)

// validateOID returns a field error (or nil) for a policy-supplied dotted OID
// string. It must be a valid, canonical ASN.1 OID — evaluation matches it by
// exact string against the request's parsed OID (always canonical), so a
// malformed or non-canonical form would silently never match. Canonical means
// asn1.ObjectIdentifier round-trips to the same string.
func validateOID(path *field.Path, oid string) *field.Error {
	parsed, err := utilpki.ParseObjectIdentifier(oid)
	if err != nil || parsed.String() != oid {
		return field.Invalid(path, oid, "must be a valid, canonical dotted ASN.1 object identifier (e.g. \"1.3.6.1.4.1.311.20.2.3\")")
	}
	for _, arc := range parsed {
		if arc < 0 {
			return field.Invalid(path, oid, "OID arcs must be non-negative")
		}
	}
	return nil
}

// Validate validates that the processed CertificateRequestPolicy has valid
// allowed fields defined and there are no parsing errors in the values.
func (a allowed) Validate(_ context.Context, policy *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
	// If no allowed fields are defined we can exit early
	if policy.Spec.Allowed == nil {
		return approver.WebhookValidationResponse{
			Allowed: true,
			Errors:  nil,
		}, nil
	}

	var (
		el      field.ErrorList
		allowed = policy.Spec.Allowed
		fldPath = field.NewPath("spec", "allowed")
	)

	type stringSlicePair struct {
		path  *field.Path
		slice *policyapi.CertificateRequestPolicyAllowedStringSlice
	}
	stringSlices := []stringSlicePair{
		{fldPath.Child("dnsNames"), allowed.DNSNames},
		{fldPath.Child("ipAddresses"), allowed.IPAddresses},
		{fldPath.Child("uris"), allowed.URIs},
		{fldPath.Child("emailAddresses"), allowed.EmailAddresses},
	}

	type stringPair struct {
		path   *field.Path
		string *policyapi.CertificateRequestPolicyAllowedString
	}
	strings := []stringPair{
		{fldPath.Child("commonName"), allowed.CommonName},
	}

	if allowedSub := allowed.Subject; allowedSub != nil {
		fldPathSub := fldPath.Child("subject")

		stringSlices = append(stringSlices, stringSlicePair{fldPathSub.Child("organizations"), allowedSub.Organizations})
		stringSlices = append(stringSlices, stringSlicePair{fldPathSub.Child("countries"), allowedSub.Countries})
		stringSlices = append(stringSlices, stringSlicePair{fldPathSub.Child("organizationalUnits"), allowedSub.OrganizationalUnits})
		stringSlices = append(stringSlices, stringSlicePair{fldPathSub.Child("localities"), allowedSub.Localities})
		stringSlices = append(stringSlices, stringSlicePair{fldPathSub.Child("provinces"), allowedSub.Provinces})
		stringSlices = append(stringSlices, stringSlicePair{fldPathSub.Child("streetAddresses"), allowedSub.StreetAddresses})
		stringSlices = append(stringSlices, stringSlicePair{fldPathSub.Child("postalCodes"), allowedSub.PostalCodes})

		strings = append(strings, stringPair{fldPathSub.Child("serialNumber"), allowedSub.SerialNumber})
	}

	for _, stringSlice := range stringSlices {
		if stringSlice.slice != nil {
			if stringSlice.slice.Required != nil && *stringSlice.slice.Required {
				if stringSlice.slice.Values == nil && len(stringSlice.slice.Validations) == 0 {
					el = append(el, field.Required(stringSlice.path.Child("values"), "at least one of 'values' or 'validations' must be defined if field is 'required'"))
				}
			}
			for i, validation := range stringSlice.slice.Validations {
				if _, err := a.validators.Get(validation.Rule); err != nil {
					el = append(el, field.Invalid(stringSlice.path.Child("validations").Index(i), validation.Rule, err.Error()))
				}
			}
		}
	}

	for _, stringI := range strings {
		if stringI.string != nil {
			if stringI.string.Required != nil && *stringI.string.Required {
				if stringI.string.Value == nil && len(stringI.string.Validations) == 0 {
					el = append(el, field.Required(stringI.path.Child("value"), "at least one of 'value' or 'validations' must be defined if field is 'required'"))
				}
			}
			for i, validation := range stringI.string.Validations {
				if _, err := a.validators.Get(validation.Rule); err != nil {
					el = append(el, field.Invalid(stringI.path.Child("validations").Index(i), validation.Rule, err.Error()))
				}
			}
		}
	}

	// allowed.otherNames mirrors the values/required/validations semantics of
	// the named slice fields, so apply the same admission checks: a 'required'
	// entry must declare values or validations, and every CEL rule must
	// compile. Without this, an invalid CEL rule would be admitted and only
	// surface as a confusing runtime error at request-evaluation time.
	otherNamesPath := fldPath.Child("otherNames")
	for i := range allowed.OtherNames {
		entry := allowed.OtherNames[i]
		path := otherNamesPath.Index(i)
		if e := validateOID(path.Child("oid"), entry.OID); e != nil {
			el = append(el, e)
		}
		if entry.Required != nil && *entry.Required {
			if entry.Values == nil && len(entry.Validations) == 0 {
				el = append(el, field.Required(path.Child("values"), "at least one of 'values' or 'validations' must be defined if field is 'required'"))
			}
		}
		for j, validation := range entry.Validations {
			if _, err := a.validators.Get(validation.Rule); err != nil {
				el = append(el, field.Invalid(path.Child("validations").Index(j), validation.Rule, err.Error()))
			}
		}
	}

	// allowed.subject.otherAttributes mirrors the values/required/validations
	// semantics of the named slice fields, so apply the same admission checks:
	// a 'required' entry must declare values or validations, and every CEL rule
	// must compile. Without this, an invalid CEL rule would be admitted and only
	// surface as a confusing runtime error at request-evaluation time.
	if allowed.Subject != nil {
		otherAttrsPath := fldPath.Child("subject").Child("otherAttributes")
		for i := range allowed.Subject.OtherAttributes {
			entry := allowed.Subject.OtherAttributes[i]
			path := otherAttrsPath.Index(i)
			// The OID must be valid/canonical, and must not duplicate a named
			// Subject field: the evaluator routes named OIDs to the dedicated
			// allowed.subject.* / allowed.commonName fields and never marks
			// them present here, so a named OID in otherAttributes is a dead
			// entry (with values) or an impossible-to-satisfy policy (with
			// required). Reject it at admission so the author uses the right
			// field.
			if e := validateOID(path.Child("oid"), entry.OID); e != nil {
				el = append(el, e)
			} else if parsed, _ := utilpki.ParseObjectIdentifier(entry.OID); isNamedSubjectOID(parsed) {
				el = append(el, field.Invalid(path.Child("oid"), entry.OID,
					"this OID is covered by a dedicated allowed.commonName / allowed.subject.* field; configure it there instead of otherAttributes"))
			}
			if entry.Required != nil && *entry.Required {
				if entry.Values == nil && len(entry.Validations) == 0 {
					el = append(el, field.Required(path.Child("values"), "at least one of 'values' or 'validations' must be defined if field is 'required'"))
				}
			}
			for j, validation := range entry.Validations {
				if _, err := a.validators.Get(validation.Rule); err != nil {
					el = append(el, field.Invalid(path.Child("validations").Index(j), validation.Rule, err.Error()))
				}
			}
		}
	}

	return approver.WebhookValidationResponse{
		Allowed: len(el) == 0,
		Errors:  el,
	}, nil
}
