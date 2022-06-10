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

	"k8s.io/apimachinery/pkg/util/validation/field"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
)

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
		if stringSlice.slice != nil && stringSlice.slice.Required != nil && *stringSlice.slice.Required && stringSlice.slice.Values == nil {
			el = append(el, field.Required(stringSlice.path.Child("values"), "values must be defined if required field"))
		}
	}

	for _, stringI := range strings {
		if stringI.string != nil && stringI.string.Required != nil && *stringI.string.Required && stringI.string.Value == nil {
			el = append(el, field.Required(stringI.path.Child("value"), "value must be defined if required field"))
		}
	}

	return approver.WebhookValidationResponse{
		Allowed: len(el) == 0,
		Errors:  el,
	}, nil
}
