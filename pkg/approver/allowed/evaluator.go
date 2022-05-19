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
	"strconv"
	"strings"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"k8s.io/apimachinery/pkg/util/validation/field"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/approver/internal"
)

// Evaluate evaluates whether the given CertificateRequest conforms to the
// allowed attributes defined in the policy. The request _must_ conform to
// _all_ allowed attributes in the policy to be permitted by the passed policy.
// If the request is denied by the allowed attributes an explanation is
// returned.
// An error signals that the policy couldn't be evaluated to completion.
func (a Allowed) Evaluate(_ context.Context, policy *policyapi.CertificateRequestPolicy, request *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
	var (
		// el will contain a list of policy violations for fields, if there are
		// items in the list, then the request does not meet the allowed
		// attributes.
		el      field.ErrorList
		allowed = policy.Spec.Allowed
		fldPath = field.NewPath("spec", "allowed")
	)

	if allowed == nil {
		allowed = new(policyapi.CertificateRequestPolicyAllowed)
	}

	csr, err := utilpki.DecodeX509CertificateRequestBytes(request.Spec.Request)
	if err != nil {
		return approver.EvaluationResponse{}, err
	}

	if len(csr.Subject.CommonName) > 0 {
		if allowed.CommonName == nil || allowed.CommonName.Value == nil {
			el = append(el, field.Invalid(fldPath.Child("commonName", "value"), csr.Subject.CommonName, "nil"))
		} else if !internal.WildcardMatchs(*allowed.CommonName.Value, csr.Subject.CommonName) {
			el = append(el, field.Invalid(fldPath.Child("commonName", "value"), csr.Subject.CommonName, *allowed.CommonName.Value))
		}
	} else if allowed.CommonName != nil && allowed.CommonName.Required != nil && *allowed.CommonName.Required {
		el = append(el, field.Required(fldPath.Child("commonName", "required"), strconv.FormatBool(*allowed.CommonName.Required)))
	}

	if len(csr.DNSNames) > 0 {
		if allowed.DNSNames == nil || allowed.DNSNames.Values == nil {
			el = append(el, field.Invalid(fldPath.Child("dnsNames", "values"), csr.DNSNames, "nil"))
		} else if !internal.WildcardSubset(*allowed.DNSNames.Values, csr.DNSNames) {
			el = append(el, field.Invalid(fldPath.Child("dnsNames", "values"), csr.DNSNames, strings.Join(*allowed.DNSNames.Values, ", ")))
		}
	} else if allowed.DNSNames != nil && allowed.DNSNames.Required != nil && *allowed.DNSNames.Required {
		el = append(el, field.Required(fldPath.Child("dnsNames", "required"), strconv.FormatBool(*allowed.DNSNames.Required)))
	}

	if len(csr.IPAddresses) > 0 {
		var ips []string
		for _, ip := range csr.IPAddresses {
			ips = append(ips, ip.String())
		}
		if allowed.IPAddresses == nil || allowed.IPAddresses.Values == nil {
			el = append(el, field.Invalid(fldPath.Child("ipAddresses", "values"), ips, "nil"))
		} else if !internal.WildcardSubset(*allowed.IPAddresses.Values, ips) {
			el = append(el, field.Invalid(fldPath.Child("ipAddresses", "values"), ips, strings.Join(*allowed.IPAddresses.Values, ", ")))
		}
	} else if allowed.IPAddresses != nil && allowed.IPAddresses.Required != nil && *allowed.IPAddresses.Required {
		el = append(el, field.Required(fldPath.Child("ipAddresses", "required"), strconv.FormatBool(*allowed.IPAddresses.Required)))
	}

	if len(csr.URIs) > 0 {
		var uris []string
		for _, uri := range csr.URIs {
			uris = append(uris, uri.String())
		}
		if allowed.URIs == nil || allowed.URIs.Values == nil {
			el = append(el, field.Invalid(fldPath.Child("uris", "values"), uris, "nil"))
		} else if !internal.WildcardSubset(*allowed.URIs.Values, uris) {
			el = append(el, field.Invalid(fldPath.Child("uris", "values"), uris, strings.Join(*allowed.URIs.Values, ", ")))
		}
	} else if allowed.URIs != nil && allowed.URIs.Required != nil && *allowed.URIs.Required {
		el = append(el, field.Required(fldPath.Child("uris", "required"), strconv.FormatBool(*allowed.URIs.Required)))
	}

	if len(csr.EmailAddresses) > 0 {
		if allowed.EmailAddresses == nil || allowed.EmailAddresses.Values == nil {
			el = append(el, field.Invalid(fldPath.Child("emailAddresses", "values"), csr.EmailAddresses, "nil"))
		} else if !internal.WildcardSubset(*allowed.EmailAddresses.Values, csr.EmailAddresses) {
			el = append(el, field.Invalid(fldPath.Child("emailAddresses", "values"), csr.EmailAddresses, strings.Join(*allowed.EmailAddresses.Values, ", ")))
		}
	} else if allowed.EmailAddresses != nil && allowed.EmailAddresses.Required != nil && *allowed.EmailAddresses.Required {
		el = append(el, field.Required(fldPath.Child("emailAddresses", "required"), strconv.FormatBool(*allowed.EmailAddresses.Required)))
	}

	if request.Spec.IsCA {
		if allowed.IsCA == nil {
			el = append(el, field.Invalid(fldPath.Child("isCA"), request.Spec.IsCA, "nil"))
		} else if !*allowed.IsCA {
			el = append(el, field.Invalid(fldPath.Child("isCA"), request.Spec.IsCA, strconv.FormatBool(*allowed.IsCA)))
		}
	}

	if len(request.Spec.Usages) > 0 {
		var requestUsages []string
		for _, usage := range request.Spec.Usages {
			requestUsages = append(requestUsages, string(usage))
		}
		if allowed.Usages == nil {
			el = append(el, field.Invalid(fldPath.Child("usages"), requestUsages, "nil"))
		} else {
			var policyUsages []string
			for _, usage := range *allowed.Usages {
				policyUsages = append(policyUsages, string(usage))
			}
			if !internal.WildcardSubset(policyUsages, requestUsages) {
				el = append(el, field.Invalid(fldPath.Child("usages"), requestUsages, strings.Join(policyUsages, ", ")))
			}
		}
	}

	fldPath = fldPath.Child("subject")
	allowedSub := allowed.Subject

	if len(csr.Subject.Organization) > 0 {
		if allowedSub == nil || allowedSub.Organizations == nil || allowedSub.Organizations.Values == nil {
			el = append(el, field.Invalid(fldPath.Child("organizations", "values"), csr.Subject.Organization, "nil"))
		} else if !internal.WildcardSubset(*allowedSub.Organizations.Values, csr.Subject.Organization) {
			el = append(el, field.Invalid(fldPath.Child("organizations", "values"), csr.Subject.Organization, strings.Join(*allowedSub.Organizations.Values, ", ")))
		}
	} else if allowedSub != nil && allowedSub.Organizations != nil && allowedSub.Organizations.Required != nil && *allowedSub.Organizations.Required {
		el = append(el, field.Required(fldPath.Child("organizations", "required"), strconv.FormatBool(*allowedSub.Organizations.Required)))
	}

	if len(csr.Subject.Country) > 0 {
		if allowedSub == nil || allowedSub.Countries == nil {
			el = append(el, field.Invalid(fldPath.Child("countries", "values"), csr.Subject.Country, "nil"))
		} else if !internal.WildcardSubset(*allowedSub.Countries.Values, csr.Subject.Country) {
			el = append(el, field.Invalid(fldPath.Child("countries", "values"), csr.Subject.Country, strings.Join(*allowedSub.Countries.Values, ", ")))
		}
	} else if allowedSub != nil && allowedSub.Countries != nil && allowedSub.Countries.Required != nil && *allowedSub.Countries.Required {
		el = append(el, field.Required(fldPath.Child("countries", "required"), strconv.FormatBool(*allowedSub.Countries.Required)))
	}

	if len(csr.Subject.OrganizationalUnit) > 0 {
		if allowedSub == nil || allowedSub.OrganizationalUnits == nil {
			el = append(el, field.Invalid(fldPath.Child("organizationalUnits", "values"), csr.Subject.OrganizationalUnit, "nil"))
		} else if !internal.WildcardSubset(*allowedSub.OrganizationalUnits.Values, csr.Subject.OrganizationalUnit) {
			el = append(el, field.Invalid(fldPath.Child("organizationalUnits", "values"), csr.Subject.OrganizationalUnit, strings.Join(*allowedSub.OrganizationalUnits.Values, ", ")))
		}
	} else if allowedSub != nil && allowedSub.OrganizationalUnits != nil && allowedSub.OrganizationalUnits.Required != nil && *allowedSub.OrganizationalUnits.Required {
		el = append(el, field.Required(fldPath.Child("organizationalUnits", "required"), strconv.FormatBool(*allowedSub.OrganizationalUnits.Required)))
	}

	if len(csr.Subject.Locality) > 0 {
		if allowedSub == nil || allowedSub.Localities == nil {
			el = append(el, field.Invalid(fldPath.Child("localities", "values"), csr.Subject.Locality, "nil"))
		} else if !internal.WildcardSubset(*allowedSub.Localities.Values, csr.Subject.Locality) {
			el = append(el, field.Invalid(fldPath.Child("localities", "values"), csr.Subject.Locality, strings.Join(*allowedSub.Localities.Values, ", ")))
		}
	} else if allowedSub != nil && allowedSub.Localities != nil && allowedSub.Localities.Required != nil && *allowedSub.Localities.Required {
		el = append(el, field.Required(fldPath.Child("localities", "required"), strconv.FormatBool(*allowedSub.Localities.Required)))
	}

	if len(csr.Subject.Province) > 0 {
		if allowedSub == nil || allowedSub.Provinces == nil {
			el = append(el, field.Invalid(fldPath.Child("provinces", "values"), csr.Subject.Province, "nil"))
		} else if !internal.WildcardSubset(*allowedSub.Provinces.Values, csr.Subject.Province) {
			el = append(el, field.Invalid(fldPath.Child("provinces", "values"), csr.Subject.Province, strings.Join(*allowedSub.Provinces.Values, ", ")))
		}
	} else if allowedSub != nil && allowedSub.Provinces != nil && allowedSub.Provinces.Required != nil && *allowedSub.Provinces.Required {
		el = append(el, field.Required(fldPath.Child("provinces", "required"), strconv.FormatBool(*allowedSub.Provinces.Required)))
	}

	if len(csr.Subject.StreetAddress) > 0 {
		if allowedSub == nil || allowedSub.StreetAddresses == nil {
			el = append(el, field.Invalid(fldPath.Child("streetAddresses", "values"), csr.Subject.StreetAddress, "nil"))
		} else if !internal.WildcardSubset(*allowedSub.StreetAddresses.Values, csr.Subject.StreetAddress) {
			el = append(el, field.Invalid(fldPath.Child("streetAddresses", "values"), csr.Subject.StreetAddress, strings.Join(*allowedSub.StreetAddresses.Values, ", ")))
		}
	} else if allowedSub != nil && allowedSub.StreetAddresses != nil && allowedSub.StreetAddresses.Required != nil && *allowedSub.StreetAddresses.Required {
		el = append(el, field.Required(fldPath.Child("streetAddresses", "required"), strconv.FormatBool(*allowedSub.StreetAddresses.Required)))
	}

	if len(csr.Subject.PostalCode) > 0 {
		if allowedSub == nil || allowedSub.PostalCodes == nil {
			el = append(el, field.Invalid(fldPath.Child("postalCodes", "values"), csr.Subject.PostalCode, "nil"))
		} else if !internal.WildcardSubset(*allowedSub.PostalCodes.Values, csr.Subject.PostalCode) {
			el = append(el, field.Invalid(fldPath.Child("postalCodes", "values"), csr.Subject.PostalCode, strings.Join(*allowedSub.PostalCodes.Values, ", ")))
		}
	} else if allowedSub != nil && allowedSub.PostalCodes != nil && allowedSub.PostalCodes.Required != nil && *allowedSub.PostalCodes.Required {
		el = append(el, field.Required(fldPath.Child("postalCodes", "required"), strconv.FormatBool(*allowedSub.PostalCodes.Required)))
	}

	if len(csr.Subject.SerialNumber) > 0 {
		if allowedSub == nil || allowedSub.SerialNumber == nil {
			el = append(el, field.Invalid(fldPath.Child("serialNumber", "value"), csr.Subject.SerialNumber, "nil"))
		} else if !internal.WildcardMatchs(*allowedSub.SerialNumber.Value, csr.Subject.SerialNumber) {
			el = append(el, field.Invalid(fldPath.Child("serialNumber", "value"), csr.Subject.SerialNumber, *allowedSub.SerialNumber.Value))
		}
	} else if allowedSub != nil && allowedSub.SerialNumber != nil && allowedSub.SerialNumber.Required != nil && *allowedSub.SerialNumber.Required {
		el = append(el, field.Required(fldPath.Child("serialNumber", "required"), strconv.FormatBool(*allowedSub.SerialNumber.Required)))
	}

	// If there are errors, then return not approved and the aggregated errors
	if len(el) > 0 {
		return approver.EvaluationResponse{Result: approver.ResultDenied, Message: el.ToAggregate().Error()}, nil
	}

	// If no evaluation errors resulting from this policy, return not denied
	return approver.EvaluationResponse{Result: approver.ResultNotDenied}, nil
}
