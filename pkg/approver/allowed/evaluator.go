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

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	utilpki "github.com/jetstack/cert-manager/pkg/util/pki"
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
		if allowed.CommonName == nil {
			el = append(el, field.Invalid(fldPath.Child("commonName"), csr.Subject.CommonName, "nil"))
		} else if !internal.WildcardMatchs(*allowed.CommonName, csr.Subject.CommonName) {
			el = append(el, field.Invalid(fldPath.Child("commonName"), csr.Subject.CommonName, *allowed.CommonName))
		}
	}

	if len(csr.DNSNames) > 0 {
		if allowed.DNSNames == nil {
			el = append(el, field.Invalid(fldPath.Child("dnsNames"), csr.DNSNames, "nil"))
		} else if !internal.WildcardSubset(*allowed.DNSNames, csr.DNSNames) {
			el = append(el, field.Invalid(fldPath.Child("dnsNames"), csr.DNSNames, strings.Join(*allowed.DNSNames, ", ")))
		}
	}

	if len(csr.IPAddresses) > 0 {
		var ips []string
		for _, ip := range csr.IPAddresses {
			ips = append(ips, ip.String())
		}
		if allowed.IPAddresses == nil {
			el = append(el, field.Invalid(fldPath.Child("ipAddresses"), ips, "nil"))
		} else if !internal.WildcardSubset(*allowed.IPAddresses, ips) {
			el = append(el, field.Invalid(fldPath.Child("ipAddresses"), ips, strings.Join(*allowed.IPAddresses, ", ")))
		}
	}

	if len(csr.URIs) > 0 {
		var uris []string
		for _, uri := range csr.URIs {
			uris = append(uris, uri.String())
		}
		if allowed.URIs == nil {
			el = append(el, field.Invalid(fldPath.Child("uris"), uris, "nil"))
		} else if !internal.WildcardSubset(*allowed.URIs, uris) {
			el = append(el, field.Invalid(fldPath.Child("uris"), uris, strings.Join(*allowed.URIs, ", ")))
		}
	}

	if len(csr.EmailAddresses) > 0 {
		if allowed.EmailAddresses == nil {
			el = append(el, field.Invalid(fldPath.Child("emailAddresses"), csr.EmailAddresses, "nil"))
		} else if !internal.WildcardSubset(*allowed.EmailAddresses, csr.EmailAddresses) {
			el = append(el, field.Invalid(fldPath.Child("emailAddresses"), csr.EmailAddresses, strings.Join(*allowed.EmailAddresses, ", ")))
		}
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
		if allowedSub == nil || allowedSub.Organizations == nil {
			el = append(el, field.Invalid(fldPath.Child("organizations"), csr.Subject.Organization, "nil"))
		} else if !internal.WildcardSubset(*allowedSub.Organizations, csr.Subject.Organization) {
			el = append(el, field.Invalid(fldPath.Child("organizations"), csr.Subject.Organization, strings.Join(*allowedSub.Organizations, ", ")))
		}
	}

	if len(csr.Subject.Country) > 0 {
		if allowedSub == nil || allowedSub.Countries == nil {
			el = append(el, field.Invalid(fldPath.Child("countries"), csr.Subject.Country, "nil"))
		} else if !internal.WildcardSubset(*allowedSub.Countries, csr.Subject.Country) {
			el = append(el, field.Invalid(fldPath.Child("countries"), csr.Subject.Country, strings.Join(*allowedSub.Countries, ", ")))
		}
	}

	if len(csr.Subject.OrganizationalUnit) > 0 {
		if allowedSub == nil || allowedSub.OrganizationalUnits == nil {
			el = append(el, field.Invalid(fldPath.Child("organizationalUnits"), csr.Subject.OrganizationalUnit, "nil"))
		} else if !internal.WildcardSubset(*allowedSub.OrganizationalUnits, csr.Subject.OrganizationalUnit) {
			el = append(el, field.Invalid(fldPath.Child("organizationalUnits"), csr.Subject.OrganizationalUnit, strings.Join(*allowedSub.OrganizationalUnits, ", ")))
		}
	}

	if len(csr.Subject.Locality) > 0 {
		if allowedSub == nil || allowedSub.Localities == nil {
			el = append(el, field.Invalid(fldPath.Child("localities"), csr.Subject.Locality, "nil"))
		} else if !internal.WildcardSubset(*allowedSub.Localities, csr.Subject.Locality) {
			el = append(el, field.Invalid(fldPath.Child("localities"), csr.Subject.Locality, strings.Join(*allowedSub.Localities, ", ")))
		}
	}

	if len(csr.Subject.Province) > 0 {
		if allowedSub == nil || allowedSub.Provinces == nil {
			el = append(el, field.Invalid(fldPath.Child("provinces"), csr.Subject.Province, "nil"))
		} else if !internal.WildcardSubset(*allowedSub.Provinces, csr.Subject.Province) {
			el = append(el, field.Invalid(fldPath.Child("provinces"), csr.Subject.Province, strings.Join(*allowedSub.Provinces, ", ")))
		}
	}

	if len(csr.Subject.StreetAddress) > 0 {
		if allowedSub == nil || allowedSub.StreetAddresses == nil {
			el = append(el, field.Invalid(fldPath.Child("streetAddresses"), csr.Subject.StreetAddress, "nil"))
		} else if !internal.WildcardSubset(*allowedSub.StreetAddresses, csr.Subject.StreetAddress) {
			el = append(el, field.Invalid(fldPath.Child("streetAddresses"), csr.Subject.StreetAddress, strings.Join(*allowedSub.StreetAddresses, ", ")))
		}
	}

	if len(csr.Subject.PostalCode) > 0 {
		if allowedSub == nil || allowedSub.PostalCodes == nil {
			el = append(el, field.Invalid(fldPath.Child("postalCodes"), csr.Subject.PostalCode, "nil"))
		} else if !internal.WildcardSubset(*allowedSub.PostalCodes, csr.Subject.PostalCode) {
			el = append(el, field.Invalid(fldPath.Child("postalCodes"), csr.Subject.PostalCode, strings.Join(*allowedSub.PostalCodes, ", ")))
		}
	}

	if len(csr.Subject.SerialNumber) > 0 {
		if allowedSub == nil || allowedSub.SerialNumber == nil {
			el = append(el, field.Invalid(fldPath.Child("serialNumber"), csr.Subject.SerialNumber, "nil"))
		} else if !internal.WildcardMatchs(*allowedSub.SerialNumber, csr.Subject.SerialNumber) {
			el = append(el, field.Invalid(fldPath.Child("serialNumber"), csr.Subject.SerialNumber, *allowedSub.SerialNumber))
		}
	}

	// If there are errors, then return not approved and the aggregated errors
	if len(el) > 0 {
		return approver.EvaluationResponse{Result: approver.ResultDenied, Message: el.ToAggregate().Error()}, nil
	}

	// If no evaluation errors resulting from this policy, return not denied
	return approver.EvaluationResponse{Result: approver.ResultNotDenied}, nil
}
