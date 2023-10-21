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
	"crypto/x509"
	"crypto/x509/pkix"
	"strconv"
	"strings"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"k8s.io/apimachinery/pkg/util/validation/field"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/internal/util"
)

// Evaluate evaluates whether the given CertificateRequest conforms to the
// allowed attributes defined in the policy. The request _must_ conform to
// _all_ allowed attributes in the policy to be permitted by the passed policy.
// If the request is denied by the allowed attributes an explanation is
// returned.
// An error signals that the policy couldn't be evaluated to completion.
func (a allowed) Evaluate(_ context.Context, policy *policyapi.CertificateRequestPolicy, request *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
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

	evaluate := evaluator{
		request: request,
		csr:     csr,
		allowed: allowed,
		fldPath: fldPath,
	}
	evaluateSubject := evaluate.Subject()

	evaluateFns := []func() field.ErrorList{
		evaluate.CommonName,
		evaluate.DNSNames,
		evaluate.IPAddresses,
		evaluate.URIs,
		evaluate.EmailAddresses,
		evaluate.IsCA,
		evaluate.Usages,
		evaluateSubject.Organization,
		evaluateSubject.Country,
		evaluateSubject.OrganizationalUnit,
		evaluateSubject.Locality,
		evaluateSubject.Province,
		evaluateSubject.StreetAddress,
		evaluateSubject.PostalCode,
		evaluateSubject.SerialNumber,
	}
	for _, fn := range evaluateFns {
		if e := fn(); e != nil {
			el = append(el, e...)
		}
	}

	// If there are errors, then return not approved and the aggregated errors
	if len(el) > 0 {
		return approver.EvaluationResponse{Result: approver.ResultDenied, Message: el.ToAggregate().Error()}, nil
	}

	// If no evaluation errors resulting from this policy, return not denied
	return approver.EvaluationResponse{Result: approver.ResultNotDenied}, nil
}

type evaluator struct {
	request *cmapi.CertificateRequest
	csr     *x509.CertificateRequest
	allowed *policyapi.CertificateRequestPolicyAllowed
	fldPath *field.Path
}

func (e evaluator) CommonName() field.ErrorList {
	return evaluateString(e.csr.Subject.CommonName, e.allowed.CommonName, e.fldPath.Child("commonName"))
}

func (e evaluator) DNSNames() field.ErrorList {
	return evaluateSlice(e.csr.DNSNames, e.allowed.DNSNames, e.fldPath.Child("dnsNames"))
}

func (e evaluator) IPAddresses() field.ErrorList {
	var ips []string
	for _, ip := range e.csr.IPAddresses {
		ips = append(ips, ip.String())
	}
	return evaluateSlice(ips, e.allowed.IPAddresses, e.fldPath.Child("ipAddresses"))
}

func (e evaluator) URIs() field.ErrorList {
	var uris []string
	for _, uri := range e.csr.URIs {
		uris = append(uris, uri.String())
	}
	return evaluateSlice(uris, e.allowed.URIs, e.fldPath.Child("uris"))
}

func (e evaluator) EmailAddresses() field.ErrorList {
	return evaluateSlice(e.csr.EmailAddresses, e.allowed.EmailAddresses, e.fldPath.Child("emailAddresses"))
}

func (e evaluator) IsCA() field.ErrorList {
	return evaluateBool(e.request.Spec.IsCA, e.allowed.IsCA, e.fldPath.Child("isCA"))
}

func (e evaluator) Usages() field.ErrorList {
	var el field.ErrorList
	if len(e.request.Spec.Usages) > 0 {
		var requestUsages []string
		for _, usage := range e.request.Spec.Usages {
			requestUsages = append(requestUsages, string(usage))
		}
		if e.allowed.Usages == nil {
			el = append(el, field.Invalid(e.fldPath.Child("usages"), requestUsages, "nil"))
		} else {
			var policyUsages []string
			for _, usage := range *e.allowed.Usages {
				policyUsages = append(policyUsages, string(usage))
			}
			if !util.WildcardSubset(policyUsages, requestUsages) {
				el = append(el, field.Invalid(e.fldPath.Child("usages"), requestUsages, strings.Join(policyUsages, ", ")))
			}
		}
	}
	return el
}

func (e evaluator) Subject() subjectEvaluator {
	allowed := e.allowed.Subject
	if allowed == nil {
		allowed = new(policyapi.CertificateRequestPolicyAllowedX509Subject)
	}
	return subjectEvaluator{
		sub:     e.csr.Subject,
		allowed: allowed,
		fldPath: e.fldPath.Child("subject"),
	}
}

type subjectEvaluator struct {
	sub     pkix.Name
	allowed *policyapi.CertificateRequestPolicyAllowedX509Subject
	fldPath *field.Path
}

func (e subjectEvaluator) Organization() field.ErrorList {
	return evaluateSlice(e.sub.Organization, e.allowed.Organizations, e.fldPath.Child("organizations"))
}

func (e subjectEvaluator) Country() field.ErrorList {
	return evaluateSlice(e.sub.Country, e.allowed.Countries, e.fldPath.Child("countries"))
}

func (e subjectEvaluator) OrganizationalUnit() field.ErrorList {
	return evaluateSlice(e.sub.OrganizationalUnit, e.allowed.OrganizationalUnits, e.fldPath.Child("organizationalUnits"))
}

func (e subjectEvaluator) Locality() field.ErrorList {
	return evaluateSlice(e.sub.Locality, e.allowed.Localities, e.fldPath.Child("localities"))
}

func (e subjectEvaluator) Province() field.ErrorList {
	return evaluateSlice(e.sub.Province, e.allowed.Provinces, e.fldPath.Child("provinces"))
}

func (e subjectEvaluator) StreetAddress() field.ErrorList {
	return evaluateSlice(e.sub.StreetAddress, e.allowed.StreetAddresses, e.fldPath.Child("streetAddresses"))
}

func (e subjectEvaluator) PostalCode() field.ErrorList {
	return evaluateSlice(e.sub.PostalCode, e.allowed.PostalCodes, e.fldPath.Child("postalCodes"))
}

func (e subjectEvaluator) SerialNumber() field.ErrorList {
	return evaluateString(e.sub.SerialNumber, e.allowed.SerialNumber, e.fldPath.Child("serialNumber"))
}

func evaluateString(s string, crp *policyapi.CertificateRequestPolicyAllowedString, fldPath *field.Path) field.ErrorList {
	var el field.ErrorList
	if len(s) > 0 {
		if crp == nil || crp.Value == nil {
			el = append(el, field.Invalid(fldPath.Child("value"), s, "nil"))
		} else if !util.WildcardMatches(*crp.Value, s) {
			el = append(el, field.Invalid(fldPath.Child("value"), s, *crp.Value))
		}
	} else if crp != nil && crp.Required != nil && *crp.Required {
		el = append(el, field.Required(fldPath.Child("required"), strconv.FormatBool(*crp.Required)))
	}
	return el
}

func evaluateSlice(s []string, crp *policyapi.CertificateRequestPolicyAllowedStringSlice, fldPath *field.Path) field.ErrorList {
	var el field.ErrorList
	if len(s) > 0 {
		if crp == nil || crp.Values == nil {
			el = append(el, field.Invalid(fldPath.Child("values"), s, "nil"))
		} else if !util.WildcardSubset(*crp.Values, s) {
			el = append(el, field.Invalid(fldPath.Child("values"), s, strings.Join(*crp.Values, ", ")))
		}
	} else if crp != nil && crp.Required != nil && *crp.Required {
		el = append(el, field.Required(fldPath.Child("required"), strconv.FormatBool(*crp.Required)))
	}
	return el
}

func evaluateBool(b bool, crp *bool, fldPath *field.Path) field.ErrorList {
	var el field.ErrorList
	if b {
		if crp == nil {
			el = append(el, field.Invalid(fldPath, b, "nil"))
		} else if !*crp {
			el = append(el, field.Invalid(fldPath, b, strconv.FormatBool(*crp)))
		}
	}
	return el
}
