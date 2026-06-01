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
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	utilpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
	"github.com/cert-manager/approver-policy/pkg/internal/util"
)

// Subject RDN attribute OIDs that are covered by a dedicated allowed.commonName
// or allowed.subject.* field. Any RDN attribute OID outside this set requires
// an explicit entry in allowed.subject.otherAttributes.
var (
	oidCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidSerialNumber       = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidCountry            = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidLocality           = asn1.ObjectIdentifier{2, 5, 4, 7}
	oidProvince           = asn1.ObjectIdentifier{2, 5, 4, 8}
	oidStreetAddress      = asn1.ObjectIdentifier{2, 5, 4, 9}
	oidOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidPostalCode         = asn1.ObjectIdentifier{2, 5, 4, 17}

	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// namedSubjectOIDs is the set of Subject RDN OIDs that correspond to a named
// allowed.commonName / allowed.subject.* field.
var namedSubjectOIDs = []asn1.ObjectIdentifier{
	oidCommonName, oidSerialNumber, oidCountry, oidLocality, oidProvince,
	oidStreetAddress, oidOrganization, oidOrganizationalUnit, oidPostalCode,
}

func isNamedSubjectOID(oid asn1.ObjectIdentifier) bool {
	for _, named := range namedSubjectOIDs {
		if oid.Equal(named) {
			return true
		}
	}
	return false
}

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

	// Decode the raw Subject DER directly so duplicate CN/SerialNumber RDNs
	// and unmapped attribute OIDs (e.g. emailAddress, DC, UID) — which the
	// lossy pkix.Name projection drops or silently overwrites — are visible
	// to policy. cert-manager copies csr.RawSubject verbatim into the issued
	// certificate, so the approver and signer must see the same bytes.
	var subjectRDNs pkix.RDNSequence
	if len(csr.RawSubject) > 0 {
		if _, err := asn1.Unmarshal(csr.RawSubject, &subjectRDNs); err != nil {
			return approver.EvaluationResponse{}, fmt.Errorf("decode csr.RawSubject: %w", err)
		}
	}

	// Decode the raw SAN extension directly so GeneralName entries with
	// context tags outside {1,2,6,7} (otherName, x400Address, directoryName,
	// ediPartyName, registeredID) — which crypto/x509 silently drops from
	// the parsed slices but which cert-manager copies into the issued
	// certificate verbatim — are visible to policy.
	var sanGNs []asn1.RawValue
	var sanPresent bool
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		sanPresent = true
		if _, err := asn1.Unmarshal(ext.Value, &sanGNs); err != nil {
			return approver.EvaluationResponse{}, fmt.Errorf("decode SAN extension: %w", err)
		}
		break
	}

	evaluate := evaluator{
		a:           a,
		request:     request,
		csr:         csr,
		subjectRDNs: subjectRDNs,
		sanGNs:      sanGNs,
		sanPresent:  sanPresent,
		allowed:     allowed,
		fldPath:     fldPath,
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
		evaluate.OtherNames,
		evaluateSubject.Organization,
		evaluateSubject.Country,
		evaluateSubject.OrganizationalUnit,
		evaluateSubject.Locality,
		evaluateSubject.Province,
		evaluateSubject.StreetAddress,
		evaluateSubject.PostalCode,
		evaluateSubject.SerialNumber,
		evaluateSubject.OtherAttributes,
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
	a       allowed
	request *cmapi.CertificateRequest
	csr     *x509.CertificateRequest
	// subjectRDNs is the full RDNSequence decoded directly from
	// csr.RawSubject — preserves duplicate CN/SerialNumber RDNs and
	// unmapped attribute OIDs that the lossy pkix.Name projection drops.
	subjectRDNs pkix.RDNSequence
	// sanGNs is the raw list of GeneralName entries from the SAN
	// extension — preserves otherName/directoryName/x400Address/
	// ediPartyName/registeredID entries that the lossy parsed slices
	// drop. sanPresent distinguishes "no SAN" from "SAN with no entries".
	sanGNs     []asn1.RawValue
	sanPresent bool
	allowed    *policyapi.CertificateRequestPolicyAllowed
	fldPath    *field.Path
}

// subjectValuesForOID returns every value associated with the given Subject
// RDN attribute OID across the full RDNSequence (not just the first/last
// match as the lossy pkix.Name projection does). Non-string values are
// hex-encoded so the existing string-based wildcard/CEL matchers can still
// reason about them. A boolean is returned alongside indicating whether
// every encountered value decoded to a string — operators reading audit logs
// should not see hex-encoded blobs and assume they were plain text.
func (e evaluator) subjectValuesForOID(oid asn1.ObjectIdentifier) (values []string, allStrings bool) {
	allStrings = true
	for _, rdn := range e.subjectRDNs {
		for _, atv := range rdn {
			if !atv.Type.Equal(oid) {
				continue
			}
			if s, ok := atv.Value.(string); ok {
				values = append(values, s)
				continue
			}
			allStrings = false
			values = append(values, fmt.Sprintf("<non-string %T>", atv.Value))
		}
	}
	return values, allStrings
}

// CommonName evaluates every CN RDN value present in csr.RawSubject against
// allowed.commonName. Multiple CN RDNs (a duplicate-CN smuggling attempt)
// trigger a separate error per value so the operator sees the full set.
func (e evaluator) CommonName() field.ErrorList {
	values, _ := e.subjectValuesForOID(oidCommonName)
	fldPath := e.fldPath.Child("commonName")
	switch len(values) {
	case 0:
		// Preserve the existing "required" semantics for the empty case.
		return e.a.evaluateString(e.request, "", e.allowed.CommonName, fldPath)
	case 1:
		return e.a.evaluateString(e.request, values[0], e.allowed.CommonName, fldPath)
	default:
		var el field.ErrorList
		for _, v := range values {
			el = append(el, e.a.evaluateString(e.request, v, e.allowed.CommonName, fldPath)...)
		}
		return el
	}
}

func (e evaluator) DNSNames() field.ErrorList {
	return e.a.evaluateSlice(e.request, e.csr.DNSNames, e.allowed.DNSNames, e.fldPath.Child("dnsNames"))
}

func (e evaluator) IPAddresses() field.ErrorList {
	var ips []string
	for _, ip := range e.csr.IPAddresses {
		ips = append(ips, ip.String())
	}
	return e.a.evaluateSlice(e.request, ips, e.allowed.IPAddresses, e.fldPath.Child("ipAddresses"))
}

func (e evaluator) URIs() field.ErrorList {
	var uris []string
	for _, uri := range e.csr.URIs {
		uris = append(uris, uri.String())
	}
	return e.a.evaluateSlice(e.request, uris, e.allowed.URIs, e.fldPath.Child("uris"))
}

func (e evaluator) EmailAddresses() field.ErrorList {
	return e.a.evaluateSlice(e.request, e.csr.EmailAddresses, e.allowed.EmailAddresses, e.fldPath.Child("emailAddresses"))
}

func (e evaluator) IsCA() field.ErrorList {
	return e.a.evaluateBool(e.request.Spec.IsCA, e.allowed.IsCA, e.fldPath.Child("isCA"))
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

// OtherNames evaluates every SAN GeneralName entry whose context tag is
// outside {1,2,6,7} (rfc822Name/dNSName/uniformResourceIdentifier/iPAddress —
// already covered by EmailAddresses/DNSNames/URIs/IPAddresses above).
// Tag 0 (otherName) is allowed only if its OID appears in
// allowed.otherNames; tags 3 (x400Address), 4 (directoryName), 5
// (ediPartyName) and 8 (registeredID) are always denied — there is no
// opt-in mechanism for these.
func (e evaluator) OtherNames() field.ErrorList {
	fldPath := e.fldPath.Child("otherNames")

	// Collect otherName entries by OID so a duplicate-OID smuggling
	// attempt is policed in one pass per OID and the operator sees the
	// full value list in the error message.
	byOID := make(map[string][]string)
	var oidOrder []string
	var presentByOID = make(map[string]bool)

	var el field.ErrorList
	for _, gn := range e.sanGNs {
		if gn.Class != asn1.ClassContextSpecific {
			el = append(el, field.Invalid(fldPath, fmt.Sprintf("class=%d tag=%d", gn.Class, gn.Tag), "unexpected SAN GeneralName class"))
			continue
		}
		switch gn.Tag {
		case 1, 2, 6, 7:
			// rfc822Name / dNSName / URI / IP — covered by the
			// parsed-slice evaluators above.
			continue
		case 0:
			oid, value, ok := parseOtherName(gn)
			if !ok {
				el = append(el, field.Invalid(fldPath, hex.EncodeToString(gn.FullBytes), "otherName SAN entry could not be decoded"))
				continue
			}
			key := oid.String()
			if _, seen := presentByOID[key]; !seen {
				presentByOID[key] = true
				oidOrder = append(oidOrder, key)
			}
			byOID[key] = append(byOID[key], value)
		case 3:
			el = append(el, field.Invalid(fldPath, hex.EncodeToString(gn.FullBytes), "x400Address SAN entries are not permitted"))
		case 4:
			el = append(el, field.Invalid(fldPath, hex.EncodeToString(gn.FullBytes), "directoryName SAN entries are not permitted"))
		case 5:
			el = append(el, field.Invalid(fldPath, hex.EncodeToString(gn.FullBytes), "ediPartyName SAN entries are not permitted"))
		case 8:
			el = append(el, field.Invalid(fldPath, hex.EncodeToString(gn.FullBytes), "registeredID SAN entries are not permitted"))
		default:
			el = append(el, field.Invalid(fldPath, fmt.Sprintf("tag=%d", gn.Tag), "unknown SAN GeneralName tag"))
		}
	}

	// Index allowed.otherNames by OID for lookup.
	allowedByOID := make(map[string]*policyapi.CertificateRequestPolicyAllowedOtherName)
	for i := range e.allowed.OtherNames {
		entry := &e.allowed.OtherNames[i]
		allowedByOID[entry.OID] = entry
	}

	// Per-OID evaluation of values present in the request against the
	// matching allow-list entry (or "no allowed value" if absent).
	for _, key := range oidOrder {
		values := byOID[key]
		entry, ok := allowedByOID[key]
		entryFld := fldPath.Key(key)
		if !ok {
			el = append(el, field.Invalid(entryFld, values, "no allowed value"))
			continue
		}
		slice := &policyapi.CertificateRequestPolicyAllowedStringSlice{
			Values:      entry.Values,
			Required:    entry.Required,
			Validations: entry.Validations,
		}
		el = append(el, e.a.evaluateSlice(e.request, values, slice, entryFld)...)
	}

	// Required: any allowed.otherNames entry with required=true must have
	// been seen in the request.
	for _, entry := range e.allowed.OtherNames {
		if entry.Required == nil || !*entry.Required {
			continue
		}
		if presentByOID[entry.OID] {
			continue
		}
		el = append(el, field.Required(fldPath.Key(entry.OID).Child("required"), strconv.FormatBool(true)))
	}

	return el
}

func (e evaluator) Subject() subjectEvaluator {
	allowed := e.allowed.Subject
	if allowed == nil {
		allowed = new(policyapi.CertificateRequestPolicyAllowedX509Subject)
	}
	return subjectEvaluator{
		a:           e.a,
		request:     e.request,
		sub:         e.csr.Subject,
		subjectRDNs: e.subjectRDNs,
		allowed:     allowed,
		fldPath:     e.fldPath.Child("subject"),
	}
}

type subjectEvaluator struct {
	a           allowed
	request     *cmapi.CertificateRequest
	sub         pkix.Name
	subjectRDNs pkix.RDNSequence
	allowed     *policyapi.CertificateRequestPolicyAllowedX509Subject
	fldPath     *field.Path
}

func (e subjectEvaluator) Organization() field.ErrorList {
	return e.a.evaluateSlice(e.request, e.sub.Organization, e.allowed.Organizations, e.fldPath.Child("organizations"))
}

func (e subjectEvaluator) Country() field.ErrorList {
	return e.a.evaluateSlice(e.request, e.sub.Country, e.allowed.Countries, e.fldPath.Child("countries"))
}

func (e subjectEvaluator) OrganizationalUnit() field.ErrorList {
	return e.a.evaluateSlice(e.request, e.sub.OrganizationalUnit, e.allowed.OrganizationalUnits, e.fldPath.Child("organizationalUnits"))
}

func (e subjectEvaluator) Locality() field.ErrorList {
	return e.a.evaluateSlice(e.request, e.sub.Locality, e.allowed.Localities, e.fldPath.Child("localities"))
}

func (e subjectEvaluator) Province() field.ErrorList {
	return e.a.evaluateSlice(e.request, e.sub.Province, e.allowed.Provinces, e.fldPath.Child("provinces"))
}

func (e subjectEvaluator) StreetAddress() field.ErrorList {
	return e.a.evaluateSlice(e.request, e.sub.StreetAddress, e.allowed.StreetAddresses, e.fldPath.Child("streetAddresses"))
}

func (e subjectEvaluator) PostalCode() field.ErrorList {
	return e.a.evaluateSlice(e.request, e.sub.PostalCode, e.allowed.PostalCodes, e.fldPath.Child("postalCodes"))
}

// SerialNumber evaluates every Subject SerialNumber RDN value present in
// csr.RawSubject. As with CommonName the lossy pkix.Name projection keeps
// only the last value; a duplicate-SN smuggling attempt is policed here.
func (e subjectEvaluator) SerialNumber() field.ErrorList {
	values := serialNumberValues(e.subjectRDNs)
	fldPath := e.fldPath.Child("serialNumber")
	switch len(values) {
	case 0:
		return e.a.evaluateString(e.request, "", e.allowed.SerialNumber, fldPath)
	case 1:
		return e.a.evaluateString(e.request, values[0], e.allowed.SerialNumber, fldPath)
	default:
		var el field.ErrorList
		for _, v := range values {
			el = append(el, e.a.evaluateString(e.request, v, e.allowed.SerialNumber, fldPath)...)
		}
		return el
	}
}

func serialNumberValues(rdns pkix.RDNSequence) []string {
	var values []string
	for _, rdn := range rdns {
		for _, atv := range rdn {
			if !atv.Type.Equal(oidSerialNumber) {
				continue
			}
			if s, ok := atv.Value.(string); ok {
				values = append(values, s)
				continue
			}
			values = append(values, fmt.Sprintf("<non-string %T>", atv.Value))
		}
	}
	return values
}

// OtherAttributes evaluates every Subject RDN attribute whose OID is not
// covered by one of the named allowed.commonName / allowed.subject.* fields.
// Such attributes are denied unless an entry with the matching OID is listed
// in allowed.subject.otherAttributes; an entry's Values/Validations then
// constrain the attribute values as for the named slice fields.
func (e subjectEvaluator) OtherAttributes() field.ErrorList {
	fldPath := e.fldPath.Child("otherAttributes")

	// Collect every unmapped-OID attribute, grouped by OID, preserving
	// the order in which OIDs first appeared in the RDN sequence so
	// error messages are stable.
	byOID := make(map[string][]string)
	var oidOrder []string
	presentByOID := make(map[string]bool)

	for _, rdn := range e.subjectRDNs {
		for _, atv := range rdn {
			if isNamedSubjectOID(atv.Type) {
				continue
			}
			key := atv.Type.String()
			var value string
			if s, ok := atv.Value.(string); ok {
				value = s
			} else {
				value = fmt.Sprintf("<non-string %T>", atv.Value)
			}
			if _, seen := presentByOID[key]; !seen {
				presentByOID[key] = true
				oidOrder = append(oidOrder, key)
			}
			byOID[key] = append(byOID[key], value)
		}
	}

	allowedByOID := make(map[string]*policyapi.CertificateRequestPolicyAllowedSubjectOtherAttribute)
	for i := range e.allowed.OtherAttributes {
		entry := &e.allowed.OtherAttributes[i]
		allowedByOID[entry.OID] = entry
	}

	var el field.ErrorList
	for _, key := range oidOrder {
		values := byOID[key]
		entry, ok := allowedByOID[key]
		entryFld := fldPath.Key(key)
		if !ok {
			el = append(el, field.Invalid(entryFld, values, "no allowed value"))
			continue
		}
		slice := &policyapi.CertificateRequestPolicyAllowedStringSlice{
			Values:      entry.Values,
			Required:    entry.Required,
			Validations: entry.Validations,
		}
		el = append(el, e.a.evaluateSlice(e.request, values, slice, entryFld)...)
	}

	for _, entry := range e.allowed.OtherAttributes {
		if entry.Required == nil || !*entry.Required {
			continue
		}
		if presentByOID[entry.OID] {
			continue
		}
		el = append(el, field.Required(fldPath.Key(entry.OID).Child("required"), strconv.FormatBool(true)))
	}

	return el
}

// parseOtherName decodes a SAN otherName GeneralName entry (context tag 0)
// into (OID, stringValue). The value bytes are extracted from the inner
// [0] EXPLICIT wrapper and decoded as a UTF-8/Printable/IA5/T61 string —
// the encodings used in practice for otherName values (notably the Microsoft
// UPN UTF8String). For other inner ASN.1 types the hex-encoded DER is
// returned so that wildcard/CEL rules can still pin a specific blob; the
// caller will treat any opaque value as a string match.
//
// ok is false only when the outer SEQUENCE itself is malformed.
func parseOtherName(gn asn1.RawValue) (asn1.ObjectIdentifier, string, bool) {
	// otherName ::= [0] IMPLICIT SEQUENCE {
	//     type-id OBJECT IDENTIFIER,
	//     value   [0] EXPLICIT ANY DEFINED BY type-id }
	//
	// asn1.UnmarshalWithParams("tag:0", &struct{...}) does not reliably
	// strip the inner [0] EXPLICIT wrapper around the ANY field, so walk
	// gn.Bytes (the SEQUENCE content, IMPLICIT-stripped by the outer
	// SAN list decode) by hand.
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(gn.Bytes, &oid)
	if err != nil {
		return nil, "", false
	}
	var explicit asn1.RawValue
	rest2, err := asn1.Unmarshal(rest, &explicit)
	if err != nil || explicit.Class != asn1.ClassContextSpecific || explicit.Tag != 0 {
		return nil, "", false
	}
	if len(rest2) != 0 {
		return nil, "", false
	}
	var inner asn1.RawValue
	if _, err := asn1.Unmarshal(explicit.Bytes, &inner); err != nil {
		// Could not decode the wrapped value at all; fall back to the
		// hex-encoded wrapper bytes so the value can still be policed.
		return oid, hex.EncodeToString(explicit.Bytes), true
	}
	return oid, otherNameValueString(inner), true
}

// otherNameValueString renders the inner value of a SAN otherName entry as
// a string. UTF8String / PrintableString / IA5String / T61String values
// (the encodings used in practice for otherName payloads such as the
// Microsoft UPN) are decoded as text; any other ASN.1 type is rendered as
// its hex-encoded full-bytes DER so that a wildcard/CEL rule can still pin
// an exact blob.
func otherNameValueString(v asn1.RawValue) string {
	if v.Class == asn1.ClassUniversal {
		switch v.Tag {
		case asn1.TagUTF8String, asn1.TagPrintableString, asn1.TagIA5String, asn1.TagT61String:
			return string(v.Bytes)
		}
	}
	return hex.EncodeToString(v.FullBytes)
}

func (a allowed) evaluateString(request *cmapi.CertificateRequest, s string, crp *policyapi.CertificateRequestPolicyAllowedString, fldPath *field.Path) field.ErrorList {
	if len(s) == 0 {
		// Attribute not set in request. We will only check if it's a required attribute
		// and not run any validations specified by the policy.
		if crp != nil && crp.Required != nil && *crp.Required {
			return []*field.Error{field.Required(fldPath.Child("required"), strconv.FormatBool(*crp.Required))}
		}
		return nil
	}

	// Attribute set in request. If neither Value nor Validations are set,
	// we exit early with error to simplify the following logic.
	if crp == nil || (crp.Value == nil && len(crp.Validations) == 0) {
		return []*field.Error{field.Invalid(fldPath, s, "no allowed value")}
	}

	var el field.ErrorList
	if crp.Value != nil && !util.WildcardMatches(*crp.Value, s) {
		el = append(el, field.Invalid(fldPath.Child("value"), s, *crp.Value))
	}

	if len(crp.Validations) > 0 {
		el = append(el, a.runValidations(request, crp.Validations, s, fldPath.Child("validations"))...)
	}
	return el
}

func (a allowed) evaluateSlice(request *cmapi.CertificateRequest, s []string, crp *policyapi.CertificateRequestPolicyAllowedStringSlice, fldPath *field.Path) field.ErrorList {
	if len(s) == 0 {
		// Attribute not set in request. We will only check if it's a required attribute
		// and not run any validations specified by the policy.
		if crp != nil && crp.Required != nil && *crp.Required {
			return []*field.Error{field.Required(fldPath.Child("required"), strconv.FormatBool(*crp.Required))}
		}
		return nil
	}

	// Attribute set in request. If neither Values nor Validations are set,
	// we exit early with error to simplify the following logic.
	if crp == nil || (crp.Values == nil && len(crp.Validations) == 0) {
		return []*field.Error{field.Invalid(fldPath, s, "no allowed values")}
	}

	var el field.ErrorList
	if crp.Values != nil && !util.WildcardSubset(*crp.Values, s) {
		el = append(el, field.Invalid(fldPath.Child("values"), s, strings.Join(*crp.Values, ", ")))
	}

	if len(crp.Validations) > 0 {
		fldPath := fldPath.Child("validations")
		for _, v := range s {
			el = append(el, a.runValidations(request, crp.Validations, v, fldPath)...)
		}
	}
	return el
}

func (a allowed) evaluateBool(b bool, crp *bool, fldPath *field.Path) field.ErrorList {
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

func (a allowed) runValidations(request *cmapi.CertificateRequest, validations []policyapi.ValidationRule, s string, fldPath *field.Path) field.ErrorList {
	var el field.ErrorList
	for i, v := range validations {
		validator, err := a.validators.Get(v.Rule)
		if err != nil {
			el = append(el, field.InternalError(fldPath.Index(i), err))
			continue
		}
		valid, err := validator.Validate(s, *request)
		if err != nil {
			el = append(el, field.InternalError(fldPath.Index(i), err))
			continue
		}
		if !valid {
			detail := ptr.Deref(v.Message, fmt.Sprintf("failed rule: %s", v.Rule))
			el = append(el, field.Invalid(fldPath.Index(i), s, detail))
		}
	}
	return el
}
