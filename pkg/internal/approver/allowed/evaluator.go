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
	"slices"
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

// oidSubjectAltName is the X.509 Subject Alternative Name extension OID.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

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
)

// namedSubjectOIDs is the set of Subject RDN OIDs that correspond to a named
// allowed.commonName / allowed.subject.* field.
var namedSubjectOIDs = []asn1.ObjectIdentifier{
	oidCommonName, oidSerialNumber, oidCountry, oidLocality, oidProvince,
	oidStreetAddress, oidOrganization, oidOrganizationalUnit, oidPostalCode,
}

func isNamedSubjectOID(oid asn1.ObjectIdentifier) bool {
	return slices.ContainsFunc(namedSubjectOIDs, oid.Equal)
}

// namedSubjectFieldPath returns the field.Path for a named Subject OID
// relative to the given subject base path (spec.allowed.subject). For CN
// the path is one level up (spec.allowed.commonName).
func namedSubjectFieldPath(subjectPath *field.Path, oid asn1.ObjectIdentifier) *field.Path {
	switch {
	case oid.Equal(oidCommonName):
		return field.NewPath("spec", "allowed", "commonName")
	case oid.Equal(oidSerialNumber):
		return subjectPath.Child("serialNumber")
	case oid.Equal(oidCountry):
		return subjectPath.Child("countries")
	case oid.Equal(oidLocality):
		return subjectPath.Child("localities")
	case oid.Equal(oidProvince):
		return subjectPath.Child("provinces")
	case oid.Equal(oidStreetAddress):
		return subjectPath.Child("streetAddresses")
	case oid.Equal(oidOrganization):
		return subjectPath.Child("organizations")
	case oid.Equal(oidOrganizationalUnit):
		return subjectPath.Child("organizationalUnits")
	case oid.Equal(oidPostalCode):
		return subjectPath.Child("postalCodes")
	default:
		return subjectPath.Child("otherAttributes").Key(oid.String())
	}
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

	// Decode the raw SAN extension with cert-manager's own SAN parser so the
	// approver evaluates the exact GeneralName entries the signer will emit.
	// crypto/x509 silently drops GeneralName tags outside {1,2,6,7}
	// (otherName, x400Address, directoryName, ediPartyName, registeredID)
	// from its parsed slices, but cert-manager copies the raw SAN extension
	// into the issued certificate verbatim — so those entries must be made
	// visible to policy here.
	var sans utilpki.GeneralNames
	var sanExtCount int
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		sanExtCount++
		if sanExtCount > 1 {
			return approver.EvaluationResponse{
				Result:  approver.ResultDenied,
				Message: "CSR contains multiple SAN extensions; at most one is permitted",
			}, nil
		}
		parsed, err := utilpki.UnmarshalSANs(ext.Value)
		if err != nil {
			// Fail closed: a SAN extension we cannot fully decode must never
			// be approved, since cert-manager would still sign its raw bytes.
			return approver.EvaluationResponse{
				Result:  approver.ResultDenied,
				Message: fmt.Sprintf("subjectAltName (SAN) extension could not be decoded: %v", err),
			}, nil
		}
		sans = parsed
	}

	// Decode the raw Subject DER directly so duplicate CN/SerialNumber RDNs
	// and unmapped attribute OIDs (e.g. emailAddress, DC, UID) — which the
	// lossy pkix.Name projection drops or silently overwrites — are visible
	// to policy. cert-manager copies csr.RawSubject verbatim into the issued
	// certificate, so the approver and signer must see the same bytes.
	var subjectRDNs pkix.RDNSequence
	if len(csr.RawSubject) > 0 {
		subjectRDNs, err = utilpki.UnmarshalRawDerBytesToRDNSequence(csr.RawSubject)
		if err != nil {
			return approver.EvaluationResponse{}, fmt.Errorf("decode csr.RawSubject: %w", err)
		}
	}

	evaluate := evaluator{
		a:           a,
		request:     request,
		csr:         csr,
		sans:        sans,
		subjectRDNs: subjectRDNs,
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
	// sans holds every SAN GeneralName entry decoded from the raw SAN
	// extension (via cert-manager's UnmarshalSANs) — including the
	// otherName/directoryName/x400Address/ediPartyName/registeredID entries
	// that crypto/x509's parsed slices drop.
	sans utilpki.GeneralNames
	// subjectRDNs is the full RDNSequence decoded directly from
	// csr.RawSubject — preserves duplicate CN/SerialNumber RDNs and
	// unmapped attribute OIDs that the lossy pkix.Name projection drops.
	subjectRDNs pkix.RDNSequence
	allowed     *policyapi.CertificateRequestPolicyAllowed
	fldPath     *field.Path
}

// subjectValuesForOID returns the string values for every Subject RDN
// attribute with the given OID across the full RDNSequence (duplicates
// preserved, unlike the lossy pkix.Name projection). If any matching ATV
// has a value that does not decode to a Go string (genuinely non-string
// ASN.1 types, or the rarely-used UniversalString/GeneralString encodings),
// it returns an error so callers can deny fail-closed without depending on
// another evaluator to catch it.
func subjectValuesForOID(rdns pkix.RDNSequence, oid asn1.ObjectIdentifier) ([]string, error) {
	var values []string
	for _, rdn := range rdns {
		for _, atv := range rdn {
			if !atv.Type.Equal(oid) {
				continue
			}
			s, ok := atv.Value.(string)
			if !ok {
				return nil, fmt.Errorf("subject attribute %s uses an unsupported ASN.1 type or string encoding; re-issue the certificate with a UTF8String or PrintableString subject", oid)
			}
			values = append(values, s)
		}
	}
	return values, nil
}

// CommonName evaluates every CN RDN value present in csr.RawSubject against
// allowed.commonName. Multiple CN RDNs (a duplicate-CN smuggling attempt)
// trigger a separate error per value so the operator sees the full set.
// A non-string-encoded CN is denied directly here (fail-closed).
func (e evaluator) CommonName() field.ErrorList {
	values, err := subjectValuesForOID(e.subjectRDNs, oidCommonName)
	fldPath := e.fldPath.Child("commonName")
	if err != nil {
		return field.ErrorList{field.Invalid(fldPath, "<non-string value>", err.Error())}
	}
	switch len(values) {
	case 0:
		return e.a.evaluateString(e.request, "", e.allowed.CommonName, fldPath)
	case 1:
		return e.a.evaluateString(e.request, values[0], e.allowed.CommonName, fldPath)
	default:
		var el field.ErrorList
		for i, v := range values {
			el = append(el, e.a.evaluateString(e.request, v, e.allowed.CommonName, fldPath.Index(i))...)
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

// OtherNames evaluates the SAN GeneralName entries that the parsed-slice
// evaluators above (DNSNames/IPAddresses/URIs/EmailAddresses) do not cover.
// otherName entries (tag 0) are permitted only when their OID is listed in
// allowed.otherNames; directoryName, x400Address, ediPartyName and
// registeredID entries are always denied — there is no opt-in for these.
func (e evaluator) OtherNames() field.ErrorList {
	var el field.ErrorList

	// SAN GeneralName types with no opt-in mechanism — always denied.
	// These are reported under subjectAltName rather than otherNames because
	// they have nothing to do with the allowed.otherNames policy field.
	sanPath := e.fldPath.Child("subjectAltName")
	for range e.sans.DirectoryNames {
		el = append(el, field.Invalid(sanPath.Child("directoryName"), "directoryName", "directoryName SAN entries are not permitted"))
	}
	for range e.sans.X400Addresses {
		el = append(el, field.Invalid(sanPath.Child("x400Address"), "x400Address", "x400Address SAN entries are not permitted"))
	}
	for range e.sans.EDIPartyNames {
		el = append(el, field.Invalid(sanPath.Child("ediPartyName"), "ediPartyName", "ediPartyName SAN entries are not permitted"))
	}
	for range e.sans.RegisteredIDs {
		el = append(el, field.Invalid(sanPath.Child("registeredID"), "registeredID", "registeredID SAN entries are not permitted"))
	}

	// Collect otherName values grouped by OID, preserving first-seen order so
	// a duplicate-OID smuggling attempt is policed in one pass and evaluation
	// (and any error messages) is deterministic.
	byOID := make(map[string][]string)
	var oidOrder []string
	for _, on := range e.sans.OtherNames {
		key := on.TypeID.String()
		if _, seen := byOID[key]; !seen {
			oidOrder = append(oidOrder, key)
		}
		byOID[key] = append(byOID[key], otherNameValueString(on.Value))
	}

	// Index allowed.otherNames by OID for lookup.
	allowedByOID := make(map[string]*policyapi.CertificateRequestPolicyAllowedOtherName)
	for i := range e.allowed.OtherNames {
		entry := &e.allowed.OtherNames[i]
		allowedByOID[entry.OID] = entry
	}

	// Per-OID evaluation of values present in the request against the
	// matching allow-list entry (or "no allowed value" if absent).
	otherNamesPath := e.fldPath.Child("otherNames")
	for _, key := range oidOrder {
		values := byOID[key]
		entry, ok := allowedByOID[key]
		entryFld := otherNamesPath.Key(key)
		if !ok {
			el = append(el, field.Invalid(entryFld, values, "no allowed values"))
			continue
		}
		el = append(el, e.a.evaluateSlice(e.request, values, &policyapi.CertificateRequestPolicyAllowedStringSlice{
			Values:      entry.Values,
			Required:    entry.Required,
			Validations: entry.Validations,
		}, entryFld)...)
	}

	// Required: any allowed.otherNames entry with required=true must have
	// been seen in the request.
	for _, entry := range e.allowed.OtherNames {
		if entry.Required == nil || !*entry.Required {
			continue
		}
		if _, ok := byOID[entry.OID]; ok {
			continue
		}
		el = append(el, field.Required(otherNamesPath.Key(entry.OID).Child("required"), strconv.FormatBool(true)))
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
// A non-string-encoded SerialNumber is denied directly here (fail-closed).
func (e subjectEvaluator) SerialNumber() field.ErrorList {
	values, err := subjectValuesForOID(e.subjectRDNs, oidSerialNumber)
	fldPath := e.fldPath.Child("serialNumber")
	if err != nil {
		return field.ErrorList{field.Invalid(fldPath, "<non-string value>", err.Error())}
	}
	switch len(values) {
	case 0:
		return e.a.evaluateString(e.request, "", e.allowed.SerialNumber, fldPath)
	case 1:
		return e.a.evaluateString(e.request, values[0], e.allowed.SerialNumber, fldPath)
	default:
		var el field.ErrorList
		for i, v := range values {
			el = append(el, e.a.evaluateString(e.request, v, e.allowed.SerialNumber, fldPath.Index(i))...)
		}
		return el
	}
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
	// seenOID tracks OIDs that appeared in the RDN sequence regardless of
	// whether the value was a string. This prevents the required-check
	// below from emitting a spurious "missing" error when the OID is
	// present but carries a non-string encoding (already reported as
	// Invalid).
	seenOID := make(map[string]bool)

	var el field.ErrorList

	for _, rdn := range e.subjectRDNs {
		for _, atv := range rdn {
			if isNamedSubjectOID(atv.Type) {
				// CN and SerialNumber are already covered by their
				// dedicated evaluators (which read from subjectRDNs
				// via subjectValuesForOID and handle non-string values
				// themselves). Only fire the backstop for the remaining
				// named-slice OIDs (O, OU, L, …) that read from the
				// lossy pkix.Name projection which silently drops
				// non-strings — but the signer still emits them via
				// RawSubject.
				if atv.Type.Equal(oidCommonName) || atv.Type.Equal(oidSerialNumber) {
					continue
				}
				if _, ok := atv.Value.(string); !ok {
					namedPath := namedSubjectFieldPath(e.fldPath, atv.Type)
					el = append(el, field.Invalid(
						namedPath,
						"<non-string value>",
						"subject attribute uses an unsupported ASN.1 type or string encoding; re-issue the certificate with a UTF8String or PrintableString subject"))
				}
				continue
			}

			key := atv.Type.String()
			seenOID[key] = true

			s, isString := atv.Value.(string)
			if !isString {
				el = append(el, field.Invalid(
					fldPath.Key(key),
					"<non-string value>",
					"subject attribute uses an unsupported ASN.1 type or string encoding; re-issue the certificate with a UTF8String or PrintableString subject"))
				continue
			}

			if _, seen := byOID[key]; !seen {
				oidOrder = append(oidOrder, key)
			}
			byOID[key] = append(byOID[key], s)
		}
	}

	allowedByOID := make(map[string]*policyapi.CertificateRequestPolicyAllowedSubjectOtherAttribute)
	for i := range e.allowed.OtherAttributes {
		entry := &e.allowed.OtherAttributes[i]
		allowedByOID[entry.OID] = entry
	}

	for _, key := range oidOrder {
		values := byOID[key]
		entry, ok := allowedByOID[key]
		entryFld := fldPath.Key(key)
		if !ok {
			el = append(el, field.Invalid(entryFld, values, "no allowed values"))
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
		if seenOID[entry.OID] {
			continue
		}
		el = append(el, field.Required(fldPath.Key(entry.OID).Child("required"), strconv.FormatBool(true)))
	}

	return el
}

// otherNameValueString renders the value of a SAN otherName entry as a
// string. utilpki.UnmarshalSANs returns the value still wrapped in its
// [0] EXPLICIT tag (otherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT
// ANY }), so unwrap it to reach the inner ANY value. UTF8String /
// PrintableString / IA5String / T61String values (the encodings used in
// practice for otherName payloads such as the Microsoft UPN) are decoded as
// text; any other ASN.1 type is rendered as its hex-encoded full-bytes DER so
// that a wildcard/CEL rule can still pin an exact blob.
func otherNameValueString(v asn1.RawValue) string {
	if v.Class == asn1.ClassContextSpecific && v.Tag == 0 {
		var inner asn1.RawValue
		if _, err := asn1.Unmarshal(v.Bytes, &inner); err == nil {
			v = inner
		}
	}
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
