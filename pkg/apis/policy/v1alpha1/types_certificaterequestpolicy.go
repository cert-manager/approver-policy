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

package v1alpha1

import (
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var CertificateRequestPolicyKind = "CertificateRequestPolicy"

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
//+kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=`.status.conditions[?(@.type == "Ready")].status`,description="CertificateRequestPolicy is ready for evaluation"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Timestamp CertificateRequestPolicy was created"
//+kubebuilder:resource:categories=cert-manager,shortName=crp,scope=Cluster
//+kubebuilder:subresource:status

// CertificateRequestPolicy is an object for describing a "policy profile" that
// makes decisions on whether applicable CertificateRequests should be approved
// or denied.
type CertificateRequestPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateRequestPolicySpec   `json:"spec,omitempty"`
	Status CertificateRequestPolicyStatus `json:"status,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// CertificateRequestPolicyList is a list of CertificateRequestPolicies.
type CertificateRequestPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CertificateRequestPolicy `json:"items"`
}

// CertificateRequestPolicySpec defines the desired state of
// CertificateRequestPolicy.
type CertificateRequestPolicySpec struct {
	// Allowed defines the allowed attributes for a CertificateRequest.
	// A CertificateRequest can request _less_ than what is allowed,
	// but _not more_, i.e. a CertificateRequest can request a subset of what
	// is declared as allowed by the policy.
	// Omitted fields declare that the equivalent CertificateRequest
	// field _must_ be omitted or have an empty value for the request to be
	// permitted.
	// +optional
	Allowed *CertificateRequestPolicyAllowed `json:"allowed,omitempty"`

	// Constraints define fields that _must_ be satisfied by a
	// CertificateRequest for the request to be allowed by this policy.
	// Omitted fields place no restrictions on the corresponding
	// attribute in a request.
	// +optional
	Constraints *CertificateRequestPolicyConstraints `json:"constraints,omitempty"`

	// Plugins are approvers that are built into approver-policy at
	// compile-time. This is an advanced feature typically used to extend
	// approver-policy core features. This field define plugins and their
	// configuration that should be executed when this policy is evaluated
	// against a CertificateRequest.
	// +optional
	Plugins map[string]CertificateRequestPolicyPluginData `json:"plugins,omitempty"`

	// Selector is used for selecting over which CertificateRequests this
	// CertificateRequestPolicy is appropriate for and so will be used for its
	// approval evaluation.
	Selector CertificateRequestPolicySelector `json:"selector"`
}

// CertificateRequestPolicyAllowed defines the allowed attributes for a
// CertificateRequest.
// A CertificateRequest can request _less_ than what is allowed,
// but _not more_, i.e. a CertificateRequest can request a subset of what is
// declared as allowed by the policy.
// Omitted fields declares that the equivalent CertificateRequest field _must_
// be omitted or have an empty value for the request to be permitted.
type CertificateRequestPolicyAllowed struct {
	// CommonName defines the X.509 Common Name that may be requested.
	// +optional
	CommonName *CertificateRequestPolicyAllowedString `json:"commonName,omitempty"`

	// DNSNames defines the X.509 DNS SANs that may be requested.
	// +optional
	DNSNames *CertificateRequestPolicyAllowedStringSlice `json:"dnsNames,omitempty"`

	// IPAddresses defines the X.509 IP SANs that may be requested.
	// +optional
	IPAddresses *CertificateRequestPolicyAllowedStringSlice `json:"ipAddresses,omitempty"`

	// URIs defines the X.509 URI SANs that may be requested.
	// +optional
	URIs *CertificateRequestPolicyAllowedStringSlice `json:"uris,omitempty"`

	// EmailAddresses defines the X.509 Email SANs that may be requested.
	// +optional
	EmailAddresses *CertificateRequestPolicyAllowedStringSlice `json:"emailAddresses,omitempty"`

	// IsCA defines if a CertificateRequest is allowed to set the `spec.isCA`
	// field set to `true`.
	// If `true`, the `spec.isCA` field can be `true` or `false`.
	// If `false` or unset, the `spec.isCA` field must be `false`.
	// +optional
	IsCA *bool `json:"isCA,omitempty"`

	// Usages defines the key usages that may be included in a
	// CertificateRequest `spec.keyUsages` field.
	// If set, `spec.keyUsages` in a CertificateRequest must be a subset of the
	// specified values.
	// If `[]` or unset, no `spec.keyUsages` are allowed.
	// TODO: add x-kubernetes-list-type: set in v1alpha2
	// +optional
	Usages *[]cmapi.KeyUsage `json:"usages,omitempty"`

	// Subject declares the X.509 Subject attributes allowed in a
	// CertificateRequest. An omitted field forbids any Subject attributes
	// from being requested.
	// A CertificateRequest can request a subset of the allowed X.509 Subject
	// attributes.
	// +optional
	Subject *CertificateRequestPolicyAllowedX509Subject `json:"subject,omitempty"`
}

// CertificateRequestPolicyAllowedX509Subject declares allowed X.509 Subject
// attributes for a CertificateRequest.
// A CertificateRequest can request a subset of the allowed X.509 Subject
// attributes.
type CertificateRequestPolicyAllowedX509Subject struct {
	// Organizations define the X.509 Subject Organizations that may be
	// requested.
	// +optional
	Organizations *CertificateRequestPolicyAllowedStringSlice `json:"organizations,omitempty"`

	// Countries define the X.509 Subject Countries that may be requested.
	// +optional
	Countries *CertificateRequestPolicyAllowedStringSlice `json:"countries,omitempty"`

	// OrganizationalUnits defines the X.509 Subject Organizational Units that
	// may be requested.
	// +optional
	OrganizationalUnits *CertificateRequestPolicyAllowedStringSlice `json:"organizationalUnits,omitempty"`

	// Localities defines the X.509 Subject Localities that may be requested.
	// +optional
	Localities *CertificateRequestPolicyAllowedStringSlice `json:"localities,omitempty"`

	// Provinces defines the X.509 Subject Provinces that may be requested.
	// +optional
	Provinces *CertificateRequestPolicyAllowedStringSlice `json:"provinces,omitempty"`

	// StreetAddresses defines the X.509 Subject Street Addresses that may be
	// requested.
	// +optional
	StreetAddresses *CertificateRequestPolicyAllowedStringSlice `json:"streetAddresses,omitempty"`

	// PostalCodes defines the X.509 Subject Postal Codes that may be requested.
	// +optional
	PostalCodes *CertificateRequestPolicyAllowedStringSlice `json:"postalCodes,omitempty"`

	// SerialNumber defines the X.509 Subject Serial Number that may be
	// requested.
	// +optional
	SerialNumber *CertificateRequestPolicyAllowedString `json:"serialNumber,omitempty"`
}

// CertificateRequestPolicyAllowedStringSlice represents allowed string values
// and/or validations paired with whether the field is a required value on the request.
// If neither allowed values nor validations are specified, the related field must be empty.
type CertificateRequestPolicyAllowedStringSlice struct {
	// Values defines allowed attribute values on the related CertificateRequest field.
	// Accepts wildcards "*".
	// If set, the related field can only include items contained in the allowed values.
	//
	// NOTE:`values: []` paired with `required: true` establishes a policy that
	// will never grant a `CertificateRequest`, but other policies may.
	// TODO: add x-kubernetes-list-type: set in v1alpha2
	// +optional
	Values *[]string `json:"values,omitempty"`

	// Required controls whether the related field must have at least one value.
	// Defaults to `false`.
	// +optional
	Required *bool `json:"required,omitempty"`

	// Validations applies rules using Common Expression Language (CEL) to
	// validate attribute values present on request beyond what is possible
	// to express using values/required.
	// ALL attribute values on the related CertificateRequest field must pass
	// ALL validations for the request to be granted by this policy.
	// +listType=map
	// +listMapKey=rule
	// +optional
	Validations []ValidationRule `json:"validations,omitempty"`
}

// CertificateRequestPolicyAllowedString represents an allowed string value
// and/or validations paired with whether the field is a required value on the request.
// If no allowed value nor validations are specified, the related field must be empty.
type CertificateRequestPolicyAllowedString struct {
	// Value defines the allowed attribute value on the related CertificateRequest field.
	// Accepts wildcards "*".
	// If set, the related field must match the specified pattern.
	//
	// NOTE:`value: ""` paired with `required: true` establishes a policy that
	// will never grant a `CertificateRequest`, but other policies may.
	// +optional
	Value *string `json:"value,omitempty"`

	// Required marks that the related field must be provided and not be an
	// empty string.
	// Defaults to `false`.
	// +optional
	Required *bool `json:"required,omitempty"`

	// Validations applies rules using Common Expression Language (CEL) to
	// validate attribute value present on request beyond what is possible
	// to express using value/required.
	// An attribute value on the related CertificateRequest field must pass
	// ALL validations for the request to be granted by this policy.
	// +listType=map
	// +listMapKey=rule
	// +optional
	Validations []ValidationRule `json:"validations,omitempty"`
}

// ValidationRule describes a validation rule expressed in CEL.
type ValidationRule struct {
	// Rule represents the expression which will be evaluated by CEL.
	// ref: https://github.com/google/cel-spec
	// The Rule is scoped to the location of the validations in the schema.
	// The `self` variable in the CEL expression is bound to the scoped value.
	// To enable more advanced validation rules, approver-policy provides the
	// `cr` (map) variable to the CEL expression containing `namespace` and
	// `name` of the `CertificateRequest` resource.
	//
	// Example (rule for namespaced DNSNames):
	// ```
	// rule: self.endsWith(cr.namespace + '.svc.cluster.local')
	// ```
	Rule string `json:"rule"`

	// Message is the message to display when validation fails.
	// Message is required if the Rule contains line breaks. Note that Message
	// must not contain line breaks.
	// If unset, a fallback message is used: "failed rule: `<rule>`".
	// e.g. "must be a URL with the host matching spec.host"
	// +optional
	Message *string `json:"message,omitempty"`
}

// CertificateRequestPolicyConstraints define fields that _must_ be satisfied
// by the CertificateRequest for the request to be allowed by this policy.
// Omitted fields will be satisfied by any value in the corresponding attribute
// of the request.
type CertificateRequestPolicyConstraints struct {
	// MinDuration defines the minimum duration for a certificate request.
	// Values are inclusive (i.e. a value of `1h` will accept a duration of
	// `1h`). MinDuration and MaxDuration may be the same value.
	// If set, a duration _must_ be requested in the CertificateRequest.
	// An omitted field applies no minimum constraint for duration.
	// +optional
	MinDuration *metav1.Duration `json:"minDuration,omitempty"`

	// MaxDuration defines the maximum duration for a certificate request.
	// for.
	// Values are inclusive (i.e. a value of `1h` will accept a duration of
	// `1h`). MinDuration and MaxDuration may be the same value.
	// If set, a duration _must_ be requested in the CertificateRequest.
	// An omitted field applies no maximum constraint for duration.
	// +optional
	MaxDuration *metav1.Duration `json:"maxDuration,omitempty"`

	// PrivateKey defines constraints on the shape of private key
	// allowed for a CertificateRequest.
	// An omitted field applies no private key shape constraints.
	// +optional
	PrivateKey *CertificateRequestPolicyConstraintsPrivateKey `json:"privateKey,omitempty"`
}

// CertificateRequestPolicyConstraintsPrivateKey defines constraints on the shape of private key
// allowed for a CertificateRequest.
type CertificateRequestPolicyConstraintsPrivateKey struct {
	// Algorithm defines the allowed crypto algorithm for the private key
	// in a request.
	// An omitted field permits any algorithm.
	// +optional
	Algorithm *cmapi.PrivateKeyAlgorithm `json:"algorithm,omitempty"`

	// MinSize defines the minimum key size for a private key.
	// Values are inclusive (i.e. a min value of `2048` will accept a size
	// of `2048`). MinSize and MaxSize may be the same value.
	// An omitted field applies no minimum constraint on size.
	// +optional
	MinSize *int `json:"minSize,omitempty"`

	// MaxSize defines the maximum key size for a private key.
	// Values are inclusive (i.e. a min value of `2048` will accept a size
	// of `2048`). MaxSize and MinSize may be the same value.
	// An omitted field applies no maximum constraint on size.
	// +optional
	MaxSize *int `json:"maxSize,omitempty"`
}

// CertificateRequestPolicyPluginData is configuration needed by the plugin
// approver to evaluate a CertificateRequest on this policy.
type CertificateRequestPolicyPluginData struct {
	// Values define a set of well-known, to the plugin, key value pairs that
	// are required for the plugin to successfully evaluate a request based on
	// this policy.
	// +optional
	Values map[string]string `json:"values,omitempty"`
}

// CertificateRequestPolicySelector is used for selecting over which
// CertificateRequests this CertificateRequestPolicy is appropriate for, and if
// so, will be used to evaluate the request.
// All selectors that have been configured must match a CertificateRequest
// in order for the CertificateRequestPolicy to be chosen for evaluation.
// At least one of IssuerRef or Namespace must be defined.
type CertificateRequestPolicySelector struct {
	// IssuerRef is used to match by issuer, meaning the
	// CertificateRequestPolicy will only evaluate CertificateRequests
	// referring to matching issuers.
	// CertificateRequests will not be processed if the issuer does not match,
	// regardless of whether the requestor is bound by RBAC.
	//
	// The following value will match _all_ issuers:
	// ```
	// issuerRef: {}
	// ```
	// +optional
	IssuerRef *CertificateRequestPolicySelectorIssuerRef `json:"issuerRef"`

	// Namespace is used to match by namespace, meaning the
	// CertificateRequestPolicy will only match CertificateRequests
	// created in matching namespaces.
	// If this field is omitted, resources in all namespaces are checked.
	// +optional
	Namespace *CertificateRequestPolicySelectorNamespace `json:"namespace"`
}

// CertificateRequestPolicySelectorIssuerRef defines the selector for matching
// the issuer reference of requests.
type CertificateRequestPolicySelectorIssuerRef struct {
	// Name is a wildcard enabled selector that matches the
	// `spec.issuerRef.name` field of requests.
	// Accepts wildcards "*".
	// An omitted field matches all names.
	// +optional
	Name *string `json:"name,omitempty"`

	// Kind is the wildcard selector to match the `spec.issuerRef.kind` field
	// on requests.
	// Accepts wildcards "*".
	// An omitted field matches all kinds.
	// +optional
	Kind *string `json:"kind,omitempty"`

	// Group is the wildcard selector to match the `spec.issuerRef.group` field
	// on requests.
	// Accepts wildcards "*".
	// An omitted field matches all groups.
	// +optional
	Group *string `json:"group,omitempty"`
}

// CertificateRequestPolicySelectorNamespace defines the selector for matching
// the namespace of requests. Note that all selectors must match in order
// for the request to be considered for evaluation by this policy.
type CertificateRequestPolicySelectorNamespace struct {
	// MatchNames is the set of namespace names that select on
	// CertificateRequests that have been created in a matching namespace.
	// Accepts wildcards "*".
	// TODO: add x-kubernetes-list-type: set in v1alpha2
	// +optional
	MatchNames []string `json:"matchNames,omitempty"`

	// MatchLabels is the set of Namespace labels that select on
	// CertificateRequests which have been created in a namespace matching the
	// selector.
	// +optional
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// CertificateRequestPolicyStatus defines the observed state of the
// CertificateRequestPolicy.
type CertificateRequestPolicyStatus struct {
	// List of status conditions to indicate the status of the
	// CertificateRequestPolicy.
	// Known condition types are `Ready`.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []CertificateRequestPolicyCondition `json:"conditions,omitempty"`
}

// CertificateRequestPolicyCondition contains condition information for a
// CertificateRequestPolicyStatus.
type CertificateRequestPolicyCondition struct {
	// Type of the condition, known values are (`Ready`).
	Type CertificateRequestPolicyConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	Status corev1.ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`

	// If set, this represents the .metadata.generation that the condition was
	// set based upon.
	// For instance, if .metadata.generation is currently 12, but the
	// .status.condition[x].observedGeneration is 9, the condition is out of
	// date with respect to the current state of the CertificateRequestPolicy.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// CertificateRequestPolicyConditionType represents a CertificateRequestPolicy
// condition value.
type CertificateRequestPolicyConditionType string

const (
	// CertificateRequestPolicyConditionReady indicates that the
	// CertificateRequestPolicy has successfully loaded the policy, and all
	// configuration including plugin options are accepted and ready for
	// evaluating CertificateRequests.
	// +k8s:deepcopy-gen=false
	CertificateRequestPolicyConditionReady CertificateRequestPolicyConditionType = "Ready"
)
