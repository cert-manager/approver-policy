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
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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
	// AllowedSubject defines the X.509 subject that is permissible.
	// An omitted field or value of nil permits all.
	// +optional
	AllowedSubject *CertificateRequestPolicyX509Subject `json:"allowedSubject,omitempty"`

	// AllowedCommonName defines the X.509 Common Name this is permissible.
	// Accepts wildcards "*".
	// An omitted field or value of nil permits all.
	// +optional
	AllowedCommonName *string `json:"allowedCommonName,omitempty"`

	// MinDuration defines the minimum duration a certificate may be requested
	// for.
	// Values are inclusive (i.e. a min value of `1h` will accept a duration of
	// `1h`). MinDuration and MaxDuration may be the same value.
	// An omitted field or value of nil permits all.
	// +optional
	MinDuration *metav1.Duration `json:"minDuration,omitempty"`

	// MaxDuration defines the maximum duration a certificate may be requested
	// for.
	// Values are inclusive (i.e. a max value of `1h` will accept a duration of
	// `1h`). MaxDuration and MinDuration may be the same value.
	// An omitted field or value of nil permits all.
	// +optional
	MaxDuration *metav1.Duration `json:"maxDuration,omitempty"`

	// AllowedDNSNames defines the X.509 DNS SAN names that may be requested for.
	// Accepts wildcards "*".
	// An omitted field or value of nil permits all.
	// An empty slice `[]` permits nothing.
	// +optional
	AllowedDNSNames *[]string `json:"allowedDNSNames,omitempty"`

	// AllowedIPAddresses defines the X.509 IP SAN names that may be requested
	// for.
	// Accepts wildcards "*".
	// An omitted field or value of nil permits all.
	// An empty slice `[]` permits nothing.
	// +optional
	AllowedIPAddresses *[]string `json:"allowedIPAddresses,omitempty"`

	// AllowedURIs defines the X.509 URI SAN names that may be requested for.
	// Accepts wildcards "*".
	// An omitted field or value of nil permits all.
	// An empty slice `[]` permits nothing.
	// +optional
	AllowedURIs *[]string `json:"allowedURIs,omitempty"`

	// AllowedEmailAddresses defines the X.509 URI SAN names that may be
	// requested for.
	// Accepts wildcards "*".
	// An omitted field or value of nil permits all.
	// An empty slice `[]` permits nothing.
	// +optional
	AllowedEmailAddresses *[]string `json:"allowedEmailAddresses,omitempty"`

	// AllowedIsCA defines whether it is permissible for the CertificateRequest
	// to contain the field `spec.isCA`.
	// An omitted field or value of nil permits all.
	// +optional
	AllowedIsCA *bool `json:"allowedIsCA,omitempty"`

	// AllowedUsages defines the list of permissible key usages that may appear
	// of the CertificateRequest `spec.keyUsages` field.
	// An omitted field or value of nil permits all.
	// An empty slice `[]` permits nothing.
	// +optional
	AllowedUsages *[]cmapi.KeyUsage `json:"allowedUsages,omitempty"`

	// AllowedPrivateKey defines the shape of permissible private keys that may
	// be used for the request.
	// An omitted field or value of nil permits all.
	// +optional
	AllowedPrivateKey *CertificateRequestPolicyPrivateKey `json:"allowedPrivateKey,omitempty"`

	// Plugins define a set of plugins and their configuration that should be
	// executed when this policy is evaluated against a CertificateRequest. A
	// plugin must already be built within policy-approver for it to be
	// available.
	// +optional
	Plugins map[string]CertificateRequestPolicyPluginData `json:"plugins,omitempty"`

	// IssuerRefSelector is used to match this CertificateRequestPolicy against
	// processed CertificateRequests. This policy will only be evaluated against
	// a CertificateRequest whose `spec.issuerRef` field matches
	// `issuerRefSelector`. CertificateRequests will not be processed on unmatched
	// `issuerRefSelector`, regardless of whether the requestor is bound.
	// Accepts wildcards "*".
	// Nil values are equivalent to "*",
	//
	// The following value will match _all_ `issuerRefs`:
	// ```
	// issuerRefSelector: {}
	// ```
	//
	// Required field.
	IssuerRefSelector *CertificateRequestPolicyIssuerRefSelector `json:"issuerRefSelector"`
}

// CertificateRequestPolicyX509Subject  controls the X.509 Subject which may
// appear on requests to be permissible for this policy.
type CertificateRequestPolicyX509Subject struct {
	// AllowedOrganizations defines the X.509 Subject Organizations that may be
	// requested for.
	// Accepts wildcards "*".
	// An omitted field or value of nil permits all.
	// An empty slice `[]` permits nothing.
	// +optional
	AllowedOrganizations *[]string `json:"allowedOrganizations,omitempty"`

	// AllowedCountries defines the X.509 Subject Countries that may be requested
	// for.
	// Accepts wildcards "*".
	// An omitted field or value of nil permits all.
	// An empty slice `[]` permits nothing.
	// +optional
	AllowedCountries *[]string `json:"allowedCountries,omitempty"`

	// AllowedOrganizationalUnitsdefines the X.509 Subject Organizational Units
	// that may be requested for.
	// Accepts wildcards "*".
	// An omitted field or value of nil permits all.
	// An empty slice `[]` permits nothing.
	// +optional
	AllowedOrganizationalUnits *[]string `json:"allowedOrganizationalUnits,omitempty"`

	// AllowedLocalities defines the X.509 Subject Localities that may be
	// requested for.
	// Accepts wildcards "*".
	// An omitted field or value of nil permits all.
	// An empty slice `[]` permits nothing.
	// +optional
	AllowedLocalities *[]string `json:"allowedLocalities,omitempty"`

	// AllowedProvinces defines the X.509 Subject Provinces that may be requested
	// for.
	// Accepts wildcards "*".
	// An omitted field or value of nil permits all.
	// An empty slice `[]` permits nothing.
	// +optional
	AllowedProvinces *[]string `json:"allowedProvinces,omitempty"`

	// AllowedStreetAddresses defines the X.509 Subject Street Addresses that may
	// be requested for.
	// Accepts wildcards "*".
	// An omitted field or value of nil permits all.
	// An empty slice `[]` permits nothing.
	// +optional
	AllowedStreetAddresses *[]string `json:"allowedStreetAddresses,omitempty"`

	// AllowedPostalCodes defines the X.509 Subject Postal Codes that may be
	// requested for.
	// Accepts wildcards "*".
	// An omitted field or value of nil permits all.
	// An empty slice `[]` permits nothing.
	// +optional
	AllowedPostalCodes *[]string `json:"allowedPostalCodes,omitempty"`

	// AllowedSerialNumber defines the X.509 Subject Serial Number that must be
	// requested for.
	// An omitted field or value of nil permits all.
	// +optional
	AllowedSerialNumber *string `json:"allowedSerialNumber,omitempty"`
}

// CertificateRequestPolicyPrivateKey defines what shape of private key is
// permissible for a request to use.
type CertificateRequestPolicyPrivateKey struct {
	// AllowedAlgorithm defines the allowed crypto algorithm that is used by the
	// requestor for their private key.
	// An omitted field or value of nil permits all.
	// +optional
	AllowedAlgorithm *cmapi.PrivateKeyAlgorithm `json:"allowedAlgorithm,omitempty"`

	// MinSize defines the minimum key size a requestor may use for their private
	// key.
	// Values are inclusive (i.e. a min value of `2048` will accept a size
	// of `2048`). MinSize and MaxSize may be the same value.
	// An omitted field or value of nil permits all.
	// +optional
	MinSize *int `json:"minSize,omitempty"`

	// MaxSize defines the maximum key size a requestor may use for their private
	// key.
	// Values are inclusive (i.e. a min value of `2048` will accept a size
	// of `2048`). MaxSize and MinSize may be the same value.
	// An omitted field or value of nil permits all.
	// +optional
	MaxSize *int `json:"maxSize,omitempty"`
}

// CertificateRequestPolicyIssuerRefSelector defines the selector for matching
// on `issuerRef` of requests.
type CertificateRequestPolicyIssuerRefSelector struct {
	// Name is the wildcard selector to match the `spec.issuerRef.name` field on
	// requests.
	// Accepts wildcards "*".
	// An omitted field or value of nil permits all.
	// +optional
	Name *string `json:"name,omitempty"`

	// Kind is the wildcard selector to match the `spec.issuerRef.kind` field on
	// requests.
	// Accepts wildcards "*".
	// An omitted field or value of nil permits all.
	// +optional
	Kind *string `json:"kind,omitempty"`

	// Group is the wildcard selector to match the `spec.issuerRef.group` field
	// on requests.
	// Accepts wildcards "*".
	// An omitted field or value of nil permits all.
	// +optional
	Group *string `json:"group,omitempty"`
}

// CertificateRequestPolicyPluginData is configuration needed by the plugin
// approver to evaluate a CertificateRequest on this policy.
type CertificateRequestPolicyPluginData struct {
	// Values define a set of well-known, to the plugin, key value pairs that are
	// required for the plugin to successfully evaluate a request based on this
	// policy.
	// +optional
	Values map[string]string `json:"values,omitempty"`
}

// CertificateRequestPolicyStatus defines the observed state of the
// CertificateRequestPolicy.
type CertificateRequestPolicyStatus struct {
	// List of status conditions to indicate the status of the
	// CertificateRequestPolicy.
	// Known condition types are `Ready`.
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
	// .status.condition[x].observedGeneration is 9, the condition is out of date
	// with respect to the current state of the CertificateRequestPolicy.
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
	CertificateRequestPolicyConditionReady CertificateRequestPolicyConditionType = "Ready"
)
