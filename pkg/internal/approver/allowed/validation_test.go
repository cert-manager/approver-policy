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
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/pointer"

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
)

func Test_Validate(t *testing.T) {
	tests := map[string]struct {
		policy      *policyapi.CertificateRequestPolicy
		expResponse approver.WebhookValidationResponse
	}{
		"if policy contains no allowed, expect a Allowed=true response": {
			policy: &policyapi.CertificateRequestPolicy{
				Spec: policyapi.CertificateRequestPolicySpec{
					Allowed: nil,
				},
			},
			expResponse: approver.WebhookValidationResponse{
				Allowed: true,
				Errors:  nil,
			},
		},
		"if policy contains validation errors, expect a Allowed=false response": {
			policy: &policyapi.CertificateRequestPolicy{
				Spec: policyapi.CertificateRequestPolicySpec{
					Allowed: &policyapi.CertificateRequestPolicyAllowed{
						CommonName:     &policyapi.CertificateRequestPolicyAllowedString{Required: pointer.Bool(true), Value: nil},
						DNSNames:       &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: nil},
						IPAddresses:    &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: nil},
						URIs:           &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: nil},
						EmailAddresses: &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: nil},
						Subject: &policyapi.CertificateRequestPolicyAllowedX509Subject{
							Organizations:       &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: nil},
							Countries:           &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: nil},
							OrganizationalUnits: &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: nil},
							Localities:          &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: nil},
							Provinces:           &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: nil},
							StreetAddresses:     &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: nil},
							PostalCodes:         &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: nil},
							SerialNumber:        &policyapi.CertificateRequestPolicyAllowedString{Required: pointer.Bool(true), Value: nil},
						},
					},
				},
			},
			expResponse: approver.WebhookValidationResponse{
				Allowed: false,
				Errors: field.ErrorList{
					field.Required(field.NewPath("spec.allowed.dnsNames.values"), "values must be defined if required field"),
					field.Required(field.NewPath("spec.allowed.ipAddresses.values"), "values must be defined if required field"),
					field.Required(field.NewPath("spec.allowed.uris.values"), "values must be defined if required field"),
					field.Required(field.NewPath("spec.allowed.emailAddresses.values"), "values must be defined if required field"),
					field.Required(field.NewPath("spec.allowed.subject.organizations.values"), "values must be defined if required field"),
					field.Required(field.NewPath("spec.allowed.subject.countries.values"), "values must be defined if required field"),
					field.Required(field.NewPath("spec.allowed.subject.organizationalUnits.values"), "values must be defined if required field"),
					field.Required(field.NewPath("spec.allowed.subject.localities.values"), "values must be defined if required field"),
					field.Required(field.NewPath("spec.allowed.subject.provinces.values"), "values must be defined if required field"),
					field.Required(field.NewPath("spec.allowed.subject.streetAddresses.values"), "values must be defined if required field"),
					field.Required(field.NewPath("spec.allowed.subject.postalCodes.values"), "values must be defined if required field"),
					field.Required(field.NewPath("spec.allowed.commonName.value"), "value must be defined if required field"),
					field.Required(field.NewPath("spec.allowed.subject.serialNumber.value"), "value must be defined if required field"),
				},
			},
		},
		"if policy contains all non-subject required and they have values, expect a Allowed=true response": {
			policy: &policyapi.CertificateRequestPolicy{
				Spec: policyapi.CertificateRequestPolicySpec{
					Allowed: &policyapi.CertificateRequestPolicyAllowed{
						CommonName:     &policyapi.CertificateRequestPolicyAllowedString{Required: pointer.Bool(true), Value: pointer.String("")},
						DNSNames:       &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: &[]string{}},
						IPAddresses:    &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: &[]string{}},
						URIs:           &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: &[]string{}},
						EmailAddresses: &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: &[]string{}},
						Subject: &policyapi.CertificateRequestPolicyAllowedX509Subject{
							Organizations:       &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(false), Values: &[]string{}},
							Countries:           &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(false), Values: &[]string{}},
							OrganizationalUnits: &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(false), Values: &[]string{}},
							Localities:          &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(false), Values: &[]string{}},
							Provinces:           &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(false), Values: nil},
							StreetAddresses:     &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(false), Values: &[]string{}},
							PostalCodes:         &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(false), Values: nil},
							SerialNumber:        &policyapi.CertificateRequestPolicyAllowedString{Required: pointer.Bool(true), Value: pointer.String("")},
						},
					},
				},
			},
			expResponse: approver.WebhookValidationResponse{
				Allowed: true,
				Errors:  nil,
			},
		},
		"if policy contains all required but values are defined, expect a Allowed=true response": {
			policy: &policyapi.CertificateRequestPolicy{
				Spec: policyapi.CertificateRequestPolicySpec{
					Allowed: &policyapi.CertificateRequestPolicyAllowed{
						CommonName:     &policyapi.CertificateRequestPolicyAllowedString{Required: pointer.Bool(true), Value: pointer.String("")},
						DNSNames:       &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: &[]string{}},
						IPAddresses:    &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: &[]string{}},
						URIs:           &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: &[]string{}},
						EmailAddresses: &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: &[]string{}},
						Subject: &policyapi.CertificateRequestPolicyAllowedX509Subject{
							Organizations:       &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: &[]string{}},
							Countries:           &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: &[]string{}},
							OrganizationalUnits: &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: &[]string{}},
							Localities:          &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: &[]string{}},
							Provinces:           &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: &[]string{}},
							StreetAddresses:     &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: &[]string{}},
							PostalCodes:         &policyapi.CertificateRequestPolicyAllowedStringSlice{Required: pointer.Bool(true), Values: &[]string{}},
							SerialNumber:        &policyapi.CertificateRequestPolicyAllowedString{Required: pointer.Bool(true), Value: pointer.String("")},
						},
					},
				},
			},
			expResponse: approver.WebhookValidationResponse{
				Allowed: true,
				Errors:  nil,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			response, err := Approver().Validate(context.TODO(), test.policy)
			assert.NoError(t, err)
			assert.Equal(t, test.expResponse, response)
		})
	}
}
