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
		"if policy contains 'required' validation errors, expect an Allowed=false response": {
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
					field.Required(field.NewPath("spec.allowed.dnsNames.values"), "at least one of 'values' or 'validations' must be defined if field is 'required'"),
					field.Required(field.NewPath("spec.allowed.ipAddresses.values"), "at least one of 'values' or 'validations' must be defined if field is 'required'"),
					field.Required(field.NewPath("spec.allowed.uris.values"), "at least one of 'values' or 'validations' must be defined if field is 'required'"),
					field.Required(field.NewPath("spec.allowed.emailAddresses.values"), "at least one of 'values' or 'validations' must be defined if field is 'required'"),
					field.Required(field.NewPath("spec.allowed.subject.organizations.values"), "at least one of 'values' or 'validations' must be defined if field is 'required'"),
					field.Required(field.NewPath("spec.allowed.subject.countries.values"), "at least one of 'values' or 'validations' must be defined if field is 'required'"),
					field.Required(field.NewPath("spec.allowed.subject.organizationalUnits.values"), "at least one of 'values' or 'validations' must be defined if field is 'required'"),
					field.Required(field.NewPath("spec.allowed.subject.localities.values"), "at least one of 'values' or 'validations' must be defined if field is 'required'"),
					field.Required(field.NewPath("spec.allowed.subject.provinces.values"), "at least one of 'values' or 'validations' must be defined if field is 'required'"),
					field.Required(field.NewPath("spec.allowed.subject.streetAddresses.values"), "at least one of 'values' or 'validations' must be defined if field is 'required'"),
					field.Required(field.NewPath("spec.allowed.subject.postalCodes.values"), "at least one of 'values' or 'validations' must be defined if field is 'required'"),
					field.Required(field.NewPath("spec.allowed.commonName.value"), "at least one of 'value' or 'validations' must be defined if field is 'required'"),
					field.Required(field.NewPath("spec.allowed.subject.serialNumber.value"), "at least one of 'value' or 'validations' must be defined if field is 'required'"),
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
		"if policy contains invalid CEL validations, expect an Allowed=false response": {
			policy: &policyapi.CertificateRequestPolicy{
				Spec: policyapi.CertificateRequestPolicySpec{
					Allowed: &policyapi.CertificateRequestPolicyAllowed{
						CommonName:     &policyapi.CertificateRequestPolicyAllowedString{Validations: []policyapi.ValidationRule{{Rule: "cel"}}},
						DNSNames:       &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self > 2"}}},
						IPAddresses:    &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self && false"}}},
						URIs:           &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self.exists(x, p)"}}},
						EmailAddresses: &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self"}}},
						Subject: &policyapi.CertificateRequestPolicyAllowedX509Subject{
							Organizations:       &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self == '"}}},
							Countries:           &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self.length < 24"}}},
							OrganizationalUnits: &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: ""}}},
							Localities:          &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "cr.name[1] > 2"}}},
							Provinces:           &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "cel"}}},
							StreetAddresses:     &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "cel"}}},
							PostalCodes:         &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "cel"}}},
							SerialNumber:        &policyapi.CertificateRequestPolicyAllowedString{Validations: []policyapi.ValidationRule{{Rule: "cel"}}},
						},
					},
				},
			},
			expResponse: approver.WebhookValidationResponse{
				Allowed: false,
				Errors: field.ErrorList{
					field.Invalid(field.NewPath("spec.allowed.dnsNames.validations[0]"), "self > 2", "ERROR: <input>:1:6: found no matching overload for '_>_' applied to '(string, int)'\n | self > 2\n | .....^"),
					field.Invalid(field.NewPath("spec.allowed.ipAddresses.validations[0]"), "self && false", "ERROR: <input>:1:1: expected type 'bool' but found 'string'\n | self && false\n | ^"),
					field.Invalid(field.NewPath("spec.allowed.uris.validations[0]"), "self.exists(x, p)", "ERROR: <input>:1:1: expression of type 'string' cannot be range of a comprehension (must be list, map, or dynamic)\n | self.exists(x, p)\n | ^\nERROR: <input>:1:16: undeclared reference to 'p' (in container '')\n | self.exists(x, p)\n | ...............^"),
					field.Invalid(field.NewPath("spec.allowed.emailAddresses.validations[0]"), "self", "got string, wanted bool result type"),
					field.Invalid(field.NewPath("spec.allowed.subject.organizations.validations[0]"), "self == '", "ERROR: <input>:1:9: Syntax error: token recognition error at: '''\n | self == '\n | ........^\nERROR: <input>:1:10: Syntax error: mismatched input '<EOF>' expecting {'[', '{', '(', '.', '-', '!', 'true', 'false', 'null', NUM_FLOAT, NUM_INT, NUM_UINT, STRING, BYTES, IDENTIFIER}\n | self == '\n | .........^"),
					field.Invalid(field.NewPath("spec.allowed.subject.countries.validations[0]"), "self.length < 24", "ERROR: <input>:1:5: type 'string' does not support field selection\n | self.length < 24\n | ....^"),
					field.Invalid(field.NewPath("spec.allowed.subject.organizationalUnits.validations[0]"), "", "ERROR: <input>:1:1: Syntax error: mismatched input '<EOF>' expecting {'[', '{', '(', '.', '-', '!', 'true', 'false', 'null', NUM_FLOAT, NUM_INT, NUM_UINT, STRING, BYTES, IDENTIFIER}"),
					field.Invalid(field.NewPath("spec.allowed.subject.localities.validations[0]"), "cr.name[1] > 2", "ERROR: <input>:1:8: found no matching overload for '_[_]' applied to '(string, int)'\n | cr.name[1] > 2\n | .......^"),
					field.Invalid(field.NewPath("spec.allowed.subject.provinces.validations[0]"), "cel", "ERROR: <input>:1:1: undeclared reference to 'cel' (in container '')\n | cel\n | ^"),
					field.Invalid(field.NewPath("spec.allowed.subject.streetAddresses.validations[0]"), "cel", "ERROR: <input>:1:1: undeclared reference to 'cel' (in container '')\n | cel\n | ^"),
					field.Invalid(field.NewPath("spec.allowed.subject.postalCodes.validations[0]"), "cel", "ERROR: <input>:1:1: undeclared reference to 'cel' (in container '')\n | cel\n | ^"),
					field.Invalid(field.NewPath("spec.allowed.commonName.validations[0]"), "cel", "ERROR: <input>:1:1: undeclared reference to 'cel' (in container '')\n | cel\n | ^"),
					field.Invalid(field.NewPath("spec.allowed.subject.serialNumber.validations[0]"), "cel", "ERROR: <input>:1:1: undeclared reference to 'cel' (in container '')\n | cel\n | ^"),
				},
			},
		},
		"if policy contains valid CEL validations, expect a Allowed=true response": {
			policy: &policyapi.CertificateRequestPolicy{
				Spec: policyapi.CertificateRequestPolicySpec{
					Allowed: &policyapi.CertificateRequestPolicyAllowed{
						CommonName:     &policyapi.CertificateRequestPolicyAllowedString{Validations: []policyapi.ValidationRule{{Rule: "self.size() > 2"}}},
						DNSNames:       &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self.size() > 2"}}},
						IPAddresses:    &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self.size() > 2"}}},
						URIs:           &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self.size() > 2"}}},
						EmailAddresses: &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self.size() > 2"}}},
						Subject: &policyapi.CertificateRequestPolicyAllowedX509Subject{
							Organizations:       &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self.size() > 2"}}},
							Countries:           &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self.size() > 2"}}},
							OrganizationalUnits: &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self.size() > 2"}}},
							Localities:          &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self.size() > 2"}}},
							Provinces:           &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self.size() > 2"}}},
							StreetAddresses:     &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self.size() > 2"}}},
							PostalCodes:         &policyapi.CertificateRequestPolicyAllowedStringSlice{Validations: []policyapi.ValidationRule{{Rule: "self.size() > 2"}}},
							SerialNumber:        &policyapi.CertificateRequestPolicyAllowedString{Validations: []policyapi.ValidationRule{{Rule: "self.size() > 2"}}},
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
