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

package util

import (
	"fmt"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestTemplateStr(t *testing.T) {

	// Prepare a certificate request with values
	request := cmapi.CertificateRequest{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{Namespace: "request-ns"},
		Spec:       cmapi.CertificateRequestSpec{},
		Status:     cmapi.CertificateRequestStatus{},
	}

	// Create the tests
	tests := []struct {
		testname string
		data     TemplateData
		input    string
		exp      string
	}{
		{
			testname: "No template",
			data:     TemplateData{Request: &request},
			input:    "not templated",
			exp:      "not templated",
		},
		{
			testname: "namespace template",
			data:     TemplateData{Request: &request},
			input:    "---{{ .Request.Namespace }}---",
			exp:      "---request-ns---",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s", test.input), func(t *testing.T) {
			if match := TemplateStr(test.data, test.input); match != test.exp {
				t.Errorf("unexpected result (%s): exp=\"%s\" got=\"%s\"",
					test.input, test.exp, match)
			}
		})
	}
}

func TestTemplateArray(t *testing.T) {

	// Prepare a certificate request with values
	request := cmapi.CertificateRequest{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{Namespace: "request-ns"},
		Spec:       cmapi.CertificateRequestSpec{},
		Status:     cmapi.CertificateRequestStatus{},
	}

	// Create the tests
	tests := []struct {
		testname string
		data     TemplateData
		inputs   []string
		exps     []string
	}{
		{
			testname: "No template",
			data:     TemplateData{Request: &request},
			inputs:   []string{"not templated 1", "not templated 2"},
			exps:     []string{"not templated 1", "not templated 2"},
		},
		{
			testname: "namespace template",
			data:     TemplateData{Request: &request},
			inputs:   []string{"ns: '{{ .Request.Namespace }}'"},
			exps:     []string{"ns: 'request-ns'"},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s", test.inputs), func(t *testing.T) {
			results := TemplateArray(test.data, test.inputs)
			if len(results) != len(test.exps) {
				t.Errorf("unexpected length of arrays. exp=%d got %d",
					len(test.exps), len(results))
			}
			for idx := range results {
				if idx > len(test.exps) {
					// Failsafe for different array lengths
					continue
				}

				if results[idx] != test.exps[idx] {
					t.Errorf("unexpected result (%s): exp=\"%s\" got=\"%s\"",
						test.inputs[idx], test.exps[idx], results[idx])
				}
			}
		})
	}
}
