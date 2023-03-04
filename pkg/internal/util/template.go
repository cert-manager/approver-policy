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
	"bytes"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"text/template"
)

// TemplateData is the data we will be able to retrieve data from.
// It just contains the request but could be enriched later.
type TemplateData struct {
	Request *cmapi.CertificateRequest
}

// TemplateStr takes an input string which may be a template and replaces
// appropriate templates with data.
func TemplateStr(data TemplateData, input string) string {

	t, err := template.New("template").Parse(input)
	if err != nil {
		return input
	}

	buffer := new(bytes.Buffer)
	err = t.Execute(buffer, data)
	if err != nil {
		return input
	}

	return buffer.String()
}

// TemplateArray takes an input string array which may be a template and replaces
// appropriate templates with data.
func TemplateArray(data TemplateData, inputs []string) []string {
	var results = make([]string, 0)

	for _, input := range inputs {
		results = append(results, TemplateStr(data, input))
	}

	return results
}
