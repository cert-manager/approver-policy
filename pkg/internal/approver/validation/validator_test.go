/*
Copyright 2023 The cert-manager Authors.

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

package validation

import (
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/stretchr/testify/assert"
)

func Test_Validator_Compile(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{name: "no-var-use", expr: "'www.example.com'.endsWith('.com')"},
		{name: "simple-checks", expr: "size(cr.namespace) < 24"},
		{name: "standard-macros", expr: "[1,2,3].all(i, i % 2 > 0)"},
		{name: "extended-string-function-library", expr: "self.startsWith('spiffe://trust-domain.com/')"},
		{name: "doc-example", expr: "['.svc', '.svc.cluster.local'].exists(d, self.endsWith(cr.namespace + d))"},
		{name: "err-no-expression", wantErr: true},
		{name: "err-undeclared-vars", expr: "foo = bar", wantErr: true},
		{name: "err-must-return-bool", expr: "size('foo')", wantErr: true},
		{name: "err-invalid-property", expr: "size(cr.foo) < 24", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &validator{expression: tt.expr}
			err := v.compile()
			if tt.wantErr {
				assert.Error(t, err)
				return
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_Validator_Validate(t *testing.T) {
	v := &validator{expression: "self.startsWith('spiffe://acme.com/ns/%s/sa/'.format([cr.namespace]))"}
	err := v.compile()
	assert.NoError(t, err)

	type args struct {
		val string
		cr  cmapi.CertificateRequest
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{name: "correct-namespace", args: args{val: "spiffe://acme.com/ns/foo-ns/sa/bar", cr: newCertificateRequest("foo-ns")}, want: true},
		{name: "wrong-namespace", args: args{val: "spiffe://acme.com/ns/foo-ns/sa/bar", cr: newCertificateRequest("bar-ns")}, want: false},
		{name: "unrelated", args: args{val: "spiffe://example.com", cr: newCertificateRequest("foo-ns")}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := v.Validate(tt.args.val, tt.args.cr)
			if tt.wantErr {
				assert.Error(t, err)
				return
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func newCertificateRequest(namespace string) cmapi.CertificateRequest {
	request := cmapi.CertificateRequest{}
	request.SetNamespace(namespace)
	return request
}
