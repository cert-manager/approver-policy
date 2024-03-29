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

	"github.com/stretchr/testify/assert"
)

func Test_Cache_Get(t *testing.T) {
	c := NewCache()

	type args struct {
		expr string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "valid-expression", args: args{expr: "self.endsWith(cr.namespace + '.svc')"}},
		{name: "invalid-expression", args: args{expr: "foo"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.Get(tt.args.expr)

			if tt.wantErr {
				assert.Error(t, err)
				// Cache should return same error for same expression
				_, sameErr := c.Get(tt.args.expr)
				assert.Same(t, err, sameErr)
			} else {
				assert.NoError(t, err)
				// Cache should return same validator for same expression
				same, _ := c.Get(tt.args.expr)
				assert.Same(t, got, same)
			}
		})
	}
}
