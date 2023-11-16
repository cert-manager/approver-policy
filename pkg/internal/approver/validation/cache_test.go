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
