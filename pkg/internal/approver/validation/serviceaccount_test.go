/*
Copyright 2024 The cert-manager Authors.

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
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
)

func TestStringToServiceAccount(t *testing.T) {
	tests := map[string]struct {
		input     ref.Val
		expectSA  bool
		expectNS  string
		expectErr bool
	}{
		"valid service account username should return ServiceAccount": {
			input:    types.String("system:serviceaccount:my-namespace:my-sa"),
			expectSA: true,
			expectNS: "my-namespace",
		},
		"invalid username should return error": {
			input:     types.String("not-a-service-account"),
			expectErr: true,
		},
		"non-string input should return error": {
			input:     types.Int(42),
			expectErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			result := stringToServiceAccount(test.input)
			if test.expectErr {
				assert.True(t, types.IsError(result), "expected error result")
				return
			}
			sa, ok := result.(ServiceAccount)
			require.True(t, ok, "expected ServiceAccount type")
			assert.Equal(t, test.expectNS, sa.Namespace)
			assert.Equal(t, "my-sa", sa.Name)
		})
	}
}

func TestIsServiceAccount(t *testing.T) {
	tests := map[string]struct {
		input  ref.Val
		expect ref.Val
	}{
		"valid service account username should return true": {
			input:  types.String("system:serviceaccount:default:my-sa"),
			expect: types.True,
		},
		"invalid username should return false": {
			input:  types.String("not-valid"),
			expect: types.False,
		},
		"empty string should return false": {
			input:  types.String(""),
			expect: types.False,
		},
		"non-string input should return error": {
			input:  types.Int(42),
			expect: nil,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			result := isServiceAccount(test.input)
			if test.expect == nil {
				assert.True(t, types.IsError(result), "expected error result")
				return
			}
			assert.Equal(t, test.expect, result)
		})
	}
}

func TestGetServiceAccountName(t *testing.T) {
	sa := ServiceAccount{Name: "test-sa", Namespace: "test-ns"}
	result := getServiceAccountName(sa)
	assert.Equal(t, types.String("test-sa"), result)
}

func TestGetServiceAccountName_NonServiceAccount(t *testing.T) {
	result := getServiceAccountName(types.String("not-a-sa"))
	assert.True(t, types.IsError(result), "expected error for non-ServiceAccount input")
}

func TestGetServiceAccountNamespace(t *testing.T) {
	sa := ServiceAccount{Name: "test-sa", Namespace: "test-ns"}
	result := getServiceAccountNamespace(sa)
	assert.Equal(t, types.String("test-ns"), result)
}

func TestGetServiceAccountNamespace_NonServiceAccount(t *testing.T) {
	result := getServiceAccountNamespace(types.String("not-a-sa"))
	assert.True(t, types.IsError(result), "expected error for non-ServiceAccount input")
}

func TestServiceAccount_Equal(t *testing.T) {
	sa1 := ServiceAccount{Name: "sa", Namespace: "ns"}
	sa2 := ServiceAccount{Name: "sa", Namespace: "ns"}
	sa3 := ServiceAccount{Name: "other", Namespace: "ns"}

	assert.Equal(t, types.Bool(true), sa1.Equal(sa2))
	assert.Equal(t, types.Bool(false), sa1.Equal(sa3))
}

func TestServiceAccount_Equal_NonServiceAccount(t *testing.T) {
	sa := ServiceAccount{Name: "sa", Namespace: "ns"}
	result := sa.Equal(types.String("not-a-sa"))
	assert.True(t, types.IsError(result), "expected error for non-ServiceAccount comparison")
}

func TestServiceAccount_Type(t *testing.T) {
	sa := ServiceAccount{Name: "sa", Namespace: "ns"}
	assert.Equal(t, SAType, sa.Type())
}

func TestServiceAccount_Value(t *testing.T) {
	sa := ServiceAccount{Name: "sa", Namespace: "ns"}
	result := sa.Value()
	assert.Equal(t, sa, result)
}

func TestServiceAccount_ConvertToNative(t *testing.T) {
	sa := ServiceAccount{Name: "my-sa", Namespace: "my-ns"}

	t.Run("convert to ServiceAccount type", func(t *testing.T) {
		result, err := sa.ConvertToNative(reflect.TypeFor[ServiceAccount]())
		require.NoError(t, err)
		assert.Equal(t, sa, result)
	})

	t.Run("convert to string type", func(t *testing.T) {
		result, err := sa.ConvertToNative(reflect.TypeFor[string]())
		require.NoError(t, err)
		expected := serviceaccount.MakeUsername("my-ns", "my-sa")
		assert.Equal(t, expected, result)
	})

	t.Run("convert to unsupported type should error", func(t *testing.T) {
		_, err := sa.ConvertToNative(reflect.TypeFor[int]())
		assert.Error(t, err)
	})
}

func TestServiceAccount_ConvertToType(t *testing.T) {
	sa := ServiceAccount{Name: "sa", Namespace: "ns"}

	t.Run("convert to SAType", func(t *testing.T) {
		result := sa.ConvertToType(SAType)
		assert.Equal(t, sa, result)
	})

	t.Run("convert to TypeType", func(t *testing.T) {
		result := sa.ConvertToType(types.TypeType)
		assert.Equal(t, SAType, result)
	})

	t.Run("convert to unsupported type should error", func(t *testing.T) {
		result := sa.ConvertToType(types.StringType)
		assert.True(t, types.IsError(result), "expected error for unsupported type conversion")
	})
}

func TestServiceAccountLib_CompileOptions(t *testing.T) {
	lib := &saLib{}
	options := lib.CompileOptions()
	assert.NotEmpty(t, options, "CompileOptions should return CEL environment options")
}

func TestServiceAccountLib_ProgramOptions(t *testing.T) {
	lib := &saLib{}
	options := lib.ProgramOptions()
	assert.Empty(t, options, "ProgramOptions should return empty slice")
}

func TestServiceAccountLib_CELIntegration(t *testing.T) {
	env, err := cel.NewEnv(
		ServiceAccountLib(),
		cel.Variable("username", cel.StringType),
	)
	require.NoError(t, err, "CEL environment should compile with ServiceAccountLib")

	tests := map[string]struct {
		expr   string
		input  map[string]any
		expect any
	}{
		"isServiceAccount should return true for valid username": {
			expr:   "isServiceAccount(username)",
			input:  map[string]any{"username": "system:serviceaccount:default:my-sa"},
			expect: true,
		},
		"isServiceAccount should return false for invalid username": {
			expr:   "isServiceAccount(username)",
			input:  map[string]any{"username": "not-valid"},
			expect: false,
		},
		"serviceAccount().getName() should return name": {
			expr:   "serviceAccount(username).getName()",
			input:  map[string]any{"username": "system:serviceaccount:test-ns:test-sa"},
			expect: "test-sa",
		},
		"serviceAccount().getNamespace() should return namespace": {
			expr:   "serviceAccount(username).getNamespace()",
			input:  map[string]any{"username": "system:serviceaccount:test-ns:test-sa"},
			expect: "test-ns",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ast, issues := env.Compile(test.expr)
			require.NoError(t, issues.Err(), "expression should compile")

			prg, err := env.Program(ast)
			require.NoError(t, err, "program should create")

			out, _, err := prg.Eval(test.input)
			require.NoError(t, err, "program should evaluate")
			assert.Equal(t, test.expect, out.Value())
		})
	}
}
