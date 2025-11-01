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
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
)

var (
	SAType = cel.ObjectType("cm.io.policy.pkg.internal.approver.validation.ServiceAccount")
)

type saLib struct{}
type ServiceAccount struct {
	Name      string
	Namespace string
}

func ServiceAccountLib() cel.EnvOption {
	return cel.Lib(&saLib{})
}

// ConvertToNative implements ref.Val.ConvertToNative.
func (sa ServiceAccount) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeFor[ServiceAccount]().AssignableTo(typeDesc) {
		return sa, nil
	}
	if reflect.TypeFor[string]().AssignableTo(typeDesc) {
		return serviceaccount.MakeUsername(sa.Namespace, sa.Name), nil
	}
	return nil, fmt.Errorf("type conversion error from 'serviceaccount' to '%v'", typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (sa ServiceAccount) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case SAType:
		return sa
	case types.TypeType:
		return SAType
	}
	return types.NewErr("type conversion error from '%s' to '%s'", SAType, typeVal)
}

// Equal implements ref.Val.Equal.
func (sa ServiceAccount) Equal(other ref.Val) ref.Val {
	otherSA, ok := other.(ServiceAccount)
	if !ok {
		return types.MaybeNoSuchOverloadErr(other)
	}
	return types.Bool(sa.Name == otherSA.Name && sa.Namespace == otherSA.Namespace)
}

// Type implements ref.Val.Type.Y
func (sa ServiceAccount) Type() ref.Type {
	return SAType
}

// Value implements ref.Val.Value.
func (sa ServiceAccount) Value() any {
	return sa
}

var saLibraryDecls = map[string][]cel.FunctionOpt{
	"serviceAccount": {
		cel.Overload("username_to_serviceaccount", []*cel.Type{cel.StringType}, SAType,
			cel.UnaryBinding(stringToServiceAccount))},
	"getName": {
		cel.MemberOverload("serviceaccount_get_name", []*cel.Type{SAType}, cel.StringType,
			cel.UnaryBinding(getServiceAccountName))},
	"getNamespace": {
		cel.MemberOverload("serviceaccount_get_namespace", []*cel.Type{SAType}, cel.StringType,
			cel.UnaryBinding(getServiceAccountNamespace))},
	"isServiceAccount": {
		cel.Overload("serviceaccount_is_sa", []*cel.Type{cel.StringType}, cel.BoolType,
			cel.UnaryBinding(isServiceAccount))},
}

func stringToServiceAccount(arg ref.Val) ref.Val {
	s, ok := arg.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	ns, name, err := serviceaccount.SplitUsername(s)

	if err != nil {
		return types.NewErr("Unable to convert to serviceaccount: err: %s, username: %s", err, s)
	}

	return ServiceAccount{
		Name:      name,
		Namespace: ns,
	}
}

func isServiceAccount(arg ref.Val) ref.Val {
	s, ok := arg.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	_, _, err := serviceaccount.SplitUsername(s)

	if err != nil {
		return types.False
	}

	return types.True
}

func getServiceAccountName(arg ref.Val) ref.Val {
	s, ok := arg.Value().(ServiceAccount)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return types.String(s.Name)
}

func getServiceAccountNamespace(arg ref.Val) ref.Val {
	s, ok := arg.Value().(ServiceAccount)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return types.String(s.Namespace)
}

func (*saLib) CompileOptions() []cel.EnvOption {
	options := []cel.EnvOption{}
	for name, overloads := range saLibraryDecls {
		options = append(options, cel.Function(name, overloads...))
	}
	return options
}

func (*saLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}
