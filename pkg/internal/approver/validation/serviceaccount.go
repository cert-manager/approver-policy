package validation

import (
	"fmt"
	reflect "reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
)

func ServiceAccountLib() cel.EnvOption {
	return cel.Lib(&saLib{})
}

type saLib struct{}
type ServiceAccount struct {
	Name             string
	Namespace        string
	IsServiceAccount bool
}

var (
	SAType = cel.ObjectType("cm.io.policy.pkg.internal.approver.validation.ServiceAccount")
)

// ConvertToNative implements ref.Val.ConvertToNative.
func (sa ServiceAccount) ConvertToNative(typeDesc reflect.Type) (interface{}, error) {
	if reflect.TypeOf(sa).AssignableTo(typeDesc) {
		return sa, nil
	}
	if reflect.TypeOf("").AssignableTo(typeDesc) {
		return sa, nil
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
	otherDur, ok := other.(ServiceAccount)
	if !ok {
		return types.MaybeNoSuchOverloadErr(other)
	}
	return types.Bool(sa.IsServiceAccount && otherDur.IsServiceAccount && sa.Name == otherDur.Name && sa.Namespace == otherDur.Namespace)
}

// Type implements ref.Val.Type.Y
func (sa ServiceAccount) Type() ref.Type {
	return SAType
}

// Value implements ref.Val.Value.
func (sa ServiceAccount) Value() interface{} {
	return sa
}

var saLibraryDecls = map[string][]cel.FunctionOpt{
	"ServiceAccount": {
		cel.Overload("username_to_serviceaccount", []*cel.Type{cel.StringType}, SAType,
			cel.UnaryBinding(stringToServiceAccount))},
	"getName": {
		cel.MemberOverload("serviceaccount_get_name", []*cel.Type{SAType}, cel.StringType,
			cel.UnaryBinding(getServiceAccountName))},
	"getNamespace": {
		cel.MemberOverload("serviceaccount_get_namespace", []*cel.Type{SAType}, cel.StringType,
			cel.UnaryBinding(getServiceAccountNamespace))},
	"isServiceAccount": {
		cel.MemberOverload("serviceaccount_is_sa", []*cel.Type{SAType}, cel.BoolType,
			cel.UnaryBinding(isServiceAccount))},
}

func stringToServiceAccount(arg ref.Val) ref.Val {
	s, ok := arg.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	ns, name, err := serviceaccount.SplitUsername(s)

	if err != nil {
		return ServiceAccount{
			Name:             "",
			Namespace:        "",
			IsServiceAccount: false,
		}
	}

	return ServiceAccount{
		Name:             name,
		Namespace:        ns,
		IsServiceAccount: true,
	}
}

func isServiceAccount(arg ref.Val) ref.Val {
	s, ok := arg.Value().(ServiceAccount)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return types.Bool(s.IsServiceAccount)
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
