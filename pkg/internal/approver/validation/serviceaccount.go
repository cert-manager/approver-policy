package validation

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
)

func ServiceAccount() cel.EnvOption {
	return cel.Lib(saLib)
}

var saLib = &sa{}

type sa struct{}

var saLibraryDecls = map[string][]cel.FunctionOpt{
	"serviceaccount.getName": {
		cel.Overload("serviceaccount_get_name", []*cel.Type{cel.StringType}, cel.StringType,
			cel.UnaryBinding(getServiceAccountName))},
	"serviceaccount.getNamespace": {
		cel.Overload("serviceaccount_get_namespace", []*cel.Type{cel.StringType}, cel.StringType,
			cel.UnaryBinding(getServiceAccountNamespace))},
}

func getServiceAccountName(arg ref.Val) ref.Val {
	s, ok := arg.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	_, name, err := serviceaccount.SplitUsername(s)
	if err != nil {
		// Return an empty string if unable to parse the username field for circumstances where non-k8s serviceaccount username is presented
		return types.String("")
	}
	return types.String(name)
}

func getServiceAccountNamespace(arg ref.Val) ref.Val {
	s, ok := arg.Value().(string)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}
	namespace, _, err := serviceaccount.SplitUsername(s)
	if err != nil {
		// Return an empty string if unable to parse the username field for circumstances where non-k8s serviceaccount username is presented
		return types.String("")
	}
	return types.String(namespace)
}

func (*sa) CompileOptions() []cel.EnvOption {
	options := []cel.EnvOption{}
	for name, overloads := range saLibraryDecls {
		options = append(options, cel.Function(name, overloads...))
	}
	return options
}

func (*sa) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}
