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
	"errors"
	"fmt"
	"reflect"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

const (
	varSelf    = "self"
	varRequest = "cr"
)

// Validator knows how to validate CSR attribute values in CertificateRequests
// against CEL expressions declared in CertificateRequestPolicy.
// Validator is stateless, thread-safe, and cacheable.
type Validator interface {
	// Validate validates the supplied value against the Validator CEL
	// expression in the context of the request.
	// Returns 'true' if the value is valid (passes validation).
	// Returned errors should be considered as internal/technical errors,
	// and should NOT be returned unprocessed to end-users of the API.
	// CEL program errors are usually not very human-readable and require
	// knowledge of how CEL works and is used.
	Validate(value string, request cmapi.CertificateRequest) (bool, error)
}

type validator struct {
	expression string
	program    cel.Program
}

func (v *validator) compile() error {
	if v.program != nil {
		// Already compiled
		return nil
	}

	env, err := cel.NewEnv(
		cel.Types(&CertificateRequest{}),
		cel.Variable(varSelf, cel.StringType),
		cel.Variable(varRequest, cel.ObjectType("cm.io.policy.pkg.internal.approver.validation.CertificateRequest")),
		ext.Strings(),
	)
	if err != nil {
		return err
	}

	ast, iss := env.Compile(v.expression)
	if iss.Err() != nil {
		return iss.Err()
	}
	if !reflect.DeepEqual(ast.OutputType(), cel.BoolType) {
		return fmt.Errorf(
			"got %v, wanted %v result type", ast.OutputType(), cel.BoolType)
	}

	v.program, err = env.Program(ast)
	return err
}

func (v *validator) Validate(value string, request cmapi.CertificateRequest) (bool, error) {
	if v.program == nil {
		return false, errors.New("must compile first")
	}

	vars := map[string]interface{}{
		varSelf: value,
		varRequest: &CertificateRequest{
			Name:      request.GetName(),
			Namespace: request.GetNamespace(),
		},
	}

	out, _, err := v.program.Eval(vars)
	if err != nil {
		return false, err
	}

	return out.Value().(bool), nil
}
