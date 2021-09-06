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

package constraints

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"strconv"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	utilpki "github.com/jetstack/cert-manager/pkg/util/pki"
	"k8s.io/apimachinery/pkg/util/validation/field"

	policyapi "github.com/cert-manager/policy-approver/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/policy-approver/pkg/approver"
)

// Evaluate evaluates whether the given CertificateRequest satisfies the
// constraints which have been defined in the CertificateRequestPolicy. The
// request _must_ satisfy _all_ constraints defined in the policy to be
// permitted by the passed policy.
// If the request is denied by the constraints an explanation is returned.
// An error signals that the policy couldn't be evaluated to completion.
func (c Constraints) Evaluate(_ context.Context, policy *policyapi.CertificateRequestPolicy, request *cmapi.CertificateRequest) (approver.EvaluationResponse, error) {
	// If no constraints defined, exit early.
	if policy.Spec.Constraints == nil {
		return approver.EvaluationResponse{Result: approver.ResultNotDenied, Message: ""}, nil
	}

	var (
		// el will contain a list of policy violations for fields, if there are
		// items in the list, then the request does not meet the constraints.
		el      field.ErrorList
		consts  = policy.Spec.Constraints
		fldPath = field.NewPath("spec", "constraints")
	)

	if consts.MaxDuration != nil {
		// If the request contains no duration or the maxDuration is smaller than requested, append error.
		if request.Spec.Duration == nil {
			el = append(el, field.Invalid(fldPath.Child("maxDuration"), request.Spec.Duration.String(), consts.MaxDuration.Duration.String()))
		} else if consts.MaxDuration.Duration < request.Spec.Duration.Duration {
			el = append(el, field.Invalid(fldPath.Child("maxDuration"), request.Spec.Duration.Duration.String(), consts.MaxDuration.Duration.String()))
		}
	}

	if consts.MinDuration != nil {
		// If the request contains no duration or the minDuration is larger than requested, append error.
		if request.Spec.Duration == nil {
			el = append(el, field.Invalid(fldPath.Child("minDuration"), request.Spec.Duration.String(), consts.MinDuration.Duration.String()))
		} else if consts.MinDuration.Duration > request.Spec.Duration.Duration {
			el = append(el, field.Invalid(fldPath.Child("minDuration"), request.Spec.Duration.Duration.String(), consts.MinDuration.Duration.String()))
		}
	}

	if consts.PrivateKey != nil {
		fldPath := fldPath.Child("privateKey")

		// Decode CSR from CertificateRequest
		csr, err := utilpki.DecodeX509CertificateRequestBytes(request.Spec.Request)
		if err != nil {
			return approver.EvaluationResponse{}, err
		}

		alg, size, err := decodePublicKey(csr.PublicKey)
		if err != nil {
			return approver.EvaluationResponse{}, err
		}

		if consts.PrivateKey.Algorithm != nil && *consts.PrivateKey.Algorithm != alg {
			el = append(el, field.Invalid(fldPath.Child("algorithm"), string(alg), string(*consts.PrivateKey.Algorithm)))
		}

		if consts.PrivateKey.MaxSize != nil && *consts.PrivateKey.MaxSize < size {
			el = append(el, field.Invalid(fldPath.Child("maxSize"), strconv.Itoa(size), strconv.Itoa(*consts.PrivateKey.MaxSize)))
		}

		if consts.PrivateKey.MinSize != nil && *consts.PrivateKey.MinSize > size {
			el = append(el, field.Invalid(fldPath.Child("minSize"), strconv.Itoa(size), strconv.Itoa(*consts.PrivateKey.MinSize)))
		}
	}

	// If there are errors, then return not approved and the aggregated errors
	if len(el) > 0 {
		return approver.EvaluationResponse{Result: approver.ResultDenied, Message: el.ToAggregate().Error()}, nil
	}

	// If no evaluation errors resulting from this policy, return not denied
	return approver.EvaluationResponse{Result: approver.ResultNotDenied}, nil
}

// decodePublicKey will return the algorithm and size of the given public key.
// If the public key cannot be decoded, an error is returned.
func decodePublicKey(pub interface{}) (cmapi.PrivateKeyAlgorithm, int, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		rsapub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return "", -1, errors.New("failed to decode RSA public key")
		}
		return cmapi.RSAKeyAlgorithm, rsapub.Size(), nil

	case *ecdsa.PublicKey:
		ecdsapub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return "", -1, errors.New("failed to decode ECDSA public key")
		}
		return cmapi.ECDSAKeyAlgorithm, ecdsapub.Curve.Params().BitSize, nil

	case *ed25519.PublicKey:
		if _, ok := pub.(*ed25519.PublicKey); !ok {
			return "", -1, errors.New("failed to decode Ed25519 public key")
		}
		return cmapi.Ed25519KeyAlgorithm, -1, nil

	default:
		return "", -1, fmt.Errorf("unrecognised public key type %T", pub)
	}
}
