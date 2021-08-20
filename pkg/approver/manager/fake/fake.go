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

package fake

import (
	"context"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"

	"github.com/cert-manager/policy-approver/pkg/approver/manager"
)

var _ manager.Interface = &FakeManager{}

// FakeManager is a testing manager designed to mock managers with a determined
// response.
type FakeManager struct {
	reviewFunc func(context.Context, *cmapi.CertificateRequest) (bool, string, error)
}

func NewFakeManager() *FakeManager {
	return new(FakeManager)
}

func (f *FakeManager) WithReview(fn func(context.Context, *cmapi.CertificateRequest) (bool, string, error)) *FakeManager {
	f.reviewFunc = fn
	return f
}

func (f *FakeManager) Review(ctx context.Context, cr *cmapi.CertificateRequest) (bool, string, error) {
	return f.reviewFunc(ctx, cr)
}
