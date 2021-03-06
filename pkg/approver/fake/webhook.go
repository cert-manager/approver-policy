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

	policyapi "github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1"
	"github.com/cert-manager/approver-policy/pkg/approver"
)

var _ approver.Webhook = &FakeWebhook{}

// FakeWebhook is a testing webook designed to mock webhooks with a
// pre-determined response.
type FakeWebhook struct {
	validateFunc func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error)
}

func NewFakeWebhook() *FakeWebhook {
	return new(FakeWebhook)
}

func (f *FakeWebhook) WithValidate(fn func(context.Context, *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error)) *FakeWebhook {
	f.validateFunc = fn
	return f
}

func (f *FakeWebhook) Validate(ctx context.Context, policy *policyapi.CertificateRequestPolicy) (approver.WebhookValidationResponse, error) {
	return f.validateFunc(ctx, policy)
}
