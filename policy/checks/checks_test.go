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

package checks

import (
	"net"
	"net/url"
	"testing"
	"time"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestStringSlice(t *testing.T) {
	tests := map[string]struct {
		policy  *[]string
		request []string
		expErr  bool
	}{
		"if policy is nil, never error (empty request)": {
			policy:  nil,
			request: []string{},
			expErr:  false,
		},
		"if policy is nil, never error (non-empty request)": {
			policy:  nil,
			request: []string{"foo", "bar"},
			expErr:  false,
		},
		"if policy is empty list, don't error on empty request list": {
			policy:  &[]string{},
			request: []string{},
			expErr:  false,
		},
		"if policy is empty list, error on any non-empty request list": {
			policy:  &[]string{},
			request: []string{"foo.bar"},
			expErr:  true,
		},
		"if single policy that matches request, don't error": {
			policy: &[]string{
				"cert-manager",
			},
			request: []string{
				"cert-manager",
			},
			expErr: false,
		},
		"if two policies and single request where one matches, don't error": {
			policy: &[]string{
				"cert-manager",
				"foo",
			},
			request: []string{
				"cert-manager",
			},
			expErr: false,
		},
		"if policy is a subset of request, error": {
			policy: &[]string{
				"cert-manager",
			},
			request: []string{
				"cert-manager",
				"foo",
			},
			expErr: true,
		},
		"if request is a subset of policy, don't error": {
			policy: &[]string{
				"foo",
				"cert-manager",
				"bar",
			},
			request: []string{
				"cert-manager",
				"foo",
			},
			expErr: false,
		},
		"if request is a subset and policy has a match with wildcard, don't error": {
			policy: &[]string{
				"foo",
				"cert-*",
				"bar",
			},
			request: []string{
				"cert-manager",
				"foo",
			},
			expErr: false,
		},
		"if policy single wildcard and multiple requests, don't error": {
			policy: &[]string{
				"*",
			},
			request: []string{
				"cert-manager",
				"foo",
			},
			expErr: false,
		},
		"if policy is single wildcard that only matches one, error": {
			policy: &[]string{
				"foo.*",
			},
			request: []string{
				"cert-manager",
				"foo.",
			},
			expErr: true,
		},
		"if single policy wildcard matches both requests, don't error": {
			policy: &[]string{
				"foo.*",
			},
			request: []string{
				"foo.cert-manager",
				"foo.",
			},
			expErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var (
				policyKU *[]cmapi.KeyUsage
			)

			if test.policy != nil {
				policyKU = new([]cmapi.KeyUsage)
				for _, p := range *test.policy {
					*policyKU = append(*policyKU, cmapi.KeyUsage(p))
				}
			}

			var (
				requestURL []*url.URL
				requestKU  []cmapi.KeyUsage
			)
			for _, r := range test.request {
				urlR, err := url.Parse(r)
				if err != nil {
					t.Fatal(err)
				}

				requestURL = append(requestURL, urlR)
				requestKU = append(requestKU, cmapi.KeyUsage(r))
			}

			for name, testcase := range map[string]struct {
				fn      func(el *field.ErrorList, path *field.Path, policy, request interface{})
				policy  interface{}
				request interface{}
			}{
				"StringSlice": {
					fn: func(el *field.ErrorList, path *field.Path, policy, request interface{}) {
						StringSlice(el, path, policy.(*[]string), request.([]string))
					},
					policy:  test.policy,
					request: test.request,
				},
				"URLSlice": {
					fn: func(el *field.ErrorList, path *field.Path, policy, request interface{}) {
						URLSlice(el, path, policy.(*[]string), request.([]*url.URL))
					},
					policy:  test.policy,
					request: requestURL,
				},
				"KeyUsageSlice": {
					fn: func(el *field.ErrorList, path *field.Path, policy, request interface{}) {
						KeyUsageSlice(el, path, policy.(*[]cmapi.KeyUsage), request.([]cmapi.KeyUsage))
					},
					policy:  policyKU,
					request: requestKU,
				},
			} {
				var el field.ErrorList
				testcase.fn(&el, field.NewPath(""), testcase.policy, testcase.request)

				if (len(el) > 0) != test.expErr {
					t.Errorf("%s: unexpected result, policy=%v request=%v exp=%t got=%v",
						name, testcase.policy, testcase.request, test.expErr, el)
				}
			}
		})
	}
}

func TestIPSlice(t *testing.T) {
	tests := map[string]struct {
		policy  *[]string
		request []net.IP
		expErr  bool
	}{
		"if policy is nil and request is empty, don't error": {
			policy:  nil,
			request: []net.IP{},
			expErr:  false,
		},
		"if policy is empty list and request empty, don't error": {
			policy:  &[]string{},
			request: []net.IP{},
			expErr:  false,
		},
		"if policy is nil and request is not empty, don't error": {
			policy: nil,
			request: []net.IP{
				net.ParseIP("1.2.3.4"),
			},
			expErr: false,
		},
		"if single policy with wildcard and request is not empty, don't error": {
			policy: &[]string{
				"*",
			},
			request: []net.IP{
				net.ParseIP("1.2.3.4"),
			},
			expErr: false,
		},
		"if two policies with one all wildcard, other random, and request is not empty, don't error": {
			policy: &[]string{
				"*",
				"4.5.6.7",
			},
			request: []net.IP{
				net.ParseIP("1.2.3.4"),
			},
			expErr: false,
		},
		"if two policies with one wildcard but one doesn't match, other random, and request is not empty, error": {
			policy: &[]string{
				"3.*",
				"4.5.6.7",
			},
			request: []net.IP{
				net.ParseIP("1.2.3.4"),
			},
			expErr: true,
		},
		"if two policies with one exactly matches, other random, and request is not empty, don't error": {
			policy: &[]string{
				"1.2.*",
				"4.5.6.7",
			},
			request: []net.IP{
				net.ParseIP("1.2.3.4"),
			},
			expErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var el field.ErrorList
			IPSlice(&el, field.NewPath(""), test.policy, test.request)

			if (len(el) > 0) != test.expErr {
				t.Errorf("IPSlice: unexpected result, policy=%v request=%v exp=%t got=%v",
					test.policy, test.request, test.expErr, el)
			}
		})
	}
}

func TestObjectReference(t *testing.T) {
	tests := map[string]struct {
		policy  *[]cmmeta.ObjectReference
		request cmmeta.ObjectReference
		expErr  bool
	}{
		"if policy is nil and request is empty, don't error": {
			policy:  nil,
			request: cmmeta.ObjectReference{},
			expErr:  false,
		},
		"if policy is empty list, always error": {
			policy:  &[]cmmeta.ObjectReference{},
			request: cmmeta.ObjectReference{},
			expErr:  true,
		},
		"if policy is nil and request is not empty, don't error": {
			policy: nil,
			request: cmmeta.ObjectReference{
				Name:  "foo",
				Kind:  "bar",
				Group: "example.com",
			},
			expErr: false,
		},
		"if single policy with all wildcard and request is not empty, don't error": {
			policy: &[]cmmeta.ObjectReference{
				{
					Name:  "*",
					Kind:  "*",
					Group: "*",
				},
			},
			request: cmmeta.ObjectReference{
				Name:  "foo",
				Kind:  "bar",
				Group: "example.com",
			},
			expErr: false,
		},
		"if two policies with one all wildcard, other random, and request is not empty, don't error": {
			policy: &[]cmmeta.ObjectReference{
				{
					Name:  "policy-name",
					Kind:  "policy-kind",
					Group: "policy-group",
				},
				{
					Name:  "*",
					Kind:  "*",
					Group: "*",
				},
			},
			request: cmmeta.ObjectReference{
				Name:  "foo",
				Kind:  "bar",
				Group: "example.com",
			},
			expErr: false,
		},
		"if two policies with one wildcard but one doesn't match, other random, and request is not empty, error": {
			policy: &[]cmmeta.ObjectReference{
				{
					Name:  "policy-name",
					Kind:  "policy-kind",
					Group: "policy-group",
				},
				{
					Name:  "*foo",
					Kind:  "bar*",
					Group: "*.io",
				},
			},
			request: cmmeta.ObjectReference{
				Name:  "foo",
				Kind:  "bar",
				Group: "example.com",
			},
			expErr: true,
		},
		"if two policies with one exactly matches, other random, and request is not empty, don't error": {
			policy: &[]cmmeta.ObjectReference{
				{
					Name:  "policy-name",
					Kind:  "policy-kind",
					Group: "policy-group",
				},
				{
					Name:  "foo",
					Kind:  "bar",
					Group: "example.com",
				},
			},
			request: cmmeta.ObjectReference{
				Name:  "foo",
				Kind:  "bar",
				Group: "example.com",
			},
			expErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			var el field.ErrorList
			ObjectReference(&el, field.NewPath(""), test.policy, test.request)

			if (len(el) > 0) != test.expErr {
				t.Errorf("ObjectReference: unexpected result, policy=%v request=%v exp=%t got=%v",
					test.policy, test.request, test.expErr, el)
			}
		})
	}
}

func TestMinMax(t *testing.T) {
	tests := map[string]struct {
		policy  *int
		request int

		expMinErr, expMaxErr bool
	}{
		"if policy is nil, any request value (+) shouldn't error": {
			policy:    nil,
			request:   1,
			expMinErr: false,
			expMaxErr: false,
		},
		"if policy is nil, any request value (-) shouldn't error": {
			policy:    nil,
			request:   -1,
			expMinErr: false,
			expMaxErr: false,
		},
		"if policy is the same as request, should not error": {
			policy:    intPtr(1),
			request:   1,
			expMinErr: false,
			expMaxErr: false,
		},
		"if policy is larger than request, min should error, max should not error": {
			policy:    intPtr(2),
			request:   1,
			expMinErr: true,
			expMaxErr: false,
		},
		"if policy is smaller than request, min should not error, max should error": {
			policy:    intPtr(1),
			request:   2,
			expMinErr: false,
			expMaxErr: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			policySize := test.policy
			var policyDuration *metav1.Duration
			if test.policy != nil {
				policyDuration = &metav1.Duration{
					Duration: time.Duration(*test.policy),
				}
			}

			requestSize := test.request
			requestDuration := &metav1.Duration{
				Duration: time.Duration(test.request),
			}

			for name, testcase := range map[string]struct {
				fn      func(el *field.ErrorList, path *field.Path, policy, request interface{})
				policy  interface{}
				request interface{}
				expErr  bool
			}{
				"MinSize": {
					fn: func(el *field.ErrorList, path *field.Path, policy, request interface{}) {
						MinSize(el, path, policy.(*int), request.(int))
					},
					policy:  policySize,
					request: requestSize,
					expErr:  test.expMinErr,
				},
				"MaxSize": {
					fn: func(el *field.ErrorList, path *field.Path, policy, request interface{}) {
						MaxSize(el, path, policy.(*int), request.(int))
					},
					policy:  policySize,
					request: requestSize,
					expErr:  test.expMaxErr,
				},
				"MinDuration": {
					fn: func(el *field.ErrorList, path *field.Path, policy, request interface{}) {
						MinDuration(el, path, policy.(*metav1.Duration), request.(*metav1.Duration))
					},
					policy:  policyDuration,
					request: requestDuration,
					expErr:  test.expMinErr,
				},
				"MaxDuration": {
					fn: func(el *field.ErrorList, path *field.Path, policy, request interface{}) {
						MaxDuration(el, path, policy.(*metav1.Duration), request.(*metav1.Duration))
					},
					policy:  policyDuration,
					request: requestDuration,
					expErr:  test.expMaxErr,
				},
			} {
				var el field.ErrorList
				testcase.fn(&el, field.NewPath(""), testcase.policy, testcase.request)

				if (len(el) > 0) != testcase.expErr {
					t.Errorf("%s: unexpected result, policy=%v request=%v exp=%t got=%v",
						name, testcase.policy, testcase.request, testcase.expErr, el)
				}
			}
		})
	}
}

func intPtr(i int) *int {
	return &i
}
