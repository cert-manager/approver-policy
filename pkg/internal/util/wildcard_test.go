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

package util

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func Test_WildcardSubset(t *testing.T) {
	tests := []struct {
		patterns []string
		texts    []string
		exp      bool
	}{
		{
			patterns: []string{},
			texts:    []string{},
			exp:      true,
		},
		{
			patterns: []string{
				"cert-manager",
			},
			texts: []string{
				"cert-manager",
			},
			exp: true,
		},
		{
			patterns: []string{
				"cert-manager",
				"foo",
			},
			texts: []string{
				"cert-manager",
			},
			exp: true,
		},
		{
			patterns: []string{
				"cert-manager",
			},
			texts: []string{
				"cert-manager",
				"foo",
			},
			exp: false,
		},
		{
			patterns: []string{
				"foo",
				"cert-manager",
				"bar",
			},
			texts: []string{
				"cert-manager",
				"foo",
			},
			exp: true,
		},
		{
			patterns: []string{
				"foo",
				"cert-*",
				"bar",
			},
			texts: []string{
				"cert-manager",
				"foo",
			},
			exp: true,
		},
		{
			patterns: []string{
				"*",
			},
			texts: []string{
				"cert-manager",
				"foo",
			},
			exp: true,
		},
		{
			patterns: []string{
				"foo.*",
			},
			texts: []string{
				"cert-manager",
				"foo.",
			},
			exp: false,
		},
		{
			patterns: []string{
				"foo.*",
			},
			texts: []string{
				"foo.cert-manager",
				"foo.",
			},
			exp: true,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%v: %v", test.patterns, test.texts), func(t *testing.T) {
			if match := WildcardSubset(test.patterns, test.texts); match != test.exp {
				t.Errorf("unexpected subset (%v, %v): exp=%t got=%t",
					test.patterns, test.texts, test.exp, match)
			}
		})
	}
}

func Test_WildcardContains(t *testing.T) {
	tests := []struct {
		patterns []string
		text     string
		exp      bool
	}{
		{
			patterns: []string{},
			text:     "cert-manager",
			exp:      false,
		},
		{
			patterns: []string{
				"cert-manager",
			},
			text: "cert-manager",
			exp:  true,
		},
		{
			patterns: []string{
				"",
			},
			text: "",
			exp:  true,
		},
		{
			patterns: []string{
				"cert-manager",
				"foo",
			},
			text: "cert-manager",
			exp:  true,
		},
		{
			patterns: []string{
				"foo",
				"cert-manager",
			},
			text: "cert-manager",
			exp:  true,
		},
		{
			patterns: []string{
				"foo",
				"cert-*",
			},
			text: "cert-manager",
			exp:  true,
		},
		{
			patterns: []string{
				"foo",
				"cert-*manager",
			},
			text: "cert-manager",
			exp:  true,
		},
		{
			patterns: []string{
				"foo",
				"cert-m*",
			},
			text: "cert-",
			exp:  false,
		},
		{
			patterns: []string{
				"foo",
				"cert-manager",
			},
			text: "bar",
			exp:  false,
		},
		{
			patterns: []string{
				"foo",
				"*",
			},
			text: "bar",
			exp:  true,
		},
		{
			patterns: []string{
				"foo",
				"",
			},
			text: "bar",
			exp:  false,
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%v: %s", test.patterns, test.text), func(t *testing.T) {
			if match := WildcardContains(test.patterns, test.text); match != test.exp {
				t.Errorf("unexpected contains (%v, %q): exp=%t got=%t",
					test.patterns, test.text, test.exp, match)
			}
		})
	}
}

func Test_WildcardMatches(t *testing.T) {
	tests := map[string]struct {
		pattern string
		text    string
		exp     bool
	}{
		"only wildcard pattern: true": {
			pattern: "*",
			text:    "cert-manager",
			exp:     true,
		},
		"empty pattern: false": {
			pattern: "",
			text:    "cert-manager",
			exp:     false,
		},
		"empty pattern and text: true": {
			pattern: "",
			text:    "",
			exp:     true,
		},
		"short parrten with wildcard: true": {
			pattern: "cert-*",
			text:    "cert-manager.io",
			exp:     true,
		},
		"bigger pattern: false": {
			pattern: "cert-manager-foo",
			text:    "cert-manager",
			exp:     false,
		},
		"same pattern and text: true": {
			pattern: "cert-manager",
			text:    "cert-manager",
			exp:     true,
		},
		"same pattern with wildcard: true": {
			pattern: "cert-manager.io*",
			text:    "cert-manager.io",
			exp:     true,
		},
		"same pattern with wildcard at start: true": {
			pattern: "*cert-manager.io",
			text:    "cert-manager.io",
			exp:     true,
		},
		"same pattern with middle wildcard: true": {
			pattern: "cert-*manager.io",
			text:    "cert-manager.io",
			exp:     true,
		},
		"wrong pattern with wildcard: false": {
			pattern: "cert-foo*",
			text:    "cert-manager.io",
			exp:     false,
		},
		"pattren with wildcards inside: true": {
			pattern: "ce*t-*ger*io",
			text:    "cert-manager.io",
			exp:     true,
		},
		"pattern with wildcards inside but short: false": {
			pattern: "ce*t-*ger*.",
			text:    "cert-manager.io",
			exp:     false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if match := WildcardMatches(test.pattern, test.text); match != test.exp {
				t.Errorf("unexpected match (%q, %q): exp=%t got=%t",
					test.pattern, test.text, test.exp, match)
			}
		})
	}
}

// Test_WildcardMatches_BacktrackingDoesNotHang verifies that patterns with
// multiple wildcards do not cause exponential backtracking. The pattern
// "*a*a*a*a*a*a*a*a*!" against a string of 50 'a' characters would explore
// ~2^50 branches with the old recursive algorithm; the iterative replacement
// handles it in O(n*m). If the iterative algorithm is accidentally reverted,
// the call below will not return and the bounded select fails the test with an
// actionable message, rather than hanging until the global test timeout fires.
func Test_WildcardMatches_BacktrackingDoesNotHang(t *testing.T) {
	// 8 wildcards interleaved with 'a', ending in '!' which never appears
	// in the input string — forces full exploration of every branch.
	pattern := "*a*a*a*a*a*a*a*a*!"
	str := strings.Repeat("a", 50)

	done := make(chan bool, 1)
	go func() { done <- WildcardMatches(pattern, str) }()

	select {
	case match := <-done:
		if match {
			t.Errorf("expected no match for pattern %q against %q", pattern, str)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("WildcardMatches(%q, ...) did not return within 5s; exponential backtracking has regressed", pattern)
	}
}
