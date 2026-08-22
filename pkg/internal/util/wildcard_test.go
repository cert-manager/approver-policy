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
	"strings"
	"testing"
	"time"
)

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
