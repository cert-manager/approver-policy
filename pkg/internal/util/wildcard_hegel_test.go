/*
Copyright 2026 The cert-manager Authors.

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
	"regexp"
	"strings"
	"testing"

	"hegel.dev/go/hegel"
)

// wildcardRegexp translates a wildcard pattern into the equivalent anchored
// regular expression: '*' is the only metacharacter and matches any string
// (including across newlines), everything else is literal.
func wildcardRegexp(t testing.TB, pattern string) *regexp.Regexp {
	parts := strings.Split(pattern, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	re, err := regexp.Compile("(?s)\\A" + strings.Join(parts, ".*") + "\\z")
	if err != nil {
		t.Fatalf("failed to compile oracle regexp for %q: %v", pattern, err)
	}
	return re
}

// drawPattern draws a wildcard pattern built from short literal chunks
// (including multi-byte runes, since matching is rune-based) interleaved
// with '*' wildcards.
func drawPattern(tc hegel.TestCase) string {
	chunks := hegel.Draw(tc, hegel.Lists(hegel.SampledFrom([]string{
		"", "a", "b", "ab", "ba", "aa", "cert-", "manager", ".io", "é", "日本",
	})).MaxSize(5))
	sep := "*"
	if hegel.Draw(tc, hegel.Booleans()) {
		sep = ""
	}
	return strings.Join(chunks, sep)
}

// drawCandidate draws a string to match against the pattern: either an
// instantiation of the pattern (each '*' replaced by drawn text, so matches
// are actually exercised) or an unrelated string from the same alphabet,
// optionally mutated by dropping a rune.
func drawCandidate(tc hegel.TestCase, pattern string) string {
	var s string
	if hegel.Draw(tc, hegel.Booleans()) {
		expansion := func() string {
			return hegel.Draw(tc, hegel.SampledFrom([]string{"", "a", "b", "x", "aab", "é日"}))
		}
		var b strings.Builder
		for _, r := range pattern {
			if r == '*' {
				b.WriteString(expansion())
			} else {
				b.WriteRune(r)
			}
		}
		s = b.String()
	} else {
		s = drawPattern(tc) // reuse: any string over the same alphabet, may contain literal '*'
	}
	if runes := []rune(s); len(runes) > 0 && hegel.Draw(tc, hegel.Booleans()) {
		i := hegel.Draw(tc, hegel.Integers(0, len(runes)-1))
		s = string(append(runes[:i:i], runes[i+1:]...))
	}
	return s
}

// TestWildcardMatchesAgainstRegexpOracle checks WildcardMatches against an
// independent implementation of the same language: the pattern translated to
// an anchored regular expression. Every row of the old example tables is an
// instance of this rule.
func TestWildcardMatchesAgainstRegexpOracle(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		pattern := drawPattern(ht)
		str := drawCandidate(ht, pattern)
		got := WildcardMatches(pattern, str)
		want := wildcardRegexp(t, pattern).MatchString(str)
		if got != want {
			ht.Fatalf("WildcardMatches(%q, %q) = %t, regexp oracle says %t", pattern, str, got, want)
		}
	}, hegel.WithTestCases(5000))
}

// TestWildcardContainsAndSubsetLaws checks that WildcardContains is
// "any pattern matches" and WildcardSubset is "every member is contained",
// against the regexp oracle for the individual matches.
func TestWildcardContainsAndSubsetLaws(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		patterns := hegel.Draw(ht, hegel.Lists(hegel.Composite(drawPattern)).MaxSize(3))
		var members []string
		for range hegel.Draw(ht, hegel.Integers(0, 3)) {
			p := ""
			if len(patterns) > 0 {
				p = hegel.Draw(ht, hegel.SampledFrom(patterns))
			}
			members = append(members, drawCandidate(ht, p))
		}

		match := func(member string) bool {
			for _, p := range patterns {
				if wildcardRegexp(t, p).MatchString(member) {
					return true
				}
			}
			return false
		}

		for _, m := range members {
			if got, want := WildcardContains(patterns, m), match(m); got != want {
				ht.Fatalf("WildcardContains(%q, %q) = %t, want %t", patterns, m, got, want)
			}
		}
		wantSubset := true
		for _, m := range members {
			if !match(m) {
				wantSubset = false
			}
		}
		if got := WildcardSubset(patterns, members); got != wantSubset {
			ht.Fatalf("WildcardSubset(%q, %q) = %t, want %t", patterns, members, got, wantSubset)
		}
	}, hegel.WithTestCases(2000))
}
