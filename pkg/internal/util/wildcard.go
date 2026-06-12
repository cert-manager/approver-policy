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

// !!
// Originally adapted from minio's wildcard matcher (minio/minio, now archived):
// https://github.com/minio/minio/blob/RELEASE.2020-06-22T03-12-50Z/pkg/wildcard/match.go
//
// matchRunes (below) has since been rewritten to an iterative algorithm and is
// intentionally not a drop-in copy of the version now maintained at
// https://github.com/minio/pkg/blob/main/wildcard/match.go: that one is still
// recursive, and unlike minio we support only '*' (not '?') and match on runes
// rather than bytes. Prefer not to re-sync from upstream.

package util

// Wildcards '*' in patterns represent any string which has a length of 0 or
// more. A pattern containing only "*" will match anything. A pattern
// containing "*foo" will match "foo" as well as any string which ends in "foo"
// (e.g. "bar-foo").

// WildcardSubset returns whether the members is a subset of patterns which can
// include wildcards ('*'). Members is a subset of patterns if all members can
// be expressed by at least one passed pattern. The slice length of patterns
// can be less than members.
func WildcardSubset(patterns, members []string) bool {
	for _, member := range members {
		if !WildcardContains(patterns, member) {
			return false
		}
	}

	return true
}

// WildcardContains will return true if the given string matches at least one
// of the passed patterns. Patterns is a string slice which supports wildcards
// ('*').
func WildcardContains(patterns []string, member string) bool {
	for _, pattern := range patterns {
		if WildcardMatches(pattern, member) {
			return true
		}
	}

	return false
}

// WildcardMatches will return true if the given string matches the pattern.
// Pattern is a string which supports wildcards ('*').
func WildcardMatches(pattern, str string) bool {
	if len(pattern) == 0 {
		return len(str) == 0
	}

	if pattern == "*" {
		return true
	}

	return matchRunes([]rune(pattern), []rune(str))
}

// matchRunes returns whether str matches pattern using '*' wildcards.
// It uses an iterative backtrack-checkpoint algorithm that runs in O(n*m)
// time, replacing the original recursive implementation which was O(2^n)
// with multiple wildcards. See CWE-770.
//
// This is the standard greedy wildcard matcher: on each '*' we record a single
// checkpoint (starPx/starSx) and, on a later mismatch, rewind str one past that
// checkpoint rather than forking into two recursive calls. Only the most recent
// '*' needs remembering. The same technique backs Go's path/filepath.Match,
// glibc's glob(3) and many other production matchers. References:
//   - Russ Cox, "Glob Matching Can Be Simple And Fast Too" https://research.swtch.com/glob
//   - https://en.wikipedia.org/wiki/Matching_wildcards (non-recursive section)
func matchRunes(pattern, str []rune) bool {
	px, sx := 0, 0
	starPx, starSx := -1, -1

	for sx < len(str) {
		switch {
		case px < len(pattern) && pattern[px] == '*':
			// Record a checkpoint at the '*' and try to match it against the
			// empty string first.
			starPx, starSx = px, sx
			px++
		case px < len(pattern) && pattern[px] == str[sx]:
			// Literal match; advance both positions.
			px++
			sx++
		case starPx >= 0:
			// Mismatch, but a '*' is still open: backtrack to it and let it
			// consume one more character of str.
			starSx++
			sx = starSx
			px = starPx + 1
		default:
			// Mismatch with no '*' to fall back on.
			return false
		}
	}

	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}
