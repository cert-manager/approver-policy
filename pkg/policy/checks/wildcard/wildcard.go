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
// Modified from https://github.com/minio/minio/blob/RELEASE.2020-06-22T03-12-50Z.hotfix/pkg/wildcard/match.go

package wildcard

// Wildcards '*' in patterns represent any string which has a length of 0 or
// more. A pattern containing only "*" will match anything. A pattern
// containing "*foo" will match "foo" as well as any string which ends in "foo"
// (e.g. "bar-foo").

// Subset returns whether the members is a subset of patterns which can include
// wildcards ('*'). Members is a subset of patterns if all members can be
// expressed by at least one passed pattern. The slice length of patterns can
// be less than members.
func Subset(patterns, members []string) bool {
	for _, member := range members {
		if !Contains(patterns, member) {
			return false
		}
	}

	return true
}

// Contains will return true if the given string matches at least one of the
// passed patterns. Patterns is a string slice which supports wildcards ('*').
func Contains(patterns []string, member string) bool {
	for _, pattern := range patterns {
		if Matchs(pattern, member) {
			return true
		}
	}

	return false
}

// Matches will return true if the given string matches the pattern. Pattern is
// a string which supports wildcards ('*').
func Matchs(pattern, str string) bool {
	if len(pattern) == 0 {
		return len(str) == 0
	}

	if pattern == "*" {
		return true
	}

	return matchRunes([]rune(pattern), []rune(str))
}

// matchRunes will return whether the given rune slice matches the given
// pattern using wildcards ('*').
func matchRunes(pattern, str []rune) bool {
	for len(pattern) > 0 {
		switch pattern[0] {

		// If '*' then branch with recursive check for before and after '*'
		case '*':
			return matchRunes(pattern[1:], str) || (len(str) > 0 && matchRunes(pattern, str[1:]))

		// If still strings to match or patter and string don't match at index, no match.
		default:
			if len(str) == 0 || str[0] != pattern[0] {
				return false
			}
		}

		str = str[1:]
		pattern = pattern[1:]
	}

	// If both empty, then match
	return len(str) == 0 && len(pattern) == 0
}
