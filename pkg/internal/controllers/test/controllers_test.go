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

package test

import (
	"context"
	"path/filepath"
	"testing"

	testenv "github.com/cert-manager/approver-policy/test/env"
)

// Test_Controllers runs the full suite of tests for the approver-policy
// controllers.
func Test_Controllers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	t.Cleanup(func() {
		cancel()
	})

	rootDir := testenv.RootDirOrSkip(t)

	env = testenv.RunControlPlane(t, ctx,
		filepath.Join(rootDir, "_bin/cert-manager"),
		filepath.Join(rootDir, "deploy/charts/approver-policy/templates/crds"),
	)
	testenv.RunSuite(t, "approver-policy-controllers", "../../../../_artifacts")
}
