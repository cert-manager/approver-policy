# Copyright 2023 The cert-manager Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ifndef bin_dir
$(error bin_dir is not set)
endif

.PHONY: verify-govulncheck
## Verify all Go modules for vulnerabilities using govulncheck
## @category [shared] Generate/ Verify
#
# Runs `govulncheck` on all Go modules related to the project.
# Ignores Go modules among the temporary build artifacts in _bin, to avoid
# scanning the code of the vendored Go, after running make vendor-go.
# Ignores Go modules in make/_shared, because those will be checked in centrally
# in the makefile_modules repository.
#
# `verify-govulncheck` not added to the `shared_verify_targets` variable and is
# not run by `make verify`, because `make verify` is run for each PR, and we do
# not want new vulnerabilities in existing code to block the merging of PRs.
# Instead `make verify-govulnecheck` is intended to be run periodically by a CI job.
verify-govulncheck: | $(NEEDS_GOVULNCHECK)
	@find . -name go.mod -not \( -path "./$(bin_dir)/*" -or -path "./make/_shared/*" \) -printf '%h\n' \
		| while read d; do \
				echo "Running 'GOTOOLCHAIN=go$(VENDORED_GO_VERSION) $(bin_dir)/tools/govulncheck ./...' in directory '$${d}'"; \
				pushd "$${d}" >/dev/null; \
				GOTOOLCHAIN=go$(VENDORED_GO_VERSION) $(GOVULNCHECK) ./... || exit; \
				popd >/dev/null; \
				echo ""; \
			done
