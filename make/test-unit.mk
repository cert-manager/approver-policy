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

approver_policy_crds := $(bin_dir)/scratch/approver-policy-crds.yaml
$(approver_policy_crds): $(helm_chart_archive) | $(NEEDS_HELM) $(NEEDS_YQ) $(bin_dir)/scratch
	$(HELM) template test "$(helm_chart_archive)" | \
		$(YQ) e '. | select(.kind == "CustomResourceDefinition")' \
		> $@

.PHONY: test-unit
## Unit tests
## @category Testing
test-unit: | $(cert_manager_crds) $(approver_policy_crds) $(NEEDS_GINKGO) $(NEEDS_ETCD) $(NEEDS_KUBE-APISERVER) $(NEEDS_KUBECTL)
	CERT_MANAGER_CRDS=$(CURDIR)/$(cert_manager_crds) \
	APPROVER_POLICY_CRDS=$(CURDIR)/$(approver_policy_crds) \
	KUBEBUILDER_ASSETS=$(CURDIR)/$(bin_dir)/tools \
	$(GINKGO) \
		./cmd/... ./pkg/... \
		-procs=1 \
		-v \
		-ldflags $(go_manager_ldflags)
