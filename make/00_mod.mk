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

repo_name := github.com/cert-manager/approver-policy

kind_cluster_name := approver-policy
kind_cluster_config := $(bin_dir)/scratch/kind_cluster.yaml

build_names := manager

go_manager_source_path := cmd/main.go
go_manager_ldflags := -X $(repo_name)/pkg/internal/version.AppVersion=$(VERSION) -X $(repo_name)/pkg/internal/version.GitCommit=$(GITCOMMIT)
oci_manager_base_image_flavor := static
oci_manager_image_name := quay.io/jetstack/cert-manager-approver-policy
oci_manager_image_tag := $(VERSION)
oci_manager_image_name_development := cert-manager.local/cert-manager-approver-policy

deploy_name := approver-policy
deploy_namespace := cert-manager

api_docs_outfile := docs/api/api.md
api_docs_package := $(repo_name)/pkg/apis/policy/v1alpha1
api_docs_branch := main

helm_chart_source_dir := deploy/charts/approver-policy
helm_chart_name := cert-manager-approver-policy
helm_chart_version := $(VERSION)
define helm_values_mutation_function
$(YQ) \
	'( .image.repository = "$(oci_manager_image_name)" ) | \
	( .image.tag = "$(oci_manager_image_tag)" )' \
	$1 --inplace
endef
