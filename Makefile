# Copyright 2021 The cert-manager Authors.
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
MAKEFLAGS += --warn-undefined-variables --no-builtin-rules
SHELL := /usr/bin/env bash
.SHELLFLAGS := -uo pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
.SUFFIXES:
FORCE:

# The version of approver-policy
VERSION ?= $(shell git describe --tags --always --dirty --match='v*' --abbrev=14)

BINDIR := $(CURDIR)/_bin

.PHONY: all
all: help

ARCH   ?= $(shell go env GOARCH)
OS     ?= $(shell go env GOOS)

# Check https://github.com/helm/helm/releases for latest available release
HELM_VERSION ?= 3.11.3
# Check https://github.com/kubernetes-sigs/kubebuilder/blob/tools-releases/build/cloudbuild_tools.yaml
# for latest available tag
KUBEBUILDER_TOOLS_VERSION ?= 1.27.1
# Check https://github.com/kyverno/kyverno/releases for latest available release
KYVERNO_VERSION ?= v1.10.0
K8S_CLUSTER_NAME ?= approver-policy
IMAGE_REGISTRY ?= quay.io/jetstack
IMAGE_NAME := cert-manager-approver-policy
IMAGE_TAG := $(VERSION)
IMAGE := $(IMAGE_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

GOMARKDOC_FLAGS=--format github --repository.url "https://github.com/cert-manager/approver-policy" --repository.default-branch master --repository.path /

# An OCI Helm chart registry where the Helm package will be uploaded on release.
# Empty by default to prevent accidental publication of the Helm chart.
HELM_CHART_REGISTRY ?=

helm_chart_archive := $(BINDIR)/charts/cert-manager-approver-policy-$(VERSION).tgz

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Utilities

.PHONY: clean
clean: ## clean up created files
	rm -rf \
		$(BINDIR) \
		_artifacts

##@ Build

.PHONY: build
build: $(BINDIR) ## Build manager binary.
	CGO_ENABLED=0 go build -o bin/approver-policy ./cmd/

.PHONY: image
image: ## build docker image
	docker build --tag ${IMAGE} --build-arg VERSION=$(VERSION) .

##@ Development

.PHONY: generate-manifests
generate-manifests: ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
generate-manifests: | $(BINDIR)/controller-gen
	$(BINDIR)/controller-gen rbac:roleName=manager-role crd webhook paths="./..." \
		output:crd:artifacts:config=$(helm_chart_source_dir)/templates/crds

.PHONY: generate-deepcopy
generate-deepcopy: ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
generate-deepcopy: | $(BINDIR)/controller-gen
	$(BINDIR)/controller-gen object:headerFile="hack/boilerplate/boilerplate.go.txt" paths="./..."

.PHONY: generate-helm-docs
generate-helm-docs: ## Generate helm docs
generate-helm-docs: | $(BINDIR)/helm-docs
	$(BINDIR)/helm-docs deploy/charts/approver-policy

.PHONY: generate-api-docs
generate-api-docs: | $(BINDIR)/gomarkdoc
	mkdir -p docs/api
	$(BINDIR)/gomarkdoc $(GOMARKDOC_FLAGS) --output docs/api/api.md github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1

.PHONY: generate
generate: ## generate code and documentation
generate: fmt
generate: generate-manifests
generate: generate-deepcopy
generate: generate-helm-docs
generate: generate-api-docs

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

##@ Testing

.PHONY: verify-pod-security-standards
verify-pod-security-standards: $(helm_chart_archive) | $(BINDIR)/kyverno $(BINDIR)/kustomize $(BINDIR)/helm
	$(BINDIR)/kyverno apply <($(BINDIR)/kustomize build https://github.com/kyverno/policies/pod-security/enforce) \
		--resource <($(BINDIR)/helm template $(helm_chart_archive)) 2>/dev/null

# Run both `helm lint` and `helm template`, to check that the templates can be rendered.
.PHONY: verify-helm-lint
verify-helm-lint: $(helm_chart_archive) | $(BINDIR)/helm
	$(BINDIR)/helm lint $(helm_chart_archive)
	$(BINDIR)/helm template $(helm_chart_archive) --values hack/helm/sample-chart-values.yaml

# instead of running verify-generate-api-docs, this target uses the gomarkdoc --check flag to verify that the docs are up to date
.PHONY: verify-api-docs
verify-api-docs: $(BINDIR)/gomarkdoc
	@$(BINDIR)/gomarkdoc \
		--check $(GOMARKDOC_FLAGS) \
		--output docs/api/api.md github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1 \
		|| (echo "docs are not up to date; run 'make generate' and commit the result" && exit 1)

# Run the supplied make target argument in a temporary workspace and diff the results.
verify-%: FORCE
	./hack/util/verify.sh $(MAKE) -s $*

.PHONY: verify
verify: ## Verify code and generate targets.
verify: vet
verify: verify-generate-manifests
verify: verify-generate-deepcopy
verify: verify-generate-helm-docs
verify: verify-api-docs
	@echo "The following targets create temporary files in the current directory, that is why they have to be run last:"
	$(MAKE) \
		verify-helm-lint \
		verify-pod-security-standards

cert_manager_crds: $(BINDIR)/cert-manager/crds.yaml
$(BINDIR)/cert-manager/crds.yaml: | $(BINDIR)
	mkdir -p $(BINDIR)/cert-manager
	curl -sSLo $(BINDIR)/cert-manager/crds.yaml https://github.com/cert-manager/cert-manager/releases/download/$(shell curl --silent "https://api.github.com/repos/cert-manager/cert-manager/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')/cert-manager.crds.yaml

.PHONY: test
test: cert_manager_crds tools ## Test approver-policy
	KUBEBUILDER_ASSETS=$(BINDIR)/kubebuilder/bin \
	ROOTDIR=$(CURDIR) \
		$(BINDIR)/ginkgo -procs=1 -v $(TEST_ARGS) ./cmd/... ./pkg/...

.PHONY: demo
demo: cert_manager_crds tools ## create cluster and deploy approver-policy
	REPO_ROOT=$(shell pwd) ./hack/ci/create-cluster.sh

.PHONY: smoke
smoke: demo ## create cluster, deploy approver-policy, run smoke tests
	REPO_ROOT=$(shell pwd) ./hack/ci/run-smoke-test.sh
	REPO_ROOT=$(shell pwd) ./hack/ci/delete-cluster.sh

##@ Helm Chart

helm_chart_source_dir := deploy/charts/approver-policy
helm_chart_sources := $(shell find $(helm_chart_source_dir) -maxdepth 1 -type f) $(shell find $(helm_chart_source_dir)/templates -type f)

$(helm_chart_archive): $(helm_chart_sources) | $(BINDIR)/helm
	$(eval helm_chart_source_dir_versioned := $(BINDIR)/charts/approver-policy-$(VERSION))
	rm -rf $(helm_chart_source_dir_versioned)
	mkdir -p $(dir $(helm_chart_source_dir_versioned))
	cp -a $(helm_chart_source_dir) $(helm_chart_source_dir_versioned)
	mkdir -p $(dir $@)
	$(BINDIR)/helm package $(helm_chart_source_dir_versioned) \
		--app-version $(VERSION) \
		--version $(VERSION) \
		--destination $(dir $@)

# Allow target to create GitHub outputs when run via GitHub Actions
GITHUB_OUTPUT ?= /dev/null

.PHONY: helm-chart
helm-chart: ## Create a helm chart
helm-chart: $(helm_chart_archive)
	@echo path=$(helm_chart_archive) >> $(GITHUB_OUTPUT)

##@ Tools

$(BINDIR):
	mkdir -p $@

$(BINDIR)/deepcopy-gen: | $(BINDIR)
	cd hack/tools && go build -o $@ k8s.io/code-generator/cmd/deepcopy-gen

$(BINDIR)/controller-gen: | $(BINDIR)
	cd hack/tools && go build -o $@ sigs.k8s.io/controller-tools/cmd/controller-gen

$(BINDIR)/ginkgo: | $(BINDIR)
	cd hack/tools && go build -o $@ github.com/onsi/ginkgo/v2/ginkgo

$(BINDIR)/kind: | $(BINDIR)
	cd hack/tools && go build -o $@ sigs.k8s.io/kind

$(BINDIR)/kustomize: | $(BINDIR)
	cd hack/tools && go build -o $@ sigs.k8s.io/kustomize/kustomize/v5

$(BINDIR)/helm: | $(BINDIR)
	curl -o $(BINDIR)/helm.tar.gz -sSL "https://get.helm.sh/helm-v$(HELM_VERSION)-$(OS)-$(ARCH).tar.gz"
	tar -C $(BINDIR) -xzf $(BINDIR)/helm.tar.gz
	cp $(BINDIR)/$(OS)-$(ARCH)/helm $@
	rm -r $(BINDIR)/$(OS)-$(ARCH) $(BINDIR)/helm.tar.gz
	$(BINDIR)/helm repo add jetstack https://charts.jetstack.io --force-update

$(BINDIR)/kubectl: | $(BINDIR)
	curl -o $@ -LO "https://storage.googleapis.com/kubernetes-release/release/$(shell curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/$(OS)/$(ARCH)/kubectl"
	chmod +x $@

$(BINDIR)/kubebuilder/bin/kube-apiserver: | $(BINDIR)
	curl -sSLo $(BINDIR)/envtest-bins.tar.gz "https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-$(KUBEBUILDER_TOOLS_VERSION)-$(OS)-$(ARCH).tar.gz"
	mkdir -p $(BINDIR)/kubebuilder
	tar -C $(BINDIR)/kubebuilder --strip-components=1 -zvxf $(BINDIR)/envtest-bins.tar.gz

$(BINDIR)/gomarkdoc: | $(BINDIR)
	cd hack/tools && go build -o $@ github.com/princjef/gomarkdoc/cmd/gomarkdoc

$(BINDIR)/helm-docs: | $(BINDIR)
	cd hack/tools && go build -o $@ github.com/norwoodj/helm-docs/cmd/helm-docs

$(BINDIR)/kyverno: | $(BINDIR)
	curl https://github.com/kyverno/kyverno/releases/download/$(KYVERNO_VERSION)/kyverno-cli_$(KYVERNO_VERSION)_$(OS)_$(subst amd64,x86_64,${ARCH}).tar.gz -fsSL -o $@.tar.gz
	@# O writes the specified file to stdout
	tar xfO $@.tar.gz kyverno > $@
	chmod +x $@
	rm -f $@.tar.gz

.PHONY: tools
tools: ## Download and setup all tools
tools: $(BINDIR)/deepcopy-gen
tools: $(BINDIR)/controller-gen
tools: $(BINDIR)/ginkgo
tools: $(BINDIR)/kind
tools: $(BINDIR)/helm
tools: $(BINDIR)/kubectl
tools: $(BINDIR)/kubebuilder/bin/kube-apiserver
tools: $(BINDIR)/gomarkdoc
tools: $(BINDIR)/helm-docs
