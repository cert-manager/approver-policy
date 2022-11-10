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

VERSION ?= $(shell git describe --tags --always --dirty --match='v*' --abbrev=14)

BINDIR ?= $(CURDIR)/bin
ARCH   ?= $(shell go env GOARCH)
OS     ?= $(shell go env GOOS)

HELM_VERSION ?= 3.10.0
KUBEBUILDER_TOOLS_VERSION ?= 1.25.0
K8S_CLUSTER_NAME ?= approver-policy
IMAGE_REGISTRY ?= quay.io/jetstack
IMAGE_NAME := cert-manager-approver-policy
IMAGE_TAG := $(VERSION)
IMAGE := $(IMAGE_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

GOMARKDOC_FLAGS=--format github --repository.url "https://github.com/cert-manager/approver-policy" --repository.default-branch master --repository.path /

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: clean
clean: ## clean up created files
	rm -rf \
		$(BINDIR) \
		_artifacts

.PHONY: generate
generate: depend docs/api/api.md ## generate code and documentation
	./hack/update-codegen.sh

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: lint
lint: helm-docs $(BINDIR)/gomarkdoc ## Run linters against code.
	./hack/verify-boilerplate.sh
	@$(BINDIR)/gomarkdoc --check $(GOMARKDOC_FLAGS) --output docs/api/api.md github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1 || (echo "docs are not up to date; run 'make generate' and commit the result" && exit 1)

.PHONY: helm-docs
helm-docs: $(BINDIR)/helm-docs # verify helm-docs
	./hack/verify-helm-docs.sh

.PHONY: test
test: depend lint vet ## test approver-policy
	KUBEBUILDER_ASSETS=$(BINDIR)/kubebuilder/bin ROOTDIR=$(CURDIR) go test -v $(TEST_ARGS) ./cmd/... ./pkg/...

.PHONY: build
build: $(BINDIR) ## Build manager binary.
	CGO_ENABLED=0 go build -o bin/approver-policy ./cmd/

.PHONY: verify
verify: test build ## Verify repo.

.PHONY: image
image: ## build docker image
	docker build --tag ${IMAGE} --build-arg VERSION=$(VERSION) .

.PHONY: demo
demo: depend ## create cluster and deploy approver-policy
	REPO_ROOT=$(shell pwd) ./hack/ci/create-cluster.sh

.PHONY: smoke
smoke: demo ## create cluster, deploy approver-policy, run smoke tests
	REPO_ROOT=$(shell pwd) ./hack/ci/run-smoke-test.sh
	REPO_ROOT=$(shell pwd) ./hack/ci/delete-cluster.sh

.PHONY: docs/api/api.md
docs/api/api.md: $(BINDIR)/gomarkdoc
	mkdir -p docs/api
	$(BINDIR)/gomarkdoc $(GOMARKDOC_FLAGS) --output $@ github.com/cert-manager/approver-policy/pkg/apis/policy/v1alpha1

.PHONY: depend
depend: $(BINDIR) $(BINDIR)/deepcopy-gen $(BINDIR)/controller-gen $(BINDIR)/ginkgo $(BINDIR)/kubectl $(BINDIR)/kind $(BINDIR)/helm $(BINDIR)/kubebuilder/bin/kube-apiserver $(BINDIR)/cert-manager/crds.yaml $(BINDIR)/gomarkdoc

$(BINDIR):
	mkdir -p ./bin

$(BINDIR)/deepcopy-gen:
	cd hack/tools && go build -o $@ k8s.io/code-generator/cmd/deepcopy-gen

$(BINDIR)/controller-gen:
	cd hack/tools && go build -o $@ sigs.k8s.io/controller-tools/cmd/controller-gen

$(BINDIR)/ginkgo:
	cd hack/tools && go build -o $(BINDIR)/ginkgo github.com/onsi/ginkgo/v2/ginkgo

$(BINDIR)/kind:
	cd hack/tools && go build -o $(BINDIR)/kind sigs.k8s.io/kind

$(BINDIR)/helm:
	curl -o $(BINDIR)/helm.tar.gz -LO "https://get.helm.sh/helm-v$(HELM_VERSION)-$(OS)-$(ARCH).tar.gz"
	tar -C $(BINDIR) -xzf $(BINDIR)/helm.tar.gz
	cp $(BINDIR)/$(OS)-$(ARCH)/helm $(BINDIR)/helm
	rm -r $(BINDIR)/$(OS)-$(ARCH) $(BINDIR)/helm.tar.gz
	$(BINDIR)/helm repo add jetstack https://charts.jetstack.io --force-update

$(BINDIR)/kubectl:
	curl -o ./bin/kubectl -LO "https://storage.googleapis.com/kubernetes-release/release/$(shell curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/$(OS)/$(ARCH)/kubectl"
	chmod +x ./bin/kubectl

$(BINDIR)/kubebuilder/bin/kube-apiserver:
	curl -sSLo $(BINDIR)/envtest-bins.tar.gz "https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-$(KUBEBUILDER_TOOLS_VERSION)-$(OS)-$(ARCH).tar.gz"
	mkdir -p $(BINDIR)/kubebuilder
	tar -C $(BINDIR)/kubebuilder --strip-components=1 -zvxf $(BINDIR)/envtest-bins.tar.gz

$(BINDIR)/cert-manager/crds.yaml:
	mkdir -p $(BINDIR)/cert-manager
	curl -sSLo $(BINDIR)/cert-manager/crds.yaml https://github.com/cert-manager/cert-manager/releases/download/$(shell curl --silent "https://api.github.com/repos/cert-manager/cert-manager/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')/cert-manager.crds.yaml

$(BINDIR)/gomarkdoc:
	cd hack/tools && GO111MODULE=on go build -o $@ github.com/princjef/gomarkdoc/cmd/gomarkdoc

$(BINDIR)/helm-docs: $(BINDIR)
		cd hack/tools && go build -o $(BINDIR)/helm-docs github.com/norwoodj/helm-docs/cmd/helm-docs
