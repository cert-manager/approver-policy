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


BINDIR ?= $(CURDIR)/bin
ARCH   ?= $(shell go env GOARCH)
OS     ?= $(shell go env GOOS)

HELM_VERSION ?= 3.6.3
KUBEBUILDER_TOOLS_VERISON ?= 1.22.0
K8S_CLUSTER_NAME ?= policy-approver

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: manifests
manifests: controller-gen ## Generate CustomResourceDefinition objects.
	$(CONTROLLER_GEN) $(CRD_OPTIONS) webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: clean
clean: ## clean up created files
	rm -rf \
		$(BINDIR) \
		_artifacts

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: lint
lint: ## Run linters against code.
	./hack/verify-boilerplate.sh

.PHONY: test
test: depend lint vet ## test policy-approver
	KUBEBUILDER_ASSETS=$(BINDIR)/kubebuilder/bin ROOTDIR=$(CURDIR) go test -v -count 1 $(TEST_ARGS) ./cmd/... ./pkg/...

.PHONY: generate
generate: depend ## generate code
	./hack/update-codegen.sh

.PHONY: build
build: ## Build manager binary.
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o bin/policy-approver ./cmd/

.PHONY: verify
verify: test build ## Verify repo.

.PHONY: image
image: ## build docker image
	GOARCH=$(ARCH) GOOS=linux CGO_ENABLED=0 go build -o ./bin/policy-approver-linux ./cmd/.
	docker build -t quay.io/jetstack/cert-manager-policy-approver:v0.1.0 .

# ==================================
# E2E testing
# ==================================
.PHONY: kind
kind: depend image kind-cluster deploy-cert-manager kind-load deploy

.PHONY: kind-cluster
kind-cluster: depend ## Use Kind to create a Kubernetes cluster for E2E tests
	$(BINDIR)/kind get clusters | grep $(K8S_CLUSTER_NAME) || $(BINDIR)/kind create cluster --name $(K8S_CLUSTER_NAME)

.PHONY: kind-load
kind-load: ## Load all the Docker images into Kind
	$(BINDIR)/kind load docker-image --name $(K8S_CLUSTER_NAME) quay.io/jetstack/cert-manager-policy-approver:v0.1.0

.PHONY: deploy-cert-manager
deploy-cert-manager: depend ## Deploy cert-manager in the configured Kubernetes cluster in ~/.kube/config
	$(BINDIR)/helm repo add jetstack https://charts.jetstack.io --force-update
	$(BINDIR)/helm upgrade --wait -i -n cert-manager cert-manager jetstack/cert-manager --set extraArgs={--controllers='*\,-certificaterequests-approver'} --set installCRDs=true --create-namespace

.PHONY: deploy
deploy: depend ## Install CRDs into the K8s cluster
	$(BINDIR)/kubectl apply -k config/crd
	$(BINDIR)/kubectl apply -k config/default

.PHONY: e2e
e2e:

.PHONY: depend
depend: $(BINDIR) $(BINDIR)/deepcopy-gen $(BINDIR)/controller-gen $(BINDIR)/ginkgo $(BINDIR)/kubectl $(BINDIR)/kind $(BINDIR)/helm $(BINDIR)/kubebuilder/bin/kube-apiserver $(BINDIR)/cert-manager/crds.yaml

$(BINDIR):
	mkdir -p ./bin

$(BINDIR)/deepcopy-gen:
	go build -o $@ k8s.io/code-generator/cmd/deepcopy-gen

$(BINDIR)/controller-gen:
	go build -o $@ sigs.k8s.io/controller-tools/cmd/controller-gen

$(BINDIR)/ginkgo:
	go build -o $(BINDIR)/ginkgo github.com/onsi/ginkgo/ginkgo

$(BINDIR)/kind:
	go build -o $(BINDIR)/kind sigs.k8s.io/kind

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
	curl -sSLo $(BINDIR)/envtest-bins.tar.gz "https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-$(KUBEBUILDER_TOOLS_VERISON)-$(OS)-$(ARCH).tar.gz"
	mkdir -p $(BINDIR)/kubebuilder
	tar -C $(BINDIR)/kubebuilder --strip-components=1 -zvxf $(BINDIR)/envtest-bins.tar.gz

$(BINDIR)/cert-manager/crds.yaml:
	mkdir -p $(BINDIR)/cert-manager
	curl -sSLo $(BINDIR)/cert-manager/crds.yaml https://github.com/jetstack/cert-manager/releases/download/$(shell curl --silent "https://api.github.com/repos/jetstack/cert-manager/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')/cert-manager.crds.yaml
