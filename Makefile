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

MAKEFLAGS += --warn-undefined-variables
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
.SUFFIXES:
.ONESHELL:

VERSION ?= $(shell git describe --tags)

# BIN is the directory where tools will be installed
export BIN ?= ${CURDIR}/bin

OS := $(shell go env GOOS)
ARCH := $(shell go env GOARCH)

# Image URL to use all building/pushing image targets
IMG ?= quay.io/jestack/policy-approver:v0.1.0-alpha.0
# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
CRD_OPTIONS ?= "crd:trivialVersions=true,preserveUnknownFields=false"

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Kind
KIND_VERSION := 0.10.0
HELM_VERSION := 3.5.4
KIND := ${BIN}/kind-${KIND_VERSION}
HELM := ${BIN}/helm-${HELM_VERSION}
GINKGO := ${BIN}/ginkgo
K8S_CLUSTER_NAME := policy-approver-e2e
K8S_VERSION ?= 1.20.0

# cert-manager
CERT_MANAGER_VERSION ?= 1.3.0

all: build

##@ General

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

manifests: controller-gen ## Generate CustomResourceDefinition objects.
	$(CONTROLLER_GEN) $(CRD_OPTIONS) webhook paths="./..." output:crd:artifacts:config=config/crd/bases

generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

clean:
	rm -rf ${BIN}

fmt: ## Run go fmt against code.
	go fmt ./...

vet: ## Run go vet against code.
	go vet ./...

lint: ## Run linters against code.
	./hack/verify-boilerplate.sh

test: manifests generate lint fmt vet ## Run tests.
	go test ./cmd/... ./pkg/...

##@ Build

build: test ## Build manager binary.
	go build -o bin/policy-approver ./cmd

verify: all ## Verify repo.

docker-build: build
	docker build \
		--build-arg VERSION=$(VERSION) \
		--tag ${IMG} \
		--file Dockerfile \
		${CURDIR}

docker-push: ## Push docker image with the manager.
	docker push ${IMG}

##@ Deployment

install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl delete -f -

deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	pushd config/manager
	$(KUSTOMIZE) edit set image policy-approver=${IMG}
	popd
	$(KUSTOMIZE) build config/default | kubectl apply -f -

undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/default | kubectl delete -f -

# ==================================
# E2E testing
# ==================================
.PHONY: kind
kind: kind-cluster deploy-cert-manager kind-load install deploy

.PHONY: kind-cluster
kind-cluster: ## Use Kind to create a Kubernetes cluster for E2E tests
kind-cluster: ${KIND}
	${KIND} get clusters | grep ${K8S_CLUSTER_NAME} || ${KIND} create cluster --name ${K8S_CLUSTER_NAME} --image kindest/node:v${K8S_VERSION}

.PHONY: kind-load
kind-load: docker-build ## Load all the Docker images into Kind
	${KIND} load docker-image --name ${K8S_CLUSTER_NAME} ${IMG}

.PHONY: deploy-cert-manager
deploy-cert-manager: ${HELM} ## Deploy cert-manager in the configured Kubernetes cluster in ~/.kube/config
	${HELM} upgrade --wait -i -n cert-manager cert-manager cert-manager --set extraArgs={--controllers='*\,-certificaterequests-approver'} --set installCRDs=true --create-namespace --repo https://charts.jetstack.io

CONTROLLER_GEN = $(shell pwd)/bin/controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	$(call go-get-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@v0.4.1)

KUSTOMIZE = $(shell pwd)/bin/kustomize
kustomize: ## Download kustomize locally if necessary.
	$(call go-get-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v3@v3.8.7)

.PHONY: e2e
e2e: all kind ${GINKGO}
	kubectl rollout status -w -n cert-manager deployment/policy-approver
	${KIND} get kubeconfig --name ${K8S_CLUSTER_NAME} > kubeconfig.yaml
	${GINKGO} -nodes 1 ./test/. -- -kubeconfig=$(shell pwd)/kubeconfig.yaml
	${KIND} delete cluster --name ${K8S_CLUSTER_NAME}
	rm kubeconfig.yaml

${BIN}:
	mkdir -p ${BIN}

${KIND}: ${BIN}
	curl -sSL -o ${KIND} https://github.com/kubernetes-sigs/kind/releases/download/v${KIND_VERSION}/kind-${OS}-${ARCH}
	chmod +x ${KIND}

${HELM}: ${BIN}
	curl -sSL -o ${HELM}.tar.gz https://get.helm.sh/helm-v${HELM_VERSION}-${OS}-${ARCH}.tar.gz
	tar xvf ${HELM}.tar.gz -C ${BIN}
	mv ${BIN}/${OS}-${ARCH}/helm ${HELM}
	rm -rf ${BIN}/${OS}-${ARCH} ${HELM}.tar.gz
	chmod +x ${HELM}


${GINKGO}: ${BIN}
	go build -o ${BIN}/ginkgo github.com/onsi/ginkgo/ginkgo

# go-get-tool will 'go get' any package $2 and install it to $1.
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-get-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
GOBIN=$(PROJECT_DIR)/bin go get $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef
