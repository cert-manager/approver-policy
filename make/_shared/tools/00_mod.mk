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

##########################################

$(bin_dir)/scratch/image $(bin_dir)/tools $(bin_dir)/downloaded $(bin_dir)/downloaded/tools:
	@mkdir -p $@

checkhash_script := $(dir $(lastword $(MAKEFILE_LIST)))/util/checkhash.sh

# To make sure we use the right version of each tool, we put symlink in
# $(bin_dir)/tools, and the actual binaries are in $(bin_dir)/downloaded. When bumping
# the version of the tools, this symlink gets updated.

# Let's have $(bin_dir)/tools in front of the PATH so that we don't inavertedly
# pick up the wrong binary somewhere. Watch out, $(shell echo $$PATH) will
# still print the original PATH, since GNU make does not honor exported
# variables: https://stackoverflow.com/questions/54726457
export PATH := $(CURDIR)/$(bin_dir)/tools:$(PATH)

CTR=docker

TOOLS :=
# https://github.com/helm/helm/releases
TOOLS += helm=v3.12.1
# https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl
TOOLS += kubectl=v1.27.3
# https://github.com/kubernetes-sigs/kind/releases
TOOLS += kind=v0.20.0
# https://www.vaultproject.io/downloads
TOOLS += vault=1.14.0
# https://github.com/Azure/azure-workload-identity/releases
TOOLS += azwi=v1.1.0
# https://github.com/kyverno/kyverno/releases
TOOLS += kyverno=v1.10.1
# https://github.com/mikefarah/yq/releases
TOOLS += yq=v4.34.1
# https://github.com/ko-build/ko/releases
TOOLS += ko=0.14.1
# https://github.com/protocolbuffers/protobuf/releases
TOOLS += protoc=25.0

### go packages
# https://pkg.go.dev/sigs.k8s.io/controller-tools/cmd/controller-gen?tab=versions
TOOLS += controller-gen=v0.13.0
# https://pkg.go.dev/golang.org/x/tools/cmd/goimports?tab=versions
TOOLS += goimports=v0.14.0
# https://pkg.go.dev/github.com/google/go-licenses/licenses?tab=versions
TOOLS += go-licenses=v1.6.0
# https://pkg.go.dev/gotest.tools/gotestsum?tab=versions
TOOLS += gotestsum=v1.11.0
# https://pkg.go.dev/sigs.k8s.io/kustomize/kustomize/v4?tab=versions
TOOLS += kustomize=v4.5.7
# https://pkg.go.dev/github.com/itchyny/gojq?tab=versions
TOOLS += gojq=v0.12.13
# https://pkg.go.dev/github.com/google/go-containerregistry/pkg/crane?tab=versions
TOOLS += crane=v0.16.1
# https://pkg.go.dev/google.golang.org/protobuf/cmd/protoc-gen-go?tab=versions
TOOLS += protoc-gen-go=v1.31.0
# https://pkg.go.dev/github.com/norwoodj/helm-docs/cmd/helm-docs?tab=versions
TOOLS += helm-docs=v1.11.2
# https://pkg.go.dev/github.com/sigstore/cosign/v2/cmd/cosign?tab=versions
TOOLS += cosign=v2.2.0
# https://pkg.go.dev/github.com/cert-manager/boilersuite?tab=versions
TOOLS += boilersuite=v0.1.0
# https://pkg.go.dev/github.com/princjef/gomarkdoc/cmd/gomarkdoc?tab=versions
TOOLS += gomarkdoc=v1.1.0
# https://pkg.go.dev/oras.land/oras/cmd/oras?tab=versions
TOOLS += oras=v1.1.0
# https://pkg.go.dev/github.com/onsi/ginkgo/v2/ginkgo?tab=versions
TOOLS += ginkgo=$(shell awk '/ginkgo\/v2/ {print $$2}' go.mod)
# https://pkg.go.dev/github.com/cert-manager/klone?tab=versions
TOOLS += klone=v0.0.2

# https://pkg.go.dev/k8s.io/code-generator/cmd?tab=versions
K8S_CODEGEN_VERSION=v0.28.2

# https://github.com/kubernetes-sigs/kubebuilder/blob/tools-releases/build/cloudbuild_tools.yaml
KUBEBUILDER_ASSETS_VERSION=1.28.0
TOOLS += etcd=$(KUBEBUILDER_ASSETS_VERSION)
TOOLS += kube-apiserver=$(KUBEBUILDER_ASSETS_VERSION)

# https://go.dev/dl/
VENDORED_GO_VERSION := 1.21.5

# Print the go version which can be used in GH actions
.PHONY: print-go-version
print-go-version:
	@echo result=$(VENDORED_GO_VERSION)

# When switching branches which use different versions of the tools, we
# need a way to re-trigger the symlinking from $(bin_dir)/downloaded to $(bin_dir)/tools.
$(bin_dir)/scratch/%_VERSION: FORCE | $(bin_dir)/scratch
	@test "$($*_VERSION)" == "$(shell cat $@ 2>/dev/null)" || echo $($*_VERSION) > $@

# --silent = don't print output like progress meters
# --show-error = but do print errors when they happen
# --fail = exit with a nonzero error code without the response from the server when there's an HTTP error
# --location = follow redirects from the server
# --retry = the number of times to retry a failed attempt to connect
# --retry-connrefused = retry even if the initial connection was refused
CURL = curl --silent --show-error --fail --location --retry 10 --retry-connrefused

# In Prow, the pod has the folder "$(bin_dir)/downloaded" mounted into the
# container. For some reason, even though the permissions are correct,
# binaries that are mounted with hostPath can't be executed. When in CI, we
# copy the binaries to work around that. Using $(LN) is only required when
# dealing with binaries. Other files and folders can be symlinked.
#
# Details on how "$(bin_dir)/downloaded" gets cached are available in the
# description of the PR https://github.com/jetstack/testing/pull/651.
#
# We use "printenv CI" instead of just "ifeq ($(CI),)" because otherwise we
# would get "warning: undefined variable 'CI'".
ifeq ($(shell printenv CI),)
LN := ln -f -s
else
LN := cp -f -r
endif

UC = $(shell echo '$1' | tr a-z A-Z)
LC = $(shell echo '$1' | tr A-Z a-z)

TOOL_NAMES :=

# for each item `xxx` in the TOOLS variable:
# - a $(XXX_VERSION) variable is generated
#     -> this variable contains the version of the tool
# - a $(NEEDS_XXX) variable is generated
#     -> this variable contains the target name for the tool,
#        which is the relative path of the binary, this target
#        should be used when adding the tool as a dependency to
#        your target, you can't use $(XXX) as a dependency because
#        make does not support an absolute path as a dependency
# - a $(XXX) variable is generated
#     -> this variable contains the absolute path of the binary,
#        the absolute path should be used when executing the binary
#        in targets or in scripts, because it is agnostic to the
#        working directory
# - an unversioned target $(bin_dir)/tools/xxx is generated that
#   creates a copy/ link to the corresponding versioned target:
#   $(bin_dir)/tools/xxx@$(XXX_VERSION)_$(HOST_OS)_$(HOST_ARCH)
define tool_defs
TOOL_NAMES += $1

$(call UC,$1)_VERSION ?= $2
NEEDS_$(call UC,$1) := $$(bin_dir)/tools/$1
$(call UC,$1) := $$(CURDIR)/$$(bin_dir)/tools/$1

$$(bin_dir)/tools/$1: $$(bin_dir)/scratch/$(call UC,$1)_VERSION | $$(bin_dir)/downloaded/tools/$1@$$($(call UC,$1)_VERSION)_$$(HOST_OS)_$$(HOST_ARCH) $$(bin_dir)/tools
	cd $$(dir $$@) && $$(LN) $$(patsubst $$(bin_dir)/%,../%,$$(word 1,$$|)) $$(notdir $$@)
	@touch $$@ # making sure the target of the symlink is newer than *_VERSION
endef

$(foreach TOOL,$(TOOLS),$(eval $(call tool_defs,$(word 1,$(subst =, ,$(TOOL))),$(word 2,$(subst =, ,$(TOOL))))))

TOOLS_PATHS := $(TOOL_NAMES:%=$(bin_dir)/tools/%)

######
# Go #
######

# $(NEEDS_GO) is a target that is set as an order-only prerequisite in
# any target that calls $(GO), e.g.:
#
#     $(bin_dir)/tools/crane: $(NEEDS_GO)
#         $(GO) build -o $(bin_dir)/tools/crane
#
# $(NEEDS_GO) is empty most of the time, except when running "make vendor-go"
# or when "make vendor-go" was previously run, in which case $(NEEDS_GO) is set
# to $(bin_dir)/tools/go, since $(bin_dir)/tools/go is a prerequisite of
# any target depending on Go when "make vendor-go" was run.
NEEDS_GO := $(if $(findstring vendor-go,$(MAKECMDGOALS))$(shell [ -f $(bin_dir)/tools/go ] && echo yes), $(bin_dir)/tools/go,)
ifeq ($(NEEDS_GO),)
GO := go
else
export GOROOT := $(CURDIR)/$(bin_dir)/tools/goroot
export PATH := $(CURDIR)/$(bin_dir)/tools/goroot/bin:$(PATH)
GO := $(CURDIR)/$(bin_dir)/tools/go
endif

.PHONY: vendor-go
## By default, this Makefile uses the system's Go. You can use a "vendored"
## version of Go that will get downloaded by running this command once. To
## disable vendoring, run "make unvendor-go". When vendoring is enabled,
## you will want to set the following:
##
##     export PATH="$PWD/$(bin_dir)/tools:$PATH"
##     export GOROOT="$PWD/$(bin_dir)/tools/goroot"
## @category [shared] Tools
vendor-go: $(bin_dir)/tools/go

.PHONY: unvendor-go
unvendor-go: $(bin_dir)/tools/go
	rm -rf $(bin_dir)/tools/go $(bin_dir)/tools/goroot

.PHONY: which-go
## Print the version and path of go which will be used for building and
## testing in Makefile commands. Vendored go will have a path in ./bin
## @category [shared] Tools
which-go: | $(NEEDS_GO)
	@$(GO) version
	@echo "go binary used for above version information: $(GO)"

# The "_" in "_go "prevents "go mod tidy" from trying to tidy the vendored
# goroot.
$(bin_dir)/tools/go: $(bin_dir)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$(HOST_OS)-$(HOST_ARCH)/goroot/bin/go $(bin_dir)/tools/goroot $(bin_dir)/scratch/VENDORED_GO_VERSION | $(bin_dir)/tools
	cd $(dir $@) && $(LN) $(patsubst $(bin_dir)/%,../%,$<) .
	@touch $@ # making sure the target of the symlink is newer than *_VERSION

$(bin_dir)/tools/goroot: $(bin_dir)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$(HOST_OS)-$(HOST_ARCH)/goroot $(bin_dir)/scratch/VENDORED_GO_VERSION | $(bin_dir)/tools
	@rm -rf $(bin_dir)/tools/goroot
	cd $(dir $@) && $(LN) $(patsubst $(bin_dir)/%,../%,$<) .
	@touch $@ # making sure the target of the symlink is newer than *_VERSION

$(bin_dir)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-%/goroot $(bin_dir)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-%/goroot/bin/go: $(bin_dir)/downloaded/tools/go-$(VENDORED_GO_VERSION)-%.tar.gz
	@mkdir -p $(dir $@)
	rm -rf $(bin_dir)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$*/goroot
	tar xzf $< -C $(bin_dir)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$*
	mv $(bin_dir)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$*/go $(bin_dir)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$*/goroot

$(bin_dir)/downloaded/tools/go-$(VENDORED_GO_VERSION)-%.tar.gz: | $(bin_dir)/downloaded/tools
	$(CURL) https://go.dev/dl/go$(VENDORED_GO_VERSION).$*.tar.gz -o $@

###################
# go dependencies #
###################

GO_DEPENDENCIES :=
GO_DEPENDENCIES += ginkgo=github.com/onsi/ginkgo/v2/ginkgo
GO_DEPENDENCIES += controller-gen=sigs.k8s.io/controller-tools/cmd/controller-gen
GO_DEPENDENCIES += goimports=golang.org/x/tools/cmd/goimports
GO_DEPENDENCIES += go-licenses=github.com/google/go-licenses
GO_DEPENDENCIES += gotestsum=gotest.tools/gotestsum
GO_DEPENDENCIES += kustomize=sigs.k8s.io/kustomize/kustomize/v4
GO_DEPENDENCIES += gojq=github.com/itchyny/gojq/cmd/gojq
GO_DEPENDENCIES += crane=github.com/google/go-containerregistry/cmd/crane
GO_DEPENDENCIES += protoc-gen-go=google.golang.org/protobuf/cmd/protoc-gen-go
GO_DEPENDENCIES += helm-docs=github.com/norwoodj/helm-docs/cmd/helm-docs
GO_DEPENDENCIES += cosign=github.com/sigstore/cosign/v2/cmd/cosign
GO_DEPENDENCIES += boilersuite=github.com/cert-manager/boilersuite
GO_DEPENDENCIES += gomarkdoc=github.com/princjef/gomarkdoc/cmd/gomarkdoc
GO_DEPENDENCIES += oras=oras.land/oras/cmd/oras
GO_DEPENDENCIES += klone=github.com/cert-manager/klone

define go_dependency
$$(bin_dir)/downloaded/tools/$1@$($(call UC,$1)_VERSION)_%: | $$(NEEDS_GO) $$(bin_dir)/downloaded/tools
	GOBIN=$$(CURDIR)/$$(dir $$@) $$(GO) install $2@$($(call UC,$1)_VERSION)
	@mv $$(CURDIR)/$$(dir $$@)/$1 $$@
endef

$(foreach GO_DEPENDENCY,$(GO_DEPENDENCIES),$(eval $(call go_dependency,$(word 1,$(subst =, ,$(GO_DEPENDENCY))),$(word 2,$(subst =, ,$(GO_DEPENDENCY))))))

########
# Helm #
########

HELM_linux_amd64_SHA256SUM=1a7074f58ef7190f74ce6db5db0b70e355a655e2013c4d5db2317e63fa9e3dea
HELM_darwin_amd64_SHA256SUM=f487b5d8132bd2091378258a3029e33ee10f71575b2167cdfeaf6d0144d20938
HELM_darwin_arm64_SHA256SUM=e82e0433589b1b5170807d6fec75baedba40620458510bbd30cdb9d2246415fe

$(bin_dir)/downloaded/tools/helm@$(HELM_VERSION)_%: | $(bin_dir)/downloaded/tools
	$(CURL) https://get.helm.sh/helm-$(HELM_VERSION)-$(subst _,-,$*).tar.gz -o $@.tar.gz
	$(checkhash_script) $@.tar.gz $(HELM_$*_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $@.tar.gz $(subst _,-,$*)/helm > $@
	chmod +x $@
	rm -f $@.tar.gz

###########
# kubectl #
###########

KUBECTL_linux_amd64_SHA256SUM=fba6c062e754a120bc8105cde1344de200452fe014a8759e06e4eec7ed258a09
KUBECTL_darwin_amd64_SHA256SUM=10662b3859fe302903e5d4f665d74c243bdb3a709b120c5c49434659a81942c5
KUBECTL_darwin_arm64_SHA256SUM=795af693fc168351132e127d75b03ace039e4bb40d67001790db77f7b7a37a7e

$(bin_dir)/downloaded/tools/kubectl@$(KUBECTL_VERSION)_%: | $(bin_dir)/downloaded/tools
	$(CURL) https://dl.k8s.io/release/$(KUBECTL_VERSION)/bin/$(subst _,/,$*)/kubectl -o $@
	$(checkhash_script) $@ $(KUBECTL_$*_SHA256SUM)
	chmod +x $@

########
# kind #
########

KIND_linux_amd64_SHA256SUM=513a7213d6d3332dd9ef27c24dab35e5ef10a04fa27274fe1c14d8a246493ded
KIND_darwin_amd64_SHA256SUM=bffd8fb2006dc89fa0d1dde5ba6bf48caacb707e4df8551528f49145ebfeb7ad
KIND_darwin_arm64_SHA256SUM=8df041a5cae55471f3b039c3c9942226eb909821af63b5677fc80904caffaabf

$(bin_dir)/downloaded/tools/kind@$(KIND_VERSION)_%: | $(bin_dir)/downloaded/tools $(bin_dir)/tools
	$(CURL) -sSfL https://github.com/kubernetes-sigs/kind/releases/download/$(KIND_VERSION)/kind-$(subst _,-,$*) -o $@
	$(checkhash_script) $@ $(KIND_$*_SHA256SUM)
	chmod +x $@

#########
# vault #
#########

VAULT_linux_amd64_SHA256SUM=3d5c27e35d8ed43d861e892fc7d8f888f2fda4319a36f344f8c09603fb184b50
VAULT_darwin_amd64_SHA256SUM=5f1f9c548bffee8d843a08551aa018eb97ea15fd3215ecc8f97d6be3f15e29ba
VAULT_darwin_arm64_SHA256SUM=6d39460059b4a3ba723099c07f019af73687f3c05f4c390f155ad32127702fd4

$(bin_dir)/downloaded/tools/vault@$(VAULT_VERSION)_%: | $(bin_dir)/downloaded/tools
	$(CURL) https://releases.hashicorp.com/vault/$(VAULT_VERSION)/vault_$(VAULT_VERSION)_$*.zip -o $@.zip
	$(checkhash_script) $@.zip $(VAULT_$*_SHA256SUM)
	unzip -qq -c $@.zip > $@
	chmod +x $@
	rm -f $@.zip

########
# azwi #
########

AZWI_linux_amd64_SHA256SUM=db91a0daf693909d82d5f7958bebdc8e8eb9c674f9b55acf73d8156eb2777c03
AZWI_darwin_amd64_SHA256SUM=2fa7588a23231f7a47a34d94cc29406c8dedbfd9e3049cca40c2b3f698c5e7fd
AZWI_darwin_arm64_SHA256SUM=4a813f6b108ea1d735073788d89e186eff6291d3e00858f3b4d34db7d54fb14e

$(bin_dir)/downloaded/tools/azwi@$(AZWI_VERSION)_%: | $(bin_dir)/downloaded/tools
	$(CURL) https://github.com/Azure/azure-workload-identity/releases/download/$(AZWI_VERSION)/azwi-$(AZWI_VERSION)-$(subst _,-,$*).tar.gz -o $@.tar.gz
	$(checkhash_script) $@.tar.gz $(AZWI_$*_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $@.tar.gz azwi > $@ && chmod 775 $@
	rm -f $@.tar.gz

#####################
# k8s codegen tools #
#####################

K8S_CODEGEN_TOOLS := applyconfiguration-gen openapi-gen
K8S_CODEGEN_TOOLS_PATHS := $(K8S_CODEGEN_TOOLS:%=$(bin_dir)/tools/%)
K8S_CODEGEN_TOOLS_DOWNLOADS := $(K8S_CODEGEN_TOOLS:%=$(bin_dir)/downloaded/tools/%@$(K8S_CODEGEN_VERSION))

k8s-codegen-tools: $(K8S_CODEGEN_TOOLS_PATHS)

$(K8S_CODEGEN_TOOLS_PATHS): $(bin_dir)/tools/%-gen: $(bin_dir)/scratch/K8S_CODEGEN_VERSION | $(bin_dir)/downloaded/tools/%-gen@$(K8S_CODEGEN_VERSION) $(bin_dir)/tools
	cd $(dir $@) && $(LN) $(patsubst $(bin_dir)/%,../%,$(word 1,$|)) $(notdir $@)
	@touch $@ # making sure the target of the symlink is newer than *_VERSION

$(K8S_CODEGEN_TOOLS_DOWNLOADS): $(bin_dir)/downloaded/tools/%-gen@$(K8S_CODEGEN_VERSION): $(NEEDS_GO) | $(bin_dir)/downloaded/tools
	GOBIN=$(CURDIR)/$(dir $@) $(GO) install k8s.io/code-generator/cmd/$(notdir $@)
	@mv $(subst @$(K8S_CODEGEN_VERSION),,$@) $@

############################
# kubebuilder-tools assets #
# kube-apiserver / etcd    #
############################

KUBEBUILDER_TOOLS_linux_amd64_SHA256SUM=8c816871604cbe119ca9dd8072b576552ae369b96eebc3cdaaf50edd7e3c0c7b
KUBEBUILDER_TOOLS_darwin_amd64_SHA256SUM=a02e33a3981712c8d2702520f95357bd6c7d03d24b83a4f8ac1c89a9ba4d78c1
KUBEBUILDER_TOOLS_darwin_arm64_SHA256SUM=c87c6b3c0aec4233e68a12dc9690bcbe2f8d6cd72c23e670602b17b2d7118325

$(bin_dir)/downloaded/tools/etcd@$(KUBEBUILDER_ASSETS_VERSION)_%: $(bin_dir)/downloaded/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_%.tar.gz | $(bin_dir)/downloaded/tools
	$(checkhash_script) $< $(KUBEBUILDER_TOOLS_$*_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $< kubebuilder/bin/etcd > $@ && chmod 775 $@

$(bin_dir)/downloaded/tools/kube-apiserver@$(KUBEBUILDER_ASSETS_VERSION)_%: $(bin_dir)/downloaded/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_%.tar.gz | $(bin_dir)/downloaded/tools
	$(checkhash_script) $< $(KUBEBUILDER_TOOLS_$*_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $< kubebuilder/bin/kube-apiserver > $@ && chmod 775 $@

$(bin_dir)/downloaded/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz: | $(bin_dir)/downloaded/tools
	$(CURL) https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $@

###########
# kyverno #
###########

KYVERNO_linux_amd64_SHA256SUM=83bc607515cf9a7324f9fe28ef498393848349ab3c75f89adbd015288ac37e02
KYVERNO_darwin_amd64_SHA256SUM=b18c78846c2b5bf75d5fb25ad0fa01381d822fae4a1269ed31a8f04395b49d1a
KYVERNO_darwin_arm64_SHA256SUM=8a190e21aa8f56c47d12aa69abf2496f62a9ad733e186676696993175c79d851

$(bin_dir)/downloaded/tools/kyverno@$(KYVERNO_VERSION)_%: | $(bin_dir)/downloaded/tools
	$(CURL) https://github.com/kyverno/kyverno/releases/download/$(KYVERNO_VERSION)/kyverno-cli_$(KYVERNO_VERSION)_$(subst amd64,x86_64,$*).tar.gz	-fsSL -o $@.tar.gz
	$(checkhash_script) $@.tar.gz $(KYVERNO_$*_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $@.tar.gz kyverno > $@
	chmod +x $@
	rm -f $@.tar.gz

######
# yq #
######

YQ_linux_amd64_SHA256SUM=c5a92a572b3bd0024c7b1fe8072be3251156874c05f017c23f9db7b3254ae71a
YQ_darwin_amd64_SHA256SUM=25ccdecfd02aa37e07c985ac9612f17e5fd2c9eb40b051d43936bf3b99c9c2f5
YQ_darwin_arm64_SHA256SUM=30e8c7c52647f26312d8709193a269ec0ba4f384712775f87241b2abdc46de85

$(bin_dir)/downloaded/tools/yq@$(YQ_VERSION)_%: | $(bin_dir)/downloaded/tools
	$(CURL) https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_$* -o $@
	$(checkhash_script) $@ $(YQ_$*_SHA256SUM)
	chmod +x $@

######
# ko #
######

KO_linux_amd64_SHA256SUM=3f8f8e3fb4b78a4dfc0708df2b58f202c595a66c34195786f9a279ea991f4eae
KO_darwin_amd64_SHA256SUM=b879ea58255c9f2be2d4d6c4f6bd18209c78e9e0b890dbce621954ee0d63c4e5
KO_darwin_arm64_SHA256SUM=8d41c228da3e04e3de293f0f5bfe1775a4c74582ba21c86ad32244967095189f

$(bin_dir)/downloaded/tools/ko@$(KO_VERSION)_%: | $(bin_dir)/downloaded/tools
	$(CURL) https://github.com/ko-build/ko/releases/download/v$(KO_VERSION)/ko_$(KO_VERSION)_$(subst linux,Linux,$(subst darwin,Darwin,$(subst amd64,x86_64,$*))).tar.gz -o $@.tar.gz
	$(checkhash_script) $@.tar.gz $(KO_$*_SHA256SUM)
	tar xfO $@.tar.gz ko > $@
	chmod +x $@
	rm -f $@.tar.gz

##########
# protoc #
##########

PROTOC_linux_amd64_SHA256SUM=d26c4efe0eae3066bb560625b33b8fc427f55bd35b16f246b7932dc851554e67
PROTOC_darwin_amd64_SHA256SUM=15eefb30ba913e8dc4dd21d2ccb34ce04a2b33124f7d9460e5fd815a5d6459e3
PROTOC_darwin_arm64_SHA256SUM=76a997df5dacc0608e880a8e9069acaec961828a47bde16c06116ed2e570588b

$(bin_dir)/downloaded/tools/protoc@$(PROTOC_VERSION)_%: | $(bin_dir)/downloaded/tools
	$(CURL) https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOC_VERSION)/protoc-$(PROTOC_VERSION)-$(subst darwin,osx,$(subst arm64,aarch_64,$(subst amd64,x86_64,$(subst _,-,$*)))).zip -o $@.zip
	$(checkhash_script) $@.zip $(PROTOC_$*_SHA256SUM)
	unzip -qq -c $@.zip bin/protoc > $@
	chmod +x $@
	rm -f $@.zip

#################
# Other Targets #
#################

# Although we "vendor" most tools in $(bin_dir)/tools, we still require some binaries
# to be available on the system. The vendor-go MAKECMDGOALS trick prevents the
# check for the presence of Go when 'make vendor-go' is run.

# Gotcha warning: MAKECMDGOALS only contains what the _top level_ make invocation used, and doesn't look at target dependencies
# i.e. if we have a target "abc: vendor-go test" and run "make abc", we'll get an error
# about go being missing even though abc itself depends on vendor-go!
# That means we need to pass vendor-go at the top level if go is not installed (i.e. "make vendor-go abc")

MISSING=$(shell (command -v curl >/dev/null || echo curl) \
             && (command -v sha256sum >/dev/null || echo sha256sum) \
             && (command -v git >/dev/null || echo git) \
             && ([ -n "$(findstring vendor-go,$(MAKECMDGOALS),)" ] \
                || command -v $(GO) >/dev/null || echo "$(GO) (or run 'make vendor-go')") \
             && (command -v $(CTR) >/dev/null || echo "$(CTR) (or set CTR to a docker-compatible tool)"))
ifneq ($(MISSING),)
$(error Missing required tools: $(MISSING))
endif

.PHONY: tools
## Download and setup all tools
## @category [shared] Tools
tools: $(TOOLS_PATHS) $(K8S_CODEGEN_TOOLS_PATHS)

self_file := $(dir $(lastword $(MAKEFILE_LIST)))/00_mod.mk

.PHONY: tools-learn-sha
## re-download all tools and learn the sha values, useful after upgrading
## @category [shared] Tools
tools-learn-sha:
	rm -rf ./_bin/
	mkdir -p ./_bin/scratch/
	$(eval export LEARN_FILE=$(CURDIR)/$(bin_dir)/scratch/learn_file)
	echo -n "" > "$(LEARN_FILE)"

	HOST_OS=linux HOST_ARCH=amd64 $(MAKE) tools
	HOST_OS=darwin HOST_ARCH=amd64 $(MAKE) tools
	HOST_OS=darwin HOST_ARCH=arm64 $(MAKE) tools

	while read p; do \
		sed -i "$$p" $(self_file); \
	done <"$(LEARN_FILE)"
