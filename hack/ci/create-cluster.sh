#!/usr/bin/env bash

set -o errexit

REPO_ROOT="${REPO_ROOT:-$(dirname "${BASH_SOURCE}")/../..}"
KUBECTL_BIN="${KUBECTL_BIN:-$REPO_ROOT/_bin/kubectl}"
HELM_BIN="${HELM_BIN:-$REPO_ROOT/_bin/helm}"
KIND_BIN="${KIND_BIN:-$REPO_ROOT/_bin/kind}"
POLICY_APPROVER_TAG="${POLICY_APPROVER_TAG:-smoke}"
POLICY_APPROVER_REPO="${POLICY_APPROVER_REPO:-quay.io/jetstack/cert-manager-approver-policy}"
POLICY_APPROVER_IMAGE="$POLICY_APPROVER_REPO:$POLICY_APPROVER_TAG"

echo ">> building approver-policy binary..."
GOARCH=$(go env GOARCH) GOOS=linux CGO_ENABLED=0 go build -o $REPO_ROOT/_bin/approver-policy-linux $REPO_ROOT/cmd/.

echo ">> building docker image..."
docker build -t $POLICY_APPROVER_IMAGE .

echo ">> pre-creating 'kind' docker network to avoid networking issues in CI"
# When running in our CI environment the Docker network's subnet choice will cause issues with routing
# This works around this till we have a way to properly patch this.
docker network create --driver=bridge --subnet=192.168.0.0/16 --gateway 192.168.0.1 kind || true
# Sleep for 2s to avoid any races between docker's network subcommand and 'kind create'
sleep 2

echo ">> creating kind cluster..."
$KIND_BIN delete cluster --name approver-policy
$KIND_BIN create cluster --name approver-policy

echo ">> loading docker image..."
$KIND_BIN load docker-image $POLICY_APPROVER_IMAGE --name approver-policy

echo ">> installing cert-manager..."
$HELM_BIN repo add jetstack https://charts.jetstack.io --force-update
$HELM_BIN upgrade -i -n cert-manager cert-manager jetstack/cert-manager --set installCRDs=true --wait --create-namespace --set extraArgs={--controllers='*\,-certificaterequests-approver'} --set global.logLevel=2

echo ">> installing approver-policy..."
$HELM_BIN upgrade -i -n cert-manager cert-manager-approver-policy ./deploy/charts/approver-policy --wait --set app.logLevel=2 --set image.repository=$POLICY_APPROVER_REPO --set image.tag=$POLICY_APPROVER_TAG
