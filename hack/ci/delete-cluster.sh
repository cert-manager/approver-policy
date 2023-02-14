#!/usr/bin/env bash

set -o errexit

REPO_ROOT="${REPO_ROOT:-$(dirname "${BASH_SOURCE}")/../..}"
KIND_BIN="${KIND_BIN:-$REPO_ROOT/_bin/kind}"

echo ">> exporting kind cluster logs..."
$KIND_BIN export logs --name approver-policy _artifacts

echo ">> deleting kind cluster..."
$KIND_BIN delete cluster --name approver-policy
