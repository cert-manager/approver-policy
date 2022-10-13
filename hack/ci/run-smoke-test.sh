#!/usr/bin/env bash

set -o errexit

REPO_ROOT="${REPO_ROOT:-$(dirname "${BASH_SOURCE}")/../..}"
BINDIR="${BINDIR:-$(pwd)/bin}"

echo ">> running smoke tests"
${BINDIR}/kind get kubeconfig --name approver-policy > ${BINDIR}/kubeconfig.yaml
${BINDIR}/ginkgo $REPO_ROOT/test/smoke/ -- --kubeconfig-path ${BINDIR}/kubeconfig.yaml
