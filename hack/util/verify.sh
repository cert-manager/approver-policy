#!/usr/bin/env bash
#
# Verify that the supplied command does not make any changes to the repository.
#
# This is called from the Makefile to verify that all code generation scripts
# have been run and that their changes have been committed to the repository.
#
# Runs any of the scripts or Make targets in this repository, after making a
# copy of the repository, then reports any changes to the files in the copy.

# For example:
#
#  make verify-helm-chart-update || \
#    make helm-chart-update
#
set -o errexit
set -o nounset
set -o pipefail

projectdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../.." && pwd )"

cd "${projectdir}"

# Use short form arguments here to support BSD/macOS. `-d` instructs
# it to make a directory, `-t` provides a prefix to use for the directory name.
tmp="$(mktemp -d /tmp/verify.sh.XXXXXXXX)"

cleanup() {
    rm -rf "${tmp}"
}
trap "cleanup" EXIT SIGINT

cp -a "${projectdir}/." "${tmp}"
pushd "${tmp}" >/dev/null

"$@"

popd >/dev/null

if ! diff \
    --exclude=".git" \
    --exclude="_bin" \
    --exclude="helm_jsonschema" \
    --new-file --unified --show-c-function --recursive "${projectdir}" "${tmp}"
then
    echo
    echo "Project '${projectdir}' is out of date."
    echo "Please run '${*}'"
    exit 1
fi
