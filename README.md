<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>
<p align="center">
  <a href="https://godoc.org/github.com/cert-manager/approver-policy"><img src="https://godoc.org/github.com/cert-manager/approver-policy?status.svg" alt="approver-policy godoc"></a>
  <a href="https://goreportcard.com/report/github.com/cert-manager/approver-policy"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/cert-manager/approver-policy" /></a>
  <a href="https://artifacthub.io/packages/search?repo=cert-manager"><img alt="Artifact Hub" src="https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/cert-manager" /></a>
</p>

# approver-policy

approver-policy is a [cert-manager](https://cert-manager.io) approver that is
responsible for [Approving or Denying
CertificateRequests](https://cert-manager.io/docs/concepts/certificaterequest/#approval).

approver-policy exposes the CertificateRequestPolicy resource which
administrators use to define policy over what, who, and how certificates are
signed by cert-manager.

---

Please follow the documentation at
[cert-manager.io](https://cert-manager.io/docs/usage/approver-policy/) for
installing and using approver-policy.

## Makefile modules

This project uses [Makefile modules](https://github.com/cert-manager/makefile-modules), see the README there for more information.
A summary of the available make targets can be found by running `make help`.

## Release Process

There is a semi-automated release process for approver-policy.
When you create a Git tag with a tagname that has a `v` prefix and push it to GitHub.
it will trigger the [release workflow].
This will create and push a Docker image to `quay.io/jetstack/cert-manager-approver-policy:${{ github.ref_name }}`,
create a Helm chart file,
and finally create *draft* GitHub release with the Helm chart file attached and containing a reference to the Docker image.

1. Create and push a Git tag

```sh
export VERSION=v0.5.0-alpha.0
git tag --annotate --message="Release ${VERSION}" "${VERSION}"
git push origin "${VERSION}"
```

2. Wait for the [release workflow] to succeed and if successful,
   visit the draft release page to download the attached Helm chart attachment.

3. Create a PR in the [jetstack/jetstack-charts repository on GitHub](https://github.com/jetstack/jetstack-charts),
   containing the Helm chart file that is attached to the draft GitHub release.
   Wait for it to be merged and verify that the Helm chart is available from https://charts.jetstack.io.

4. Visit the [releases page], edit the draft release, click "Generate release notes", and publish the release.

[release workflow]: https://github.com/cert-manager/approver-policy/actions/workflows/release.yaml
[releases page]: https://github.com/cert-manager/approver-policy/releases
