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


## Release Process

Create a Git tag with a tagname that has a `v` prefix and push it to GitHub.
This will trigger the [release workflow].

1. Create and push a Git tag

```sh
export VERSION=v0.5.0-alpha.0
git tag --annotate --message="Release ${VERSION}" "${VERSION}"
git push origin "${VERSION}"
```

2. Wait for the [release workflow] to succeed.

3. Visit the [releases page], edit the draft release, click "Generate release notes", and publish the release.

[release workflow]: https://github.com/cert-manager/approver-policy/actions/workflows/release.yaml
[releases page]: https://github.com/cert-manager/approver-policy/releases
