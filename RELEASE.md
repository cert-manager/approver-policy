# Releases

## Schedule

The release schedule for this project is ad-hoc. Given the pre-1.0 status of the project we do not have a fixed release cadence.
However, if a vulnerability is discovered we will respond in accordance with our [security policy](https://github.com/cert-manager/community/blob/main/SECURITY.md) and this response may include a release.

## Process

There is a semi-automated release process for this project. When you create a Git tag with a tag name that has a `v` prefix and push it to GitHub it will trigger the [release workflow].

### Narrate the release in `#cert-manager-dev`

Releases are narrated as a single thread in [`#cert-manager-dev`](https://kubernetes.slack.com/archives/CDEQJ0Q8M) on the Kubernetes Slack. Open the thread before you start the pre-release checks, so each step that follows can be posted as a reply.

Start with a top-level message such as:

```
:thread: Releasing approver-policy v0.26.0 ...
```

As the release progresses, reply in the thread with:

- the pre-release check summary (see below);
- the tag URL after pushing;
- the release-workflow run URL once it starts building;
- the published release URL with `:tada:` once it is live.

This gives the whole team a single, scannable record of what was done, by whom, and when, and lets non-PANW maintainers see what is happening with the steps they cannot perform themselves (see "Post-release: Verify the Helm Chart Reaches ArtifactHub" below).

### Pre-release Checks

1. **Check for known vulnerabilities** using `govulncheck` and `trivy`:
    ```sh
    # Check the govulncheck GitHub Action is green on main:
    # https://github.com/cert-manager/approver-policy/actions/workflows/govulncheck.yaml

    # Run trivy locally (ArtifactHub uses trivy and flags MEDIUM+ vulnerabilities):
    make _bin/tools/trivy
    _bin/tools/trivy fs --scanners vuln .
    ```
    If trivy reports vulnerabilities, bump the affected dependencies before tagging,
    even if they are indirect. ArtifactHub displays trivy results on the
    [security report page](https://artifacthub.io/packages/helm/cert-manager/cert-manager-approver-policy?modal=security-report),
    and users rely on a clean report.

2. **Verify signed-tag config** so the release tag is shown as Verified on GitHub:
    ```sh
    git config --get tag.gpgsign     # must print: true
    git config --get gpg.format      # ssh (or openpgp), matching your signing setup
    git config --get user.signingkey # path to a key that is also registered with GitHub
    ```
    If `tag.gpgsign` is unset, `git tag --annotate` produces an unsigned tag and the
    GitHub release page will display **Unverified** next to the tag. Set it globally
    once with `git config --global tag.gpgsign true` so every future annotated tag
    is signed automatically. (csi-driver-spiffe v0.14.0 was tagged unsigned for this
    exact reason.)

3. **Post a pre-release check summary to the Slack thread** so the team can see the
   state of the world before you tag. Cover: govulncheck/trivy results, any
   outstanding CVEs and how they have been addressed, sidecar image status (none
   for approver-policy), notable community PRs included, dependency updates, and
   anything else relevant to this release.

### Doing a Release

The release process for this repo is documented below:

1. Create a tag for the new release:
    ```sh
    export VERSION=v0.5.0-alpha.0
    git tag --annotate --message="Release ${VERSION}" "${VERSION}"
    git push origin "${VERSION}"
    ```
   Post the tag URL to the Slack thread.

2. A GitHub action will see the new tag and do the following:
    - Build and publish any container images
    - Build and publish the OCI Helm chart
    - Create a draft GitHub release

   Post the workflow-run URL to the Slack thread so others can follow along.

3. Visit the [releases page], edit the draft release, click "Generate release notes", then edit the notes to add the following to the top
    ```
    approver-policy provides a policy engine for certificates issued by cert-manager!
    ```
4. Publish the release. Post the release URL to the Slack thread, prefixed with `:tada:`.

### Post-release: Verify the Helm Chart Reaches ArtifactHub

> [!IMPORTANT]
> The steps in this section can **only be performed by Palo Alto Networks
> employees**. The [jetstack/jetstack-charts](https://github.com/jetstack/jetstack-charts)
> repository is private and pre-dates the cert-manager project moving to a
> community governance model — it remains the path through which OCI charts on
> `quay.io/jetstack` are syndicated to `charts.jetstack.io` and ArtifactHub.
>
> If you are a release manager outside Palo Alto Networks, **do not skip this
> section**. Post in the release Slack thread asking a PANW cert-manager
> maintainer to run these steps, and link them this section as a reference.

The release workflow pushes the Helm chart to `quay.io/jetstack`, and an
`oci-sync` workflow in `jetstack/jetstack-charts` opens a PR to sync it to
`charts.jetstack.io`. That PR requires a maintainer approval before it is merged.
Until it is merged, ArtifactHub will continue to show the previous version.

`oci-sync` runs hourly on cron. If you do not want to wait for the next scheduled
run, trigger it on demand:

```sh
gh workflow run oci-sync.yaml --repo jetstack/jetstack-charts
gh pr list --repo jetstack/jetstack-charts --search "oci-sync" --state open
```

**Before merging the sync PR**, verify that the chart published to the preview
repo matches expectations. The Cloudflare Pages check on the sync PR posts a
deployment preview URL — render the chart for both the new and previous releases
from that preview, and diff them with version-label noise filtered out:

```sh
# PREVIEW is the per-deployment URL from the PR's Cloudflare Pages comment, e.g.
# https://8cebb8e5.jetstack-charts.pages.dev
export PREVIEW=https://DEPLOYMENT-ID.jetstack-charts.pages.dev
export NEW=v0.26.0
export OLD=v0.25.1     # the previous release

helm template ap cert-manager-approver-policy --repo "$PREVIEW" --version "$NEW" > /tmp/ap-new.yaml
helm template ap cert-manager-approver-policy --repo "$PREVIEW" --version "$OLD" > /tmp/ap-old.yaml

diff -u /tmp/ap-old.yaml /tmp/ap-new.yaml \
  | grep -v -E "^[-+][[:space:]]*(helm\.sh/chart:|app\.kubernetes\.io/version:|image:).*(${OLD}|${NEW})"
```

The only remaining diff should correspond to actual behavioural changes shipped
in this release. Then confirm the referenced container image is published with
the expected platforms:

```sh
make _bin/tools/crane
_bin/tools/crane manifest "quay.io/jetstack/cert-manager-approver-policy:${NEW}"
```

Record the commands you ran (and any non-trivial filtered diff) as a comment on
the sync PR before approving and merging — this leaves an audit trail for the
next maintainer. Then approve and merge the sync PR.

After merge, confirm the new version appears on ArtifactHub:
https://artifacthub.io/packages/helm/cert-manager/cert-manager-approver-policy

### Post-release: Check the ArtifactHub Security Report

Once the new version appears on ArtifactHub, check its security report for
vulnerabilities. approver-policy ships only the controller image — there are no
sidecar images — so any finding here is in code or dependencies we control and
should be addressed in a follow-up patch release.

The security report is visible in the web UI at:

https://artifacthub.io/packages/helm/cert-manager/cert-manager-approver-policy/VERSION?modal=security-report

It can also be fetched programmatically using the [ArtifactHub API]. The package
ID for approver-policy is `789b1172-cf45-4599-8553-06248bd5a441`. Note that
ArtifactHub identifies chart versions without the `v` prefix — even though our
release tags and the `version`/`appVersion` fields in `Chart.yaml` carry one —
so the API path uses the bare semver (e.g. `0.26.0`, not `v0.26.0`, which 404s):

```sh
export VERSION=0.26.0
make _bin/tools/yq
curl -sL "https://artifacthub.io/api/v1/packages/789b1172-cf45-4599-8553-06248bd5a441/${VERSION}/security-report" \
  | _bin/tools/yq -p json -o tsv '
    ["IMAGE", "SEVERITY", "CVE", "PACKAGE", "INSTALLED", "FIXED"],
    (
      to_entries[] |
      .key as $image |
      .value.Results[]? |
      .Vulnerabilities[]? |
      [$image, .Severity, .VulnerabilityID, .PkgName, .InstalledVersion, .FixedVersion // "n/a"]
    ) | @tsv
  ' | column -t -s$'\t'
```

### Post-release: Notify Community Contributors

For every non-bot, non-maintainer PR included in the release, comment thanking
the author, linking the release, and asking them to install and verify the
change in their own environment. For every public issue closed by those PRs,
comment on the issue too — invite the original reporter (and any other
commenters) to confirm the fix.

Use this template on the PR:

```
@<author> This change has been included in [vX.Y.Z](https://github.com/cert-manager/approver-policy/releases/tag/vX.Y.Z), which is now published.

Installation instructions are at https://cert-manager.io/docs/policy/approval/approver-policy/installation/

If you are able to install the new release and verify the fix in your environment, that would be much appreciated. Thank you for the contribution.
```

When commenting on a closed issue, tailor the second sentence to the specific
failure the reporter described, rather than the generic "verify the fix"
wording — e.g. "confirm that the controller no longer deadlocks against its own
webhook during reconciliation".

## Artifacts

This repo will produce the following artifacts each release. For documentation on how those artifacts are produced see the "Process" section.

- *Container Images* - Container images are published to `quay.io/jetstack`.
- *Helm chart* - An official Helm chart is maintained within this repo and published to `quay.io/jetstack` on each release.
  *  The chart is also published to the legacy HTTP Helm repository at `https://charts.jetstack.io` (maintained by Venafi).
     Publishing to the legacy repo depends on a PR to be merged in a closed Venafi repo, and might be delayed.

[ArtifactHub API]: https://artifacthub.io/docs/api/
[release workflow]: https://github.com/cert-manager/approver-policy/actions/workflows/release.yaml
[releases page]: https://github.com/cert-manager/approver-policy/releases
