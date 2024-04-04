# Design: Allow all signers by default

## Summary

Currently approver-policy is by default allowed to approve `CertificateRequest` resources for all cert-manager in-tree issuers.

This is implemented through some [custom RBAC](https://github.com/cert-manager/approver-policy/blob/aca1446b30d5debe4ebca720c65ff4a438615096/deploy/charts/approver-policy/templates/clusterrole.yaml#L24-L30)
which adds the "approve" verb, and the signers are [defaulted](https://github.com/cert-manager/approver-policy/blob/aca1446b30d5debe4ebca720c65ff4a438615096/deploy/charts/approver-policy/values.yaml#L68-L76)
in the Helm chart.

To approve for any other issuer using approver-policy, users are required to find the name of the "signer" value and append to
the `approveSignerNames` helm value.

This design proposes to default to allowing all signers.

## Justification

The current mechanism of needing to update `approveSignerNames` is extremely counter-intuitive. This has been observed
by many people attempting to use approver-policy; it's a common foot-gun for anyone trying to use external issuers.

This is partially because approver-policy exists as a sister project to cert-manager, and many external issuers will
(quite reasonably) not document the required signer names and the steps needed to use that issuer with approval.

This means that when users try to use external issuers with approval, it's a common thing to forget to update these
values. There is no hard data on how common this is, but anecdotally many hours have been spent by users trying to
debug this.

Thus, the main reason for making this change is to make approver-policy easier to use with external issuers.

This proposal is not suggesting that the "approve" verb should be removed, since users may wish to have flexibility in
restricting approver-policy - the proposal is simply that the default should allow all signers rather than just
cert-manager's built in ones.

### Why Is This So Confusing?

A big reason is that users must _already_ specify an `issuerRef` in their `CertificateRequestPolicy` resources. This
means that users already have the ability to restrict which issuers a policy will apply to - and as such, admins
implementing approver-policy may quite reasonably forget that the need to also allow issuers in RBAC.

Another big contributing factor is that users have to deal with `CertificateRequestPolicy` RBAC in a different way;
through a Role/ClusterRole allowing the "use" verb for `CertificateRequestPolicy` resources. The signer RBAC gets
forgotten by users that have to configure their `CertificateRequestPolicy` RBAC.

## Security Impact

Any change to RBAC will naturally invite questions as to the security impact of the change. In this case, the
expansion of permissions may allow approver-policy to approve `CertificateRequest` resources which it couldn't
previously. It's important to examine the impact.

We believe this change will have no practical impact beyond making approver-policy easier to use, in the vast
majority of use cases.

To determine the impact of this change, we need to ask the following question:

> "When would a user apply RBAC to restrict the signers that approver-policy can approve for?"

The answer is that a user would do this when they wish for approver-policy to apply to some issuers but not all.
This is a complex use case and is vanishingly rare, but in such a scenario the user would have to modify the
`approveSignerNames` value to match their needs.

Put another way, the current default is only relevant for security in the case that:

- a user wishes to restrict approver-policy to only approve for certain issuers
- the cluster is running at least one external issuer already
- the user wishes to use approver-policy for all in-tree issuers
- the user wishes to not use approver-policy for any external issuers

Outside of this specific scenario, changing the default can have no security impact because users would have already
had to change the `approveSignerNames` value or else the user wouldn't wish to restrict approver-policy to only apply
to other issuers and they wouldn't care about the changing default.

In this specific scenario, changing the default might have a security impact because we'd allow more signers
than the user intended. This seems like a fine trade-off; allowing all signers will massively improve UX (and especially
so for users getting started for the first time) and the described scenario is incredibly specific and rare.

We will document in release notes that the default has been changed to give any affected user the ability to update their
Helm values before upgrading.
