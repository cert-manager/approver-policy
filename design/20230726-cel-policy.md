<!--
This template is adapted from Kubernetes Enchancements KEP template https://raw.githubusercontent.com/kubernetes/enhancements/a86942e8ba802d0035ec7d4a9c992f03bca7dce9/keps/NNNN-kep-template/README.md
-->

# CEL validation rules to approve or deny a CertificateRequest

<!-- toc -->
- [Release Signoff Checklist](#release-signoff-checklist)
- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Proposal](#proposal)
  - [User Stories](#user-stories-optional)
    - [X.509 DNS SAN in namespace domain](#x509-dns-san-in-namespace-domain)
    - [SPIFFE ID identifying namespace](#spiffe-id-identifying-namespace)
  - [Notes/Constraints/Caveats (Optional)](#notesconstraintscaveats-optional)
  - [Risks and Mitigations](#risks-and-mitigations)
- [Design Details](#design-details)
  - [Test Plan](#test-plan)
  - [Graduation Criteria](#graduation-criteria)
  - [Upgrade / Downgrade Strategy](#upgrade--downgrade-strategy)
  - [Supported Versions](#supported-versions)
- [Production Readiness](#production-readiness)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
  - [CEL expressions with semantics similar to values](#cel-expressions-with-semantics-similar-to-values)
  - [CEL expressions with full decoded CSR variable](#cel-expressions-with-full-decoded-csr-variable)
<!-- /toc -->

## Release Signoff Checklist

This checklist contains actions which must be completed before a PR implementing this design can be merged.


- [x] This design doc has been discussed and approved
- [ ] Test plan has been agreed upon and the tests implemented 
- [ ] Feature gate status has been agreed upon (whether the new functionality will be placed behind a feature gate or not)
- [ ] Graduation criteria is in place if required (if the new functionality is placed behind a feature gate, how will it graduate between stages)
- [ ] User-facing documentation has been PR-ed against the release branch in [cert-manager/website]


## Summary

<!--
This section is important for producing high-quality, user-focused
documentation such as release notes.

A good summary is probably around a paragraph in length.

[documentation style guide]: https://github.com/kubernetes/community/blob/master/contributors/guide/style-guide.md
-->

While approver-policy allows policies to include namespace selectors, this does not scale when attempting to
enforce CSR attributes that must be a function of the CertificateRequest's namespace (or other CertificateRequest fields).
This proposal suggests an extension to the CertificateRequestPolicy API allowing policy authors to specify approval rules using
[CEL in Kubernetes](https://kubernetes.io/docs/reference/using-api/cel/) using variables with information from the CertificateRequest.

## Motivation

<!--
This section is for explicitly listing the motivation, goals, and non-goals of
the proposed enhancement.  Describe why the change is important and the benefits to users. The
motivation section can optionally provide links to
demonstrate the interest in this functionality amongst the community.
-->

### Goals

<!--
List specific goals. What is this proposal trying to achieve? How will we
know that this has succeeded?
-->

- allow policy authors to express `allowed` CSR attribute values to be a function of CertificateRequest's fields using CEL expressions
- include variables with `namespace` and `name` of the CertificateRequest in the CEL context provided to expressions
- validate CEL expressions in CertificateRequestPolicy on admission
- extensions to the CertificateRequestPolicy API should be backwards compatible

### Non-Goals

<!--
What is out of scope for this proposal? Listing non-goals helps to focus discussion
and make progress.
-->

- CEL support in CertificateRequestPolicy `constraints`
- CEL variable with decoded CSR in the CEL context provided to expressions

## Proposal

<!--
This is where we get down to the specifics of what the proposal actually is.
What is the desired outcome and how do we measure success?
This should have enough detail that reviewers can understand exactly what
you're proposing, but should not include things like API designs or
implementation- those should go into "Design Details" below.
-->

The current CertificateRequestPolicy API allows a policy author to specify `allowed` CSR attributes in the
CertificateRequest, and will deny the request if it contains an attribute which is not present in the `allowed` block.
To configure valid CSR attribute values, the API provides fields for allowed
`values` (array; any element matching the attribute is sufficient),
`value` (must match the attribute) or an array of literals/enums (in `usages`) depending on the requested attribute.
Allowed string fields accept wildcards `"*"` within their values.

This proposal suggests adding support for specifying allowed string fields using CEL expressions, similar to the existing
wildcard support. While CEL expressions could eventually replace the current CSR attribute validation API - including the 
wildcard support, the main improvement would be support for policies that specify an allowed attribute value that depends
on CertificateRequest fields, e.g. `namespace`. If implemented, this new feature would close
[#62](https://github.com/cert-manager/approver-policy/issues/62).

An [experimental approver-policy plugin](https://github.com/erikgb/cel-approver-policy-plugin) providing some of the
requested features exists, and the proposal (including alternatives) is inspired by this plugin.
The main downside of using a plugin for this, in addition to increased maintenance/complexity,
is that the approver-policy rules are still in play.
Which means that approver rules are somehow duplicated in the `allowed` block and in the plugin configuration but
this should be avoided as maintaining things in multiple places is error-prone.


### User Stories (Optional)

<!--
Detail the things that people will be able to do if this proposal gets implemented.
Include as much detail as possible so that people can understand the "how" of
the system. The goal here is to make this feel real for users without getting
bogged down.
-->

#### X.509 DNS SAN in namespace domain

As a cluster admin in a multi-tenant cluster, I want to provide a cert-manager ClusterIssuer to our users allowing
self-provisioning of server certificates. Since the cluster is multi-tenant, I want to ensure that tenants do not
"trip on each other's toes" and enforce that the issuer only signs certificates where the X.509 DNS SAN attribute
ends with `<namespace>.<domain>`.

A variant of this user story is exemplified in [#62](https://github.com/cert-manager/approver-policy/issues/62),
and I think it's one of the most common user stories the proposed feature will solve.

#### SPIFFE ID identifying namespace

As a cluster admin in a multi-tenant cluster, I want to provide a cert-manager ClusterIssuer to our users allowing
self-provisioning of [X.509 SVID certificates](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md).
The [SPIFFE ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md) (X.509 URI SAN) should identify
the namespace (and service account), and must start with `spiffe://<trust-domain>/ns/<namespace>/sa/`.

### Notes/Constraints/Caveats (Optional)

<!--
What are the caveats to the proposal?
What are some important details that didn't come across above?
Go into as much detail as necessary here.
This might be a good place to talk about core concepts and how they relate.
-->

N/A

### Risks and Mitigations

<!--
What are the risks of this proposal, and how do we mitigate? Think broadly.
For example, consider both security and how this will impact the larger
Kubernetes/PKI ecosystem.

-->

N/A

## Design Details

<!--
This section should contain enough information that the specifics of your
change are understandable. This may include API specs (though not always
required) or even code snippets. If there's any ambiguity about HOW your
proposal will be implemented, this is the place to discuss them.
-->

The proposal is to add sibling properties to `values` and `value` properties inside the `allowed` block.
The new fields should contain CEL validations used to validate CSR attribute values with similar
[behavior](https://cert-manager.io/docs/projects/approver-policy/#allowed) as approver-policy has today,
but with the following extension: If validations are present for the given CSR attribute, and **ALL**
validations pass for **ALL* attribute values, the attribute will be allowed.

Note: To ensure we don't break behaviors in the existing API version, the following should be enforced:

* if `required` is set to `true` in policy and attribute value empty in request, the request will be denied
  by policy without running any validations.
* if `required` is set to `true` in policy, the policy will need specify `values`/`value` or `validations`.
  This should be enforced by the webhook.
* if attribute value not empty in request, the request will be denied by policy if `values`/`value`
  and `validations` are both unset.

Most CSR attributes can have multiple values, and it could make sense to have validations on the list of
attribute values. Example: Limit the number of `dnsNames`. But we think that the most common use case is to
validate attribute value (per-item validation). Support for more complex validations, including cross-attribute
validation, can eventually be added later.

The validations themselves should be expressed using the same API as Kubernetes `x-kubernetes-validations`, having
a mandatory `rule` field for the CEL expression and an optional `message` field for the validation error message.

A request attribute value could be allowed by the policy if `values`/`value` or `validations` are specified.

To use validations in CertificateRequestPolicy the API may look like this (example):

```yaml
spec:
  allowed:
    dnsNames:
      validations:
        - message: only dnsNames in the local namespace service domain is allowed.
          rule: self.endsWith(cr.namespace + '.svc') || self.endsWith(cr.namespace + '.svc.cluster.local')
```

The CEL context variable `self` is inspired by
[CEL expressions in Kubernetes](https://kubernetes.io/docs/reference/using-api/cel/),
and should appear familiar to our users. 

It should be allowed to mix `values` and `validations`, so the following policy should also be acceptable:

```yaml
spec:
  allowed:
    dnsNames:
      values:
        - "*.sub.domain.com"
      validations:
        - message: dnsName can be maximum 64 characters.
          rule: self.size() =< 64
```

For this example, I would expect the attribute to be checked against the `values` first. If the `DNSName` CSR attribute
matches any value (**OR**ed), we would continue with the validations. Remember that **ALL** `validations` must pass
(**AND**ed) for the request to be permitted.

As stated in the [goals](#goals), the CEL validations should be checked/validated on CertificateRequestPolicy admission.
Since the `cel.Program` generated at the end of parse and check is stateless, thread-safe, and cacheable it should
be cached in approver-policy to speed up things.

### Test Plan

<!---
Describe how the new functionality will be tested (unit tests, integration tests (if applicable), e2e tests)
-->

N/A

### Graduation Criteria

<!--

Describe whether the proposed functionality will be feature gated and why (or why not).

Define graduation milestones and criteria if it should be feature-gated.

Feature maturity is defined using stages alpha, beta, GA.
Feature-gated functionality starts off at alpha and graduates through stages following the defined graduation criteria.
A feature that is in alpha or beta must be opt-in.

Example graduation criteria:

Alpha:

- Feature implemented behind a feature flag
- It is clearly defined which Kubernetes versions this feature supports
- CI tests pass for all supported Kubernetes versions

Beta:

- Gather user feedback

GA:

- N examples of real-world usage
- N installs
- Allowing time for feedback
- Works on all versions of Kubernetes supported by the version of cert-manager at which this feature becomes GA

References in Kubernetes documentation:

[feature gate]: https://git.k8s.io/community/contributors/devel/sig-architecture/feature-gates.md
[maturity-levels]: https://git.k8s.io/community/contributors/devel/sig-architecture/api_changes.md#alpha-beta-and-stable-versions
-->

N/A

### Upgrade / Downgrade Strategy

<!--
Will this feature affect upgrade/downgrade of cert-manager?
-->

N/A

### Supported Versions

<!--
What versions of Kubernetes (and other external services if applicable) will this feature support?
-->

N/A

## Production Readiness
<!--
This section should confirm that the feature can be safely operated in production environment and can be disabled or rolled back in case it is found to increase failures.
-->

N/A

### How can this feature be enabled / disabled for an existing cert-manager installation?

<!--

Can the feature be disabled after having been enabled?

Consider whether any additional steps will need to be taken to start/stop using this feature, i.e change existing resources that have had new field added for the feature before disabling it.


Do the test cases cover both the feature being enabled and it being disabled (where relevant)?

-->

N/A

### Does this feature depend on any specific services running in the cluster?

<!--
For example, are external dependencies such as ingress controllers, third party CRDs etc required for this feature to function?
-->

N/A

### Will enabling / using this feature result in new API calls (i.e to Kubernetes apiserver or external services)?
<!--
We should ensure that cert-manager does not hammer any external services with excessive calls.
Consider whether there will be sufficient backoff if any external calls fail and need to be retried.
-->

N/A

### Will enabling / using this feature result in increasing size or count of the existing API objects?

<!--
For example, will cert-manager `CustomResourceDefinition`s increase in size, will there be more `Secret`s or `CertificateRequest`s created?
-->

No

### Will enabling / using this feature result in significant increase of resource usage? (CPU, RAM...)

<!--
For example, will implementing this feature result in more objects being cached thus increasing memory consumption?
-->

Compiled CEL expressions should be cached to increase performance. This might lead to more memory being
consumed by pods. We should probably consider adding some cache expiration logic to avoid appearing like
a memory leak.

## Drawbacks

<!--
Why should this proposal _not_ be implemented?
-->

N/A

## Alternatives

<!--
What other approaches did you consider, and why did you rule them out? These do
not need to be as detailed as the proposal, but should include enough
information to express the idea and why it was not acceptable.
-->

### CEL expressions with semantics similar to values

_Note: This was the original proposal, after some consideration it was considered inferior to the current proposal,
mainly because we think we should align this CEL API extension more towards how Kubernetes supports CEL._

The proposal is to add sibling properties to `values` and `value` properties inside the `allowed` block. The new
fields should contain CEL expressions used to validate CSR attributes with the same
[behavior](https://cert-manager.io/docs/projects/approver-policy/#allowed) as approver-policy has
today, but with the following extension: If any value **OR** expression matches the corresponding CSR attribute,
the attribute will be allowed.

For the CEL expressions, we need to decide if they should either:

1. Emit a string that will be used as values do. Example: `'*.%s.svc'.format(cr.namespace)`
2. Return a bool indicating if the expression allows the value. Example: `self.endsWith(cr.namespace + '.svc')` (preferred)

To use expressions in CertificateRequestPolicy the API may look like this (example):

```yaml
spec:
  allowed:
    dnsNames:
      expressions:
        - "self.endsWith(cr.namespace + '.svc')"
        - "self.endsWith(cr.namespace + '.svc.cluster.local')"
```

The CEL context variable `self` is inspired by
[CEL expressions in Kubernetes](https://kubernetes.io/docs/reference/using-api/cel/),
and should appear familiar to our users. CEL expressions returning a bool will resemble Kubernetes CEL validation
expressions and is preferred for this reason (IMO).

It should be allowed to mix `values` and `expressions`, so the following policy should also be acceptable:

```yaml
spec:
  allowed:
    dnsNames:
      expressions:
        - "self.endsWith(cr.namespace + '.apps.my-cluster.com')"
      values:
        - "*.sub.domain.com"
```

### CEL expressions with full decoded CSR variable

This alternative was suggested by @inteon on Slack.

The idea here is to provide the policy author with a CEL context variable containing the decoded CSR replacing the
`self` variable in the proposed design. Since the expressions now get access to the full CSR, the expressions will have
to be "promoted" in the CertificateRequestPolicy API. The expression will have to return a bool indicating approved or
denied. An example policy with this alternative API might look like (example):

```yaml
spec:
  expressions:
    - >-
      has(csr.dnsNames) &&
      csr.dnsNames.all(dnsName,
      dnsName.endsWith(cr.namespace + '.svc') ||
      dnsName.endsWith(cr.namespace + '.svc.cluster.local'))
```

Pros:

- Extremely flexible. I.e. allows for CSR cross-attribute validation.
- Some would find this API more expressive and better describe the intentions.

Cons:

- More complex expressions that will require more in-depth knowledge of CEL.
- Will create a "split" API, since you would probably use either `expressions` or `allowed`/`constraints`.
  This could increase the maintenance burden and lead to subtle bugs. Breaking the API could be an option to mitigate this.
- Will probably require custom CEL functions to fulfill the requirements in approver-policy. This is the main reason for
  recommending this design, and will be elaborated below.

Let me start with a quote from the
[approver-policy documentation](https://cert-manager.io/docs/projects/approver-policy/#allowed):

> Allowed is the block that defines attributes that match against the corresponding attribute in the request.
> A request is permitted by the policy if the request omits an allowed attribute, but will deny the request if
> it contains an attribute which is not present in the allowed block.

The last sentence describes the requirement that could need custom CEL function(s) to allow the user to specify allowed
CSR attributes. We cannot expect the user to include validations for **all** CSR attributes in the expression(s). So I
think we at least need a function to list allowed CSR attribute usage.