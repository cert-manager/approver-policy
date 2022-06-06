<p align="center">
  <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" height="256" width="256" alt="cert-manager project logo" />
</p>
<p align="center">
  <a href="https://godoc.org/github.com/cert-manager/approver-policy"><img src="https://godoc.org/github.com/cert-manager/approver-policy?status.svg" alt="approver-policy godoc"></a>
  <a href="https://goreportcard.com/report/github.com/cert-manager/approver-policy"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/cert-manager/approver-policy" /></a>
  <a href="https://artifacthub.io/packages/search?repo=cert-manager"><img alt="Artifact Hub" src="https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/cert-manager" /></a>
</p>

# approver-policy

approver-policy is a [cert-manager](https://cert-manager.io) approver responsible for
[Approving or Denying CertificateRequests](https://cert-manager.io/docs/concepts/certificaterequest/#approval).

approver-policy exposes the `CertificateRequestPolicy` resource which
administrators use to define policy over what, who, and how certificates are
signed by cert-manager.

---


## Installation

[cert-manager](https://cert-manager.io) is required to be installed with approver-policy.

> :warning:
>
> It is important that the
> [default approver be disabled in cert-manager](https://cert-manager.io/docs/concepts/certificaterequest/#approver-controller).
> If the default approver is not disabled in cert-manager, approver-policy will
> race with cert-manager and thus **approver-policy** will be useless.
>
> ```terminal
> $ helm upgrade -i -n cert-manager cert-manager jetstack/cert-manager --set extraArgs={--controllers='*\,-certificaterequests-approver'} --set installCRDs=true --create-namespace
> ```
>
> :warning:

To install approver-policy:

```terminal
$ helm repo add jetstack https://charts.jetstack.io --force-update
$ helm upgrade -i -n cert-manager cert-manager-approver-policy jetstack/cert-manager-approver-policy --wait
```

If you are using approver-policy with [external
issuers](https://cert-manager.io/docs/configuration/external/), you _must_
include their signer names so that approver-policy has permissions to approve
and deny `CertificateRequests` that
[reference them](https://cert-manager.io/docs/concepts/certificaterequest/#rbac-syntax).
For example, if using approver-policy for the internal issuer types, along with
[google-ca-issuer](https://github.com/jetstack/google-cas-issuer), and
[aws-privateca-issuer](https://github.com/cert-manager/aws-privateca-issuer),
set the following values when installing:

```terminal
$ helm upgrade -i -n cert-manager cert-manager-approver-policy jetstack/cert-manager-approver-policy --wait \
  --set app.approveSignerNames="{\
issuers.cert-manager.io/*,clusterissuers.cert-manager.io/*,\
googlecasclusterissuers.cas-issuer.jetstack.io/*,googlecasissuers.cas-issuer.jetstack.io/*,\
awspcaclusterissuers.awspca.cert-manager.io/*,awspcaissuers.awspca.cert-manager.io/*\
}"
```

---

## Configuration

> Example policy resources can be found [here](./docs/examples/).

When a `CertificateRequest` is created, **approver-policy** will evaluate whether the
request is covered by any existing policies, and if so, evaluate whether it
should be approved or denied.

For a `CertificateRequest` to be covered a policy and therefore be
evaluated by it, it must be both bound via RBAC _and_ be selected by the policy
selector. `CertificateRequestPolicy` currently only supports `issuerRef` as a
selector.

**If at least one policy permits the request, the request is approved. If at
least one policy is appropriate for the request but none of those permit the
request, the request is denied.**

`CertificateRequestPolicy`s are cluster scoped resources that can be thought of
as _policy profiles_. They describe any request that is approved by that
policy. Policies are bound to Kubernetes users and `ServiceAccount`s using RBAC.

Here is an example of a policy that is bound to all Kubernetes users restricting
them to only request certificates with the common name of `hello.world` (it would
also block them from requesting certificates by that common name if they included
any other attributes, see [Allowed](#allowed) for more information):

```yaml
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicy
metadata:
  name: test-policy
spec:
  allowed:
    commonName:
      value: "hello.world"
      required: true
  selector:
    # Select all IssuerRef
    issuerRef: {}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cert-manager-policy:hello-world
rules:
  - apiGroups: ["policy.cert-manager.io"]
    resources: ["certificaterequestpolicies"]
    verbs: ["use"]
    # Name of the CertificateRequestPolicies to be used.
    resourceNames: ["test-policy"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cert-manager-policy:hello-world
roleRef:
# ClusterRole or Role _must_ be bound to a user for the policy to be considered.
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-policy:hello-world
subjects:
# The users who should be bound to the policies defined.
# Note that in the case of users creating Certificate resources, cert-manager
# is the entity that is creating the actual CertificateRequests, and so the
# cert-manager controller's
# Service Account should be bound instead.
- kind: Group
  name: system:authenticated
  apiGroup: rbac.authorization.k8s.io
```

---

## Behaviour

`CertificateRequestPolicy` is split into 4 parts; [`allowed`](#allowed), [`contraints`](#constraints),
[`selector`](#selector), and [`plugins`](#plugins).

### Allowed

Only attributes listed in the `Allowed` block would be acceptable in a request.
If any other attributes are included, the policy will _deny_ the request.

An allowed attribute can be marked as `required`, which if true, will enforce
that the attribute has been defined in the request. A field can only be marked
as `required` if the corresponding field is also defined. The `required` field
is not available for `isCA` or `usages`.

In the following `CertificateRequestPolicy`, a request will be _approved_ if it
omits the DNS name or requests the DNS name `example.com` or `foo.example.com`,
but it will be _denied_ when requesting any other DNS name:

```yaml
spec:
  ...
  allowed:
    dnsNames:
      values:
      - "example.com"
      - "foo.example.com"
  ...
```

In the following, a request will be _denied_ if the request contains no Common
Name, but will _approve_ requests whose Common Name ends in `.com`:

```yaml
spec:
  ...
  allowed:
    commonName:
      value: "*.com"
      required: true
  ...
```

If an allowed field is omitted, that attribute is considered _deny all_ for
requests.

Allowed string fields accept wildcards `*` within their values. Wildcards `*` in
patterns represent any string that has a length of 0 or more. A pattern
containing only `*` will match anything. A pattern containing `*foo` will
match `foo` as well as any string which ends in `foo` (e.g. `bar-foo`). A
pattern containing `*.foo` will match `bar-123.foo`, but not `barfoo`.

Allowed fields that are lists will permit requests that are a subset of that
list. This means that if `081284` contains `["server auth", "client auth"]`,
then a request containing only `["server auth"]` would be permitted, but not
`["server auth", "cert sign"]`.

An example including all supported allowed fields of
`CertificateRequestPolicy`:

```yaml
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicy
metadata:
  name: my-policy
spec:
  allowed:
    commonName:
      value: "example.com"
    dnsNames:
      values:
      - "example.com"
      - "*.example.com"
    ipAddresses:
      values:
      - "1.2.3.4"
      - "10.0.1.*"
    uris:
      values:
      - "spiffe://example.org/ns/*/sa/*"
    emailAddresses:
      values:
      - "*@example.com"
      required: true
    isCA: false
    usages:
    - "server auth"
    - "client auth"
    subject:
      organizations:
        values: ["hello-world"]
      countries:
        values: ["*"]
      organizationalUnits:
        values: ["*"]
      localities:
        values: ["*"]
      provinces:
        values: ["*"]
      streetAddresses:
        values: ["*"]
      postalCodes:
        values: ["*"]
      serialNumber:
        value: "*"
  ...
```

### Constraints

Constraints is the block that is used to limit what attributes the request can
have. If a constraint is not defined, then the attribute is considered _allow
all_.

Below is an example containing all supported constraints fields of
`CertificateRequestPolicy`:

```yaml
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicy
metadata:
  name: my-policy
spec:
  ...
  constraints:
    minDuration: 1h
    maxDuration: 24h
    privateKey:
      algorithm: RSA
      minSize: 2048
      maxSize: 4096
  ...
```

### Selector

Selector is a required field that is used for matching a
`CertificateRequestPolicy` against a `CertificateRequest` for evaluation.
approver-policy currently only supports selecting over the `issuerRef` of a
request.

`issuerRef` values accept wildcards `*`. If an `issuerRef` is set to an empty
object `{}`, then the policy will match against _all_ RBAC bound requests.

```yaml
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicy
metadata:
  name: my-policy
spec:
  ...
  selector:
    issuerRef:
    - name: "my-ca"
      kind: "*Issuer"
      group: "cert-manager.io"
```

```yaml
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicy
metadata:
  name: match-all-requests
spec:
  ...
  selector:
    issuerRef: {}
```

> :warning: Note that the user must still be bound by [RBAC](#Configuration) for
> the policy to be considered for evaluation against a request.

### Plugins

Plugins are built into the approver-policy image at compile time.
See [information on plugins and how to develop them](./docs/plugins.md).

----
