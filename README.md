# Policy Approver

Policy Approver is a cert-manager approver that is responsible for [Approving
or Denying
CertificateRequests](https://cert-manager.io/docs/concepts/certificaterequest/#approval).

---


# Installation

To install policy-approver, first cert-manager must be configured so that its
[internal approver is
disabled](https://cert-manager.io/docs/concepts/certificaterequest/#approver-controller).
This can be done via helm using:

```bash
$ helm upgrade -i -n cert-manager cert-manager jetstack/cert-manager --set extraArgs={--controllers='*\,-certificaterequests-approver'} --set installCRDs=true --create-namespace
```

Next, install policy-approver:

```bash
make deploy
```

For policy-approver to approve or deny CertificateRequests that reference
[external issuers](https://cert-manager.io/docs/configuration/external/), add
them to the ClusterRole defined in `config/rbac/approver_clusterrole.yaml` using
the syntax detailed
[here](https://cert-manager.io/docs/concepts/certificaterequest/#rbac-syntax).


# Configuration

When a CertificateRequest is created, the policy-approver will evaluate whether
the request should be approved or denied. This is done by testing whether the
requester is bound to a `CertificateRequestPolicy` that permits that request.

If at least one policy permits the request, the request is approved. If no
policies permits the request, the request is denied.

CertificateRequestPolicies are cluster scoped resources that can be thought of
as a "policy profile". They describe any request which is approved by that
policy. Policies are bound to Kubernetes users and ServiceAccounts using RBAC.
Below is an example of a policy that is bound to all Kubernetes users who may
only request certificates that have the common name of "hello.world". Anything
else in the request is permitted.

```yaml
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicy
metadata:
  name: test-policy
spec:
  allowedCommonName: "hello.world"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cert-manager-policy:hello-world
rules:
  - apiGroups: ["policy.cert-manager.io"]
    resources: ["certificaterequestpolicies"]
    verbs: ["use"]
    resourceNames: ["test-policy"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cert-manager-policy:hello-world
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cert-manager-policy:hello-world
subjects:
- kind: Group
  name: system:authenticated
  apiGroup: rbac.authorization.k8s.io
```

Users must be bound at the cluster scope to match against a
CertificateRequestPolicy.


## Behaviour

Every field of a policy represents a pattern which must match against that of
the request to be permitted.

If a field is omitted from the policy, then it is considered as "allow all",
meaning anything is permissible in the request.

Policy fields that are strings allow for wildcards "\*". Wildcards "\*" in
patterns represent any string which has a length of 0 or more. A pattern
containing only "\*" will match anything. A pattern containing "\*foo" will match
"foo" as well as any string which ends in "foo" (e.g. "bar-foo"). A pattern
containing "\*.foo" will match "bar-123.foo", but not "barfoo".

Policy fields that are lists will permit requests that are a subset of that
list. This means that if `allowedUsages` contains `["server auth", "client
auth"]`, then a request containing only `["server auth"]` would be permitted,
but not `["server auth", "cert sign"]`.


Below is a list of all supported fields of CertificateRequestPolicy.

```yaml
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicy
metadata:
  name: my-policy
spec:
  allowedSubject:
    allowedOrganizations: #["abc", "123"]
    allowedCountries: #["abc", "123"]
    allowedOrganizationalUnits: #["abc", "123"]
    allowedLocalities: #["abc", "123"]
    allowedProvinces: #["abc", "123"]
    allowedStreetAddresses: #["abc", "123"]
    allowedPostalCodes: #["abc", "123"]
    allowedSerialNumber: #"1234"

  allowedCommonName: # "*-istio-ca"

  # Values are inclusive (i.e. a min value with 24h will accept a duration
  # with 25h). minDuration and maxDuration may be the same value.
  minDuration: # "24h"
  maxDuration: # "720h"

  allowedDNSNames:
  #- "*.example.com"
  #- "*.example.net"

  allowedIPAddresses:
  #- "1.2.3.4"
  #- "168.192.3.*"

  allowedURIs:
  #- "spiffe://cluster.local/ns/*/sa/*"
  #- "*.root.com"

  allowedEmailAddresses:
  #- "joshua.vanleeuwen@jetstack.io"
  #- "*@example.com"

  allowedIssuer:
  #- group: cert-manager.io
  #  kind: Issuer
  #  name: my-issuer
  #- group: cas-issuer.jetstack.io
  #  kind: GoogleCASIssuer
  #  name: my-other-issuer

  allowedIsCA: # false

  allowedUsages:
  #- "server auth"
  #- "client auth"

  allowedPrivateKey:
    allowedAlgorithm: # "RSA"
    # Values are inclusive (i.e. a min value with 2048 will accept a size of
    # 2048). MinSize and MaxSize may be the same.
    minSize: # 2048
    maxSize: # 2048
```
