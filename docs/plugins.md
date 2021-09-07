## Plugins

Plugins are external approvers which are built into policy-approver at compile
time. Plugins are designed to be used as extensions to the existing policy
checks where the user requires special functionality that the existing checks
can't provide.

Plugins are defined as a block on the CertificateRequestPolicy Spec.

```yaml
apiVersion: policy.cert-manager.io/v1alpha1
kind: CertificateRequestPolicy
metadata:
  name: plugins
spec:
  ...
  plugins:
    my-plugin:
      values:
        val-1: key-1
```
