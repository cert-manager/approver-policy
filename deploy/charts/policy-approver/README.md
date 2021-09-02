# cert-manager-policy-approver

![Version: v0.1.0](https://img.shields.io/badge/Version-v0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v0.1.0](https://img.shields.io/badge/AppVersion-v0.1.0-informational?style=flat-square)

A Helm chart for cert-manager-policy-approver

**Homepage:** <https://github.com/cert-manager/policy-approver>

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| joshvanl | joshua.vanleeuwen@jetstack.io | https://cert-manager.io |

## Source Code

* <https://github.com/cert-manager/policy-approver>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| app.approveSignerNames | list | `["issuers.cert-manager.io/*","clusterissuers.cert-manager.io/*"]` | List if signer names that policy-approver will be given permission to approve and deny. CertificateRequests referencing these signer names can be processed by policy-approver. See: https://cert-manager.io/docs/concepts/certificaterequest/#approval |
| app.extraArgs | list | `[]` | Extra CLI arguments that will be passed to the policy-approver process. |
| app.logLevel | int | `1` | Verbosity of policy-approver logging. |
| app.metrics.port | int | `9402` | Port for exposing Prometheus metrics on 0.0.0.0 on path '/metrics'. |
| app.metrics.service | object | `{"enabled":true,"servicemonitor":{"enabled":false,"interval":"10s","labels":{},"prometheusInstance":"default","scrapeTimeout":"5s"},"type":"ClusterIP"}` | Service to expose metrics endpoint. |
| app.metrics.service.enabled | bool | `true` | Create a Service resource to expose metrics endpoint. |
| app.metrics.service.servicemonitor | object | `{"enabled":false,"interval":"10s","labels":{},"prometheusInstance":"default","scrapeTimeout":"5s"}` | ServiceMonitor resource for this Service. |
| app.metrics.service.type | string | `"ClusterIP"` | Service type to expose metrics. |
| app.readinessProbe.port | int | `6060` | Container port to expose policy-approver HTTP readiness probe on default network interface. |
| app.webhook.host | string | `"0.0.0.0"` | Host that the webhook listens on. |
| app.webhook.port | int | `6443` | Port that the webhook listens on. |
| app.webhook.service | object | `{"type":"ClusterIP"}` | Type of Kubernetes Service used by the Webhook |
| app.webhook.timeoutSeconds | int | `5` | Timeout of webhook HTTP request. |
| image.pullPolicy | string | `"IfNotPresent"` | Kubernetes imagePullPolicy on Deployment. |
| image.repository | string | `"quay.io/jetstack/cert-manager-policy-approver"` | Target image repository. |
| image.tag | string | `"v0.1.0"` | Target image version tag. |
| replicaCount | int | `1` | Number of replicas of policy-approver to run. |
| resources | object | `{}` |  |
| volumeMounts | list | `[]` | Optional extra volume mounts. Useful for mounting custom root CAs |
| volumes | list | `[]` | Optional extra volumes. |

