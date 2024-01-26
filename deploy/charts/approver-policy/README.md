# cert-manager-approver-policy

approver-policy is a CertificateRequest approver for cert-manager

**Homepage:** <https://cert-manager.io/docs/policy/approval/approver-policy/>

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| cert-manager-dev | <cert-manager-dev@googlegroups.com> | <https://cert-manager.io> |

## Source Code

* <https://github.com/cert-manager/approver-policy>

## Values

<!-- AUTO-GENERATED -->


<table>
<tr>
<th>Property</th>
<th>Description</th>
<th>Type</th>
<th>Default</th>
</tr>
<tr>

<td>replicaCount</td>
<td>

Number of replicas of approver-policy to run.

</td>
<td>number</td>
<td>

```yaml
1
```

</td>
</tr>
<tr>

<td>image.repository</td>
<td>

Target image repository.

</td>
<td>string</td>
<td>

```yaml
quay.io/jetstack/cert-manager-approver-policy
```

</td>
</tr>
<tr>

<td>image.registry</td>
<td>

Target image registry. This value is prepended to the target image repository, if set.

</td>
<td>unknown</td>
<td>

```yaml
null
```

</td>
</tr>
<tr>

<td>image.tag</td>
<td>

Target image version tag. Defaults to the chart's appVersion.

</td>
<td>unknown</td>
<td>

```yaml
null
```

</td>
</tr>
<tr>

<td>image.digest</td>
<td>

Target image digest. Override any tag, if set.  
For example:

```yaml
digest: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20
```

</td>
<td>unknown</td>
<td>

```yaml
null
```

</td>
</tr>
<tr>

<td>image.pullPolicy</td>
<td>

Kubernetes imagePullPolicy on Deployment.

</td>
<td>string</td>
<td>

```yaml
IfNotPresent
```

</td>
</tr>
<tr>

<td>imagePullSecrets</td>
<td>

Optional secrets used for pulling the approver-policy container image.

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>app.logLevel</td>
<td>

Verbosity of approver-policy logging. This is a value from 1 to 5.

</td>
<td>number</td>
<td>

```yaml
1
```

</td>
</tr>
<tr>

<td>app.extraArgs</td>
<td>

Extra CLI arguments that will be passed to the approver-policy process.

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>app.approveSignerNames</td>
<td>

List if signer names that approver-policy will be given permission to approve and deny. CertificateRequests referencing these signer names can be processed by approver-policy.  
  
ref: https://cert-manager.io/docs/concepts/certificaterequest/#approval


</td>
<td>array</td>
<td>

```yaml
- issuers.cert-manager.io/*
- clusterissuers.cert-manager.io/*
```

</td>
</tr>
<tr>

<td>app.metrics.port</td>
<td>

Port for exposing Prometheus metrics on 0.0.0.0 on path '/metrics'.

</td>
<td>number</td>
<td>

```yaml
9402
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor</td>
<td>

Create a Service resource to expose metrics endpoint.

</td>
<td>bool</td>
<td>

```yaml
true
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor</td>
<td>

The service type to expose metrics.

</td>
<td>string</td>
<td>

```yaml
ClusterIP
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor.enabled</td>
<td>

Create Prometheus ServiceMonitor resource for approver-policy.

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor.prometheusInstance</td>
<td>

The value for the "prometheus" label on the ServiceMonitor. This allows for multiple Prometheus instances selecting difference ServiceMonitors using label selectors.

</td>
<td>string</td>
<td>

```yaml
default
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor.interval</td>
<td>

The interval that the Prometheus will scrape for metrics.

</td>
<td>string</td>
<td>

```yaml
10s
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor.scrapeTimeout</td>
<td>

The timeout on each metric probe request.

</td>
<td>string</td>
<td>

```yaml
5s
```

</td>
</tr>
<tr>

<td>app.metrics.service.servicemonitor.labels</td>
<td>

Additional labels to give the ServiceMonitor resource.

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>app.readinessProbe.port</td>
<td>

The container port to expose approver-policy HTTP readiness probe on default network interface.

</td>
<td>number</td>
<td>

```yaml
6060
```

</td>
</tr>
<tr>

<td>app.webhook.host</td>
<td>

The host that the webhook listens on.

</td>
<td>string</td>
<td>

```yaml
0.0.0.0
```

</td>
</tr>
<tr>

<td>app.webhook.port</td>
<td>

The port that the webhook listens on.

</td>
<td>number</td>
<td>

```yaml
10250
```

</td>
</tr>
<tr>

<td>app.webhook.timeoutSeconds</td>
<td>

The timeout of webhook HTTP request.

</td>
<td>number</td>
<td>

```yaml
5
```

</td>
</tr>
<tr>

<td>app.webhook.service.type</td>
<td>

The type of Kubernetes Service used by the webhook.

</td>
<td>string</td>
<td>

```yaml
ClusterIP
```

</td>
</tr>
<tr>

<td>app.webhook.hostNetwork</td>
<td>

Boolean value, expose pod on hostNetwork.  
Required when running a custom CNI in managed providers such as AWS EKS.  
  
For more information, see [AWS EKS](https://cert-manager.io/docs/installation/compatibility/#aws-eks).

</td>
<td>bool</td>
<td>

```yaml
false
```

</td>
</tr>
<tr>

<td>app.webhook.dnsPolicy</td>
<td>

This value may need to be changed if `hostNetwork: true`

</td>
<td>string</td>
<td>

```yaml
ClusterFirst
```

</td>
</tr>
<tr>

<td>app.webhook.affinity</td>
<td>

A Kubernetes Affinity, if required. For more information, see [Affinity v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#affinity-v1-core).  
  
For example:

```yaml
affinity:
  nodeAffinity:
   requiredDuringSchedulingIgnoredDuringExecution:
     nodeSelectorTerms:
     - matchExpressions:
       - key: foo.bar.com/role
         operator: In
         values:
         - master
```

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>app.webhook.nodeSelector</td>
<td>

The nodeSelector on Pods tells Kubernetes to schedule Pods on the nodes with matching labels. For more information, see [Assigning Pods to Nodes](https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/).

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>app.webhook.tolerations</td>
<td>

A list of Kubernetes Tolerations, if required. For more information, see [Toleration v1 core](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.27/#toleration-v1-core).  
  
For example:

```yaml
tolerations:
- key: foo.bar.com/role
  operator: Equal
  value: master
  effect: NoSchedule
```

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>volumeMounts</td>
<td>

Optional extra volume mounts. Useful for mounting custom root CAs.  
  
For example:

```yaml
volumeMounts:
- name: my-volume-mount
  mountPath: /etc/approver-policy/secrets
```

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>volumes</td>
<td>

Optional extra volumes.  
  
For example:

```yaml
volumes:
- name: my-volume
  secret:
    secretName: my-secret
```

</td>
<td>array</td>
<td>

```yaml
[]
```

</td>
</tr>
<tr>

<td>resources</td>
<td>

Kubernetes pod resources.  
For more information, see [Resource Management for Pods and Containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/).  
  
For example:

```yaml
resources:
  limits:
    cpu: 100m
    memory: 128Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>commonLabels</td>
<td>

Allow custom labels to be placed on resources - optional.

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
<tr>

<td>podAnnotations</td>
<td>

Allow custom annotations to be placed on cert-manager-approver pod - optional.

</td>
<td>object</td>
<td>

```yaml
{}
```

</td>
</tr>
</table>

<!-- /AUTO-GENERATED -->