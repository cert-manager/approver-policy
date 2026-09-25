{{/*
Expand the name of the chart.
*/}}
{{- define "cert-manager-approver-policy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cert-manager-approver-policy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels

Labels are merged as a map, not concatenated as YAML text, so a key in
.Values.commonLabels cannot produce a duplicate key. On conflict
.Values.commonLabels wins.

The "app" label is not set here. Resources that carry it merge it in
themselves, because whether it can be overridden depends on whether a
selector reads it.

IMPORTANT: This function is standardized across all charts in the cert-manager GH organization.
Any changes to this function should also be made in cert-manager, trust-manager, google-cas-issuer, ...
See https://github.com/cert-manager/cert-manager/issues/9348 for a list of linked PRs.
*/}}
{{- define "cert-manager-approver-policy.labels" -}}
{{- $labels := dict
  "app.kubernetes.io/name" (include "cert-manager-approver-policy.name" .)
  "helm.sh/chart" (include "cert-manager-approver-policy.chart" .)
  "app.kubernetes.io/instance" .Release.Name
  "app.kubernetes.io/managed-by" .Release.Service
-}}
{{- if .Chart.AppVersion }}
{{- $labels = set $labels "app.kubernetes.io/version" .Chart.AppVersion }}
{{- end }}
{{- toYaml (mergeOverwrite $labels (.Values.commonLabels | default dict)) }}
{{- end -}}

{{/*
Common labels plus "app", for resources that carry it but are not selected
by it.

"app" is applied at a lower precedence than the common labels, so
.Values.commonLabels can still override it, as it could before the labels
were merged. Resources whose "app" label IS read by a selector must not use
this: they merge "app" in at a higher precedence instead, so that it cannot
be overridden and leave the selector matching nothing.
*/}}
{{- define "cert-manager-approver-policy.labelsWithApp" -}}
{{- toYaml (mergeOverwrite
      (dict "app" (include "cert-manager-approver-policy.name" .))
      (include "cert-manager-approver-policy.labels" . | fromYaml)
) }}
{{- end -}}

{{/*
Util function for generating the image URL based on the provided options.
IMPORTANT: This function is standardized across all charts in the cert-manager GH organization.
Any changes to this function should also be made in cert-manager, trust-manager, approver-policy, ...
See https://github.com/cert-manager/cert-manager/issues/6329 for a list of linked PRs.
*/}}
{{- define "approver-policy.image" -}}
{{- /*
Calling convention:

- (tuple <imageValues> <imageRegistry> <imageNamespace> <defaultReference>)

We intentionally pass imageRegistry/imageNamespace as explicit arguments rather than reading
from `.Values` inside this helper, because `helm-tool lint` does not reliably track `.Values.*`
usage through tuple/variable indirection.
*/ -}}

{{- if ne (len .) 4 -}}
  {{- fail (printf "ERROR: template \"approver-policy.image\" expects (tuple <imageValues> <imageRegistry> <imageNamespace> <defaultReference>), got %d arguments" (len .)) -}}
{{- end -}}

{{- $image := index . 0 -}}
{{- $imageRegistry := index . 1 | default "" -}}
{{- $imageNamespace := index . 2 | default "" -}}
{{- $defaultReference := index . 3 -}}

{{- $repository := "" -}}
{{- if $image.repository -}}
  {{- $repository = $image.repository -}}

  {{- /*
    Backwards compatibility: if image.registry is set, additionally prefix the repository with this registry.
  */ -}}
  {{- if $image.registry -}}
    {{- $repository = printf "%s/%s" $image.registry $repository -}}
  {{- end -}}
{{- else -}}
  {{- $name := required "ERROR: image.name must be set when image.repository is empty" $image.name -}}
  {{- $repository = $name -}}

  {{- if $imageNamespace -}}
    {{- $repository = printf "%s/%s" $imageNamespace $repository -}}
  {{- end -}}

  {{- if $imageRegistry -}}
    {{- $repository = printf "%s/%s" $imageRegistry $repository -}}
  {{- end -}}

  {{- /*
    Backwards compatibility: if image.registry is set, additionally prefix the repository with this registry.
  */ -}}
  {{- if $image.registry -}}
    {{- $repository = printf "%s/%s" $image.registry $repository -}}
  {{- end -}}
{{- end -}}

{{- $repository -}}
{{- if and $image.tag $image.digest -}}
  {{- printf ":%s@%s" $image.tag $image.digest -}}
{{- else if $image.tag -}}
  {{- printf ":%s" $image.tag -}}
{{- else if $image.digest -}}
  {{- printf "@%s" $image.digest -}}
{{- else -}}
  {{- printf "%s" $defaultReference -}}
{{- end -}}
{{- end }}

{{/*
Copied from
https://github.com/kyverno/kyverno/blob/df5e39c005a78f1ffe6a2eeda3f4497cc9c24384/charts/kyverno/templates/_helpers/_pdb.tpl
*/}}
{{- define "cert-manager-approver-policy.pdb.spec" -}}
{{- if and .minAvailable .maxUnavailable -}}
  {{- fail "Cannot set both .minAvailable and .maxUnavailable" -}}
{{- end -}}
{{- if not .maxUnavailable -}}
minAvailable: {{ default 1 .minAvailable }}
{{- end -}}
{{- if .maxUnavailable -}}
maxUnavailable: {{ .maxUnavailable }}
{{- end -}}
{{- end -}}
