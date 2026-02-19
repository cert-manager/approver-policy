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
*/}}
{{- define "cert-manager-approver-policy.labels" -}}
app.kubernetes.io/name: {{ include "cert-manager-approver-policy.name" . }}
helm.sh/chart: {{ include "cert-manager-approver-policy.chart" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Values.commonLabels}}
{{ toYaml .Values.commonLabels }}
{{- end }}
{{- end -}}

{{/*
Util function for generating the image URL based on the provided options.
IMPORTANT: This function is standarized across all charts in the cert-manager GH organization.
Any changes to this function should also be made in cert-manager, trust-manager, approver-policy, ...
See https://github.com/cert-manager/cert-manager/issues/6329 for a list of linked PRs.
*/}}
{{- define "image" -}}
{{- $image := index . 0 -}}
{{- $defaultTag := index . 1 -}}
{{- $root := index . 2 -}}
{{- $repo := "" -}}
{{- if $image.repository -}}
{{- $repo = $image.repository -}}
{{- else -}}
{{- $registry := $root.Values.imageRegistry -}}
{{- $namespace := $root.Values.imageNamespace -}}
{{- $name := $image.name -}}
{{- if $registry -}}
{{- if $namespace -}}
{{- $repo = printf "%s/%s/%s" $registry $namespace $name -}}
{{- else -}}
{{- $repo = printf "%s/%s" $registry $name -}}
{{- end -}}
{{- else -}}
{{- if $namespace -}}
{{- $repo = printf "%s/%s" $namespace $name -}}
{{- else -}}
{{- $repo = $name -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if $image.registry -}}
{{- $repo = printf "%s/%s" $image.registry $repo -}}
{{- end -}}
{{- $repo -}}
{{- if $image.digest -}}
{{ printf "@%s" $image.digest }}
{{- else -}}
{{ printf ":%s" (default $defaultTag $image.tag) }}
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
