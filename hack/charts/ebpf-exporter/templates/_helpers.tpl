{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "ebpf-exporter.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "ebpf-exporter.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Generate basic labels */}}
{{- define "ebpf-exporter.labels" }}
helm.sh/chart: {{ template "ebpf-exporter.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: metrics
app.kubernetes.io/part-of: {{ template "ebpf-exporter.name" . }}
{{- include "ebpf-exporter.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- if .Values.podLabels}}
{{ toYaml .Values.podLabels }}
{{- end }}
{{- if .Values.releaseLabel }}
release: {{ .Release.Name }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "ebpf-exporter.selectorLabels" }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/name: {{ template "ebpf-exporter.name" . }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "ebpf-exporter.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}


{{/*
Create the name of the service account to use
*/}}
{{- define "ebpf-exporter.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
    {{ default (include "ebpf-exporter.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
    {{ default "default" .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{/*
The image to use
*/}}
{{- define "ebpf-exporter.image" -}}
{{- if .Values.image.sha -}}
{{- printf "%s:%s@%s" .Values.image.repository (default (printf "v%s" .Chart.AppVersion) .Values.image.tag) .Values.image.sha }}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default (printf "v%s" .Chart.AppVersion) .Values.image.tag) }}
{{- end }}
{{- end }}

{{/*
Allow the release namespace to be overridden for multi-namespace deployments in combined charts
*/}}
{{- define "ebpf-exporter.namespace" -}}
  {{- if .Values.namespaceOverride -}}
    {{- .Values.namespaceOverride -}}
  {{- else -}}
    {{- .Release.Namespace -}}
  {{- end -}}
{{- end -}}

{{/*
Create the namespace name of the service monitor
*/}}
{{- define "ebpf-exporter.monitor-namespace" -}}
  {{- if .Values.namespaceOverride -}}
    {{- .Values.namespaceOverride -}}
  {{- else -}}
    {{- if .Values.prometheus.monitor.namespace -}}
      {{- .Values.prometheus.monitor.namespace -}}
    {{- else -}}
      {{- .Release.Namespace -}}
    {{- end -}}
  {{- end -}}
{{- end -}}
