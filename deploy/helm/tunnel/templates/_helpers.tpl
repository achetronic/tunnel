{{/* Expand the chart name. */}}
{{- define "tunnel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully-qualified app name, capped at 63 chars (DNS label limit). If the release
name already contains the chart name, it is not appended again.
*/}}
{{- define "tunnel.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Chart label value: <name>-<version>, with "+" replaced by "_". */}}
{{- define "tunnel.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Common labels applied to every resource. */}}
{{- define "tunnel.labels" -}}
helm.sh/chart: {{ include "tunnel.chart" . }}
{{ include "tunnel.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels for Deployment and Service selectors. These must stay stable
across upgrades, so keep mutable fields out of here.
*/}}
{{- define "tunnel.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tunnel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name to use: the fullname when create is true (unless name is
set), otherwise serviceAccount.name or "default".
*/}}
{{- define "tunnel.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "tunnel.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
