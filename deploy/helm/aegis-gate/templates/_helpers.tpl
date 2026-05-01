{{/*
Expand the name of the chart.
*/}}
{{- define "aegis-gate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name. Truncated to 63 chars (k8s name limit).
*/}}
{{- define "aegis-gate.fullname" -}}
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

{{/*
Chart label.
*/}}
{{- define "aegis-gate.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "aegis-gate.labels" -}}
helm.sh/chart: {{ include "aegis-gate.chart" . }}
{{ include "aegis-gate.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels — used by Service + Deployment to match pods.
*/}}
{{- define "aegis-gate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aegis-gate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "aegis-gate.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "aegis-gate.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Generated WafConfig YAML when `config.raw` is unset. Renders the
minimum viable shape for an HA deployment with the values.yaml
knobs the chart exposes.
*/}}
{{- define "aegis-gate.generatedConfig" -}}
listeners:
  data:
{{- if .Values.config.listeners.dataPlaintext.enabled }}
    - bind: "0.0.0.0:{{ .Values.config.listeners.dataPlaintext.port }}"
      tls: false
{{- end }}
{{- if .Values.config.listeners.dataTls.enabled }}
    - bind: "0.0.0.0:{{ .Values.config.listeners.dataTls.port }}"
      tls: true
{{- end }}
  admin:
    bind: "{{ .Values.admin.bind }}"
{{- if .Values.config.listeners.dataTls.enabled }}

tls:
  min_version: "1.2"
  certificates:
    - cert_path: "/etc/aegis/tls/tls.crt"
      key_ref:   "/etc/aegis/tls/tls.key"
      hosts: {{ .Values.tls.hosts | toJson }}
  hsts:
    max_age: 31536000
    include_subdomains: true
    preload: false
{{- end }}

state:
  backend: {{ .Values.config.state.backend | quote }}
{{- if eq .Values.config.state.backend "redis" }}
  redis:
    url: "${secret:env:AEGIS_REDIS_URL}"
{{- end }}

load_mode:
  elevated_rps: {{ .Values.config.load_mode.elevated_rps }}
  critical_rps: {{ .Values.config.load_mode.critical_rps }}
  sample_interval: 1s
  hysteresis:      0.10

admin:
  bind: "{{ .Values.admin.bind }}"
  dashboard_auth:
    password_hash_ref: "${secret:env:AEGIS_ADMIN_PASSWORD_HASH}"
    csrf_secret_ref:   "${secret:env:AEGIS_CSRF_SECRET}"
    session_ttl_idle: "30m"
    session_ttl_absolute: "8h"
    ip_allowlist: {{ .Values.admin.ipAllowlist | toJson }}
    totp_enabled: {{ .Values.admin.totp.enabled }}
{{- end }}
