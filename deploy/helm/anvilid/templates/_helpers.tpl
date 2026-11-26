{{/* Chart name. */}}
{{- define "anvilid.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fully qualified app name (release-prefixed unless it already contains the chart name). */}}
{{- define "anvilid.fullname" -}}
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

{{- define "anvilid.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "anvilid.selectorLabels" -}}
app.kubernetes.io/name: {{ include "anvilid.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "anvilid.labels" -}}
helm.sh/chart: {{ include "anvilid.chart" . }}
{{ include "anvilid.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* image reference: repository@digest, or repository:tag (tag defaults to appVersion). */}}
{{- define "anvilid.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{/* true when more than one pod can run at a time. */}}
{{- define "anvilid.multiNode" -}}
{{- if or (gt (int .Values.replicaCount) 1) .Values.hpa.enabled }}true{{ end }}
{{- end }}

{{/* true when a shared rate limiter is configured. */}}
{{- define "anvilid.hasRedis" -}}
{{- if or .Values.redis.url .Values.redis.existingSecretKey }}true{{ end }}
{{- end }}

{{/* SQLite volume claim name. */}}
{{- define "anvilid.claimName" -}}
{{- default (printf "%s-data" (include "anvilid.fullname" .)) .Values.persistence.existingClaim }}
{{- end }}

{{/*
Template-time safety checks. Unsafe configurations fail `helm template` / `helm install` instead of
producing a deployment that silently misbehaves.
*/}}
{{- define "anvilid.validate" -}}
{{- $multi := include "anvilid.multiNode" . -}}
{{- if and (eq .Values.database.type "sqlite") $multi -}}
{{- fail "database.type=sqlite is single-node: replicaCount > 1 and hpa.enabled need database.type=postgres (several pods cannot share one SQLite file)" -}}
{{- end -}}
{{- if eq .Values.database.type "postgres" -}}
{{- if not .Values.existingSecret.name -}}
{{- fail "database.type=postgres needs existingSecret.name: a Secret with the KEK (existingSecret.kekKey) and the database URL (existingSecret.databaseUrlKey)" -}}
{{- end -}}
{{- if or (not .Values.existingSecret.kekKey) (not .Values.existingSecret.databaseUrlKey) -}}
{{- fail "database.type=postgres needs existingSecret.kekKey and existingSecret.databaseUrlKey" -}}
{{- end -}}
{{- end -}}
{{- if and $multi (not (include "anvilid.hasRedis" .)) (not .Values.redis.acknowledgePerNodeLimits) -}}
{{- fail "replicaCount > 1 (or hpa.enabled) without redis.url: every pod would enforce the rate limits on its own, multiplying the budget by the number of pods. Set redis.url (or redis.existingSecretKey) for a shared limiter, or redis.acknowledgePerNodeLimits=true to accept per-node limits" -}}
{{- end -}}
{{- if le (int .Values.terminationGracePeriodSeconds) (int .Values.shutdownDrainSeconds) -}}
{{- fail "terminationGracePeriodSeconds must be larger than shutdownDrainSeconds (the pod would be killed during the drain)" -}}
{{- end -}}
{{- end }}
