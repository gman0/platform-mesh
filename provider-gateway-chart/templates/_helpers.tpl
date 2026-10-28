{{- define "provider-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "provider-gateway.labels" -}}
app.kubernetes.io/name: {{ include "provider-gateway.name" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "provider-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "provider-gateway.name" . }}
{{- end -}}

{{/* The operator proxy's Service. */}}
{{- define "provider-gateway.proxyServiceName" -}}
{{- printf "%s-operator-proxy" (include "provider-gateway.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
The operator proxy Service's DNS names, as a list. The first is the kubeconfigs'
tls-server-name and proxy host; the serving certificate covers them all.
*/}}
{{- define "provider-gateway.names" -}}
{{- $svc := include "provider-gateway.proxyServiceName" . -}}
{{- $ns := .Release.Namespace -}}
{{- list (printf "%s.%s.svc" $svc $ns) (printf "%s.%s.svc.cluster.local" $svc $ns) (printf "%s.%s" $svc $ns) $svc | toJson -}}
{{- end -}}

{{/* The kubeconfig Secrets' namespace. */}}
{{- define "provider-gateway.kubeconfigNamespace" -}}
{{- default (printf "%s-kubeconfigs" .Release.Namespace) .Values.kubeconfigSecrets.namespace | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* The serving certificate's Secret, with cert-manager. */}}
{{- define "provider-gateway.servingSecretName" -}}
{{- printf "%s-serving" (include "provider-gateway.name" .) -}}
{{- end -}}
