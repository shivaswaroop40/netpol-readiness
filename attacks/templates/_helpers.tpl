{{/* Common labels applied to every object the chart creates. */}}
{{- define "npready.labels" -}}
app.kubernetes.io/name: npready-attacks
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
npready.dev/component: attack-probe
{{- end -}}

{{/* Build the whitespace-separated target list for one family.
     TCP  -> "host:port host:port"
     HTTP -> "url url"
     This value is passed to the container as an ENV VAR (literal string, never
     shell-parsed), so no value can inject shell commands. */}}
{{- define "npready.targets" -}}
{{- $f := .fam -}}
{{- range $i, $t := $f.targets -}}
{{- if $i }} {{ end -}}
{{- if eq $f.kind "http" }}{{ $t.url }}{{ else }}{{ $t.host }}:{{ $t.port }}{{ end -}}
{{- end -}}
{{- end -}}

{{/* The probe script is STATIC — it interpolates NO chart values. Every input
     (family id, kind, timeout, and the target list) arrives via env vars, which
     Kubernetes delivers as literal strings. The script always quotes them, so a
     hostile value is treated as an unresolvable hostname/URL, never as code.
     A leading-dash guard additionally prevents nc/wget flag injection. */}}
{{- define "npready.probeScript" -}}
set -u
echo "=== npready probe family=$FAM_ID technique=$FAM_TECH expect=$FAM_EXPECT ==="
any_open=1
for t in $TARGETS; do
  case "$t" in
    -*) echo "RESULT $FAM_ID $t SKIPPED (refusing leading-dash target)"; continue ;;
  esac
  if [ "$FAM_KIND" = "http" ]; then
    if wget -T "$TIMEOUT" -q -O /dev/null -- "$t" 2>/dev/null; then
      echo "RESULT $FAM_ID $t OPEN (reachable)"; any_open=0
    else
      echo "RESULT $FAM_ID $t BLOCKED (denied or unreachable)"
    fi
  else
    host="${t%:*}"; port="${t##*:}"
    if nc -z -w "$TIMEOUT" "$host" "$port" 2>/dev/null; then
      echo "RESULT $FAM_ID $host:$port OPEN (reachable)"; any_open=0
    else
      echo "RESULT $FAM_ID $host:$port BLOCKED (denied or unreachable)"
    fi
  fi
done
echo "=== npready probe done family=$FAM_ID any_open=$any_open ==="
# Exit 0 always: a probe reporting BLOCKED is a *successful* run, not a failure.
exit 0
{{- end -}}
