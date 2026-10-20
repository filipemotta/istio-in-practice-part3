#!/usr/bin/env bash
# Plain-text inventory of a namespace, to run BEFORE switching it to STRICT.
# Asks Prometheus which callers reached the namespace's sidecars without
# mTLS in the time window: istio_requests_total reported by the destination
# proxy with connection_security_policy="none". The destination sidecar knows
# the caller's workload even without a certificate (Istio resolves the peer
# IP), but not its principal: plain text carries no identity.
# Exits 1 if there is any plain-text caller (a gate for CI or a runbook),
# 2 if the window holds no requests at all (no traffic is not proof of
# readiness), 0 only if every caller in the window used mutual TLS.
# Read-only (Prometheus through the API server service proxy), so it has no
# lab-only guard and can be pointed at any cluster with the samples/addons
# Prometheus: it always passes --context, defaulting to the lab's
# kind-istio-p3, never to your current kubectl context.
# Usage: mtls/plaintext-inventory.sh <namespace> [kube context] [window, default 1h] [destination workload]
set -euo pipefail

ns="${1:?usage: $0 <namespace> [kube context] [window] [destination workload]}"
ctx="${2:-kind-istio-p3}"
window="${3:-1h}"
workload="${4:-}"
prom_ns="${PROM_NAMESPACE:-istio-system}"
prom_svc="${PROM_SERVICE:-prometheus:9090}"

query() {
  local q
  q="$(jq -rn --arg q "$1" '$q | @uri')"
  kubectl --context "${ctx}" get --raw \
    "/api/v1/namespaces/${prom_ns}/services/${prom_svc}/proxy/api/v1/query?query=${q}"
}

q="sum by (source_workload_namespace, source_workload, source_principal, destination_workload, connection_security_policy) (increase(istio_requests_total{reporter=\"destination\", destination_workload_namespace=\"${ns}\"${workload:+, destination_workload=\"${workload}\"}}[${window}])) > 0"
rows="$(query "${q}" | jq -r '.data.result[]
  | [.metric.connection_security_policy, "\(.metric.source_workload_namespace)/\(.metric.source_workload)",
     .metric.destination_workload, .metric.source_principal, (.value[1] | tonumber | round | tostring)] | @tsv' | sort)"

echo "callers of ${ns}${workload:+/${workload}} in the last ${window} (reporter=destination):"
if [ -z "${rows}" ]; then
  echo "  no requests recorded in the window: nothing to judge (no traffic is not proof of readiness)"
  exit 2
fi
printf '%s\n' "${rows}" | awk -F'\t' '{ printf "  %-11s %-34s -> %-14s requests=%-6s principal=%s\n", $1, $2, $3, $5, $4 }'
plain="$(awk -F'\t' '$1 == "none"' <<< "${rows}" | wc -l | tr -d ' ')"
if [ "${plain}" -gt 0 ]; then
  echo "NOT READY for STRICT: ${plain} caller/destination pair(s) still send plain text"
  exit 1
fi
echo "ready for STRICT: every caller in the window used mutual TLS"
