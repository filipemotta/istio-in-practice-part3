#!/usr/bin/env bash
# Shared helpers sourced by the lab scripts. Not meant to be run directly.
# shellcheck shell=bash

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export REPO_ROOT
export PATH="${REPO_ROOT}/bin:${PATH}"

CLUSTER_NAME="istio-p3"
KUBE_CONTEXT="kind-${CLUSTER_NAME}"
ISTIO_VERSION="1.31.2"
GATEWAY_API_VERSION="v1.6.0"
OUT="${REPO_ROOT}/out"
mkdir -p "${OUT}"
export CLUSTER_NAME KUBE_CONTEXT ISTIO_VERSION GATEWAY_API_VERSION OUT

# Safety: the lab only ever talks to its own kind cluster. Every kubectl and
# istioctl call passes --context explicitly, so the current context of your
# kubeconfig is never used; on top of that, refuse to run if the lab context
# does not point at a kind cluster with the expected name.
assert_lab_context() {
  local cluster server
  # Resolve context -> cluster -> server: the cluster the context really uses.
  cluster="$(kubectl config view -o jsonpath="{.contexts[?(@.name==\"${KUBE_CONTEXT}\")].context.cluster}" 2>/dev/null || true)"
  server="$(kubectl config view -o jsonpath="{.clusters[?(@.name==\"${cluster}\")].cluster.server}" 2>/dev/null || true)"
  if [ -z "${cluster}" ] || [[ ! "${server}" =~ ^https://(127\.0\.0\.1|localhost):[0-9]+$ ]]; then
    echo "refusing to run: context ${KUBE_CONTEXT} is missing or does not point at a local kind API server (server='${server}')" >&2
    exit 3
  fi
}

k()    { kubectl --context "${KUBE_CONTEXT}" "$@"; }
ictl() { istioctl --context "${KUBE_CONTEXT}" "$@"; }

ensure_clis() { bash "${REPO_ROOT}/tools/install-cli.sh" >/dev/null; }

step() { printf '\n==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }

# --- assertions: failures are counted, the script exits non-zero at the end ---
PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '    [PASS] %s\n' "$1"; }
fail() { FAILED=$((FAILED + 1)); printf '    [FAIL] %s\n' "$1"; }

# expect_eq <description> <expected> <actual>
expect_eq() {
  if [ "$2" = "$3" ]; then pass "$1 (got $3)"; else fail "$1 (expected $2, got $3)"; fi
}
# expect_match <description> <extended regex> <actual>
expect_match() {
  if grep -Eq -- "$2" <<< "$3"; then pass "$1"; else fail "$1 (no match for /$2/ in: $3)"; fi
}
# expect_no_match <description> <extended regex> <actual>
expect_no_match() {
  if grep -Eq -- "$2" <<< "$3"; then fail "$1 (unexpected /$2/ in: $3)"; else pass "$1"; fi
}
# expect_between <description> <min> <max> <actual integer>
expect_between() {
  if [[ "$4" =~ ^-?[0-9]+$ ]] && [ "$4" -ge "$2" ] && [ "$4" -le "$3" ]; then
    pass "$1 (got $4, accepted range $2..$3)"
  else
    fail "$1 (got $4, accepted range $2..$3)"
  fi
}

finish() {
  printf '\n    result: %s passed, %s failed\n' "${PASSED}" "${FAILED}"
  [ "${FAILED}" -eq 0 ]
}

# --- requests from a pod of the lab ---
# req <ns> <deployment> <url> [extra curl args...] -> "<http code> <curl exit>"
# One request with curl from the "app" container of that deployment. The curl
# exit code matters as much as the HTTP code: a connection refused or reset by
# a proxy has no HTTP code at all ("000").
req() {
  local ns="$1" dep="$2" url="$3"; shift 3
  # shellcheck disable=SC2016 # runs in the pod shell
  k -n "${ns}" exec "deploy/${dep}" -c app -- sh -c '
    url="$1"; shift
    c="$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$@" "${url}")"; rc=$?
    echo "${c:-000} ${rc}"' sh "${url}" "$@" 2>/dev/null || echo "000 99"
}
# req_full <ns> <deployment> <url> [extra curl args...] -> curl's own output:
# the response body, or curl's error message on stderr (curl -sS).
req_full() {
  local ns="$1" dep="$2" url="$3"; shift 3
  k -n "${ns}" exec "deploy/${dep}" -c app -- curl -sS --max-time 10 "$@" "${url}" 2>&1 || true
}
# codes <ns> <deployment> <requests> <url> [extra curl args...] -> histogram,
# e.g. "200=10" or "403=10"; "000" counts requests without an HTTP answer.
codes() {
  local ns="$1" dep="$2" n="$3" url="$4"; shift 4
  # shellcheck disable=SC2016 # the loop runs in the pod shell
  k -n "${ns}" exec "deploy/${dep}" -c app -- sh -c '
    n="$1"; url="$2"; shift 2; i=0
    while [ "$i" -lt "$n" ]; do
      curl -s -o /dev/null -w "%{http_code}\n" --max-time 10 "$@" "${url}"
      i=$((i + 1))
    done' sh "${n}" "${url}" "$@" | sort | uniq -c | awk '{ printf "%s%s=%s", (NR > 1 ? " " : ""), $2, $1 }'
}
# field <name> <"200=.. 403=.."> -> the number for that name (0 if absent)
field() {
  local v
  v="$(tr ' ' '\n' <<< "$2" | sed -n "s/^$1=//p")"
  printf '%s' "${v:-0}"
}

# run_id -> a unique token, used in request paths so that the requests of one
# test can be found in access logs and in the fortio request log.
run_id() { printf 'r%s%04d' "$(date +%s)" "$((RANDOM % 10000))"; }

# reached <ns> <app label> <run id> -> how many requests carrying that token
# reached the application container of those pods (fortio logs one JSON line
# per request with -loglevel Verbose). A request denied by a proxy never
# reaches the application, so this counts the requests that got through.
# fortio_log <ns> <app label> <run id> -> those JSON log lines (they include
# the request headers, e.g. header.x-forwarded-client-cert)
reached() {
  local ns="$1" app="$2" id="$3" total=0 n p
  sleep "${4:-1}"
  for p in $(k -n "${ns}" get pod -l "app=${app}" -o jsonpath='{.items[*].metadata.name}'); do
    n="$(k -n "${ns}" logs "${p}" -c fortio --since=10m 2>/dev/null | grep -F '"msg":"Echo"' | grep -cF "${id}" || true)"
    total=$((total + n))
  done
  printf '%s' "${total}"
}
fortio_log() {
  local p
  for p in $(k -n "$1" get pod -l "app=$2" -o jsonpath='{.items[*].metadata.name}'); do
    k -n "$1" logs "${p}" -c fortio --since=10m 2>/dev/null | grep -F '"msg":"Echo"' | grep -F "$3" || true
  done
}

# proxy_log <ns> <pod selector> <run id> [container] -> the access log lines of
# the proxies of those pods (istio-proxy for sidecars) that carry the run id
proxy_log() {
  local ns="$1" sel="$2" id="$3" ctr="${4:-istio-proxy}" p
  sleep 2
  for p in $(k -n "${ns}" get pod -l "${sel}" -o jsonpath='{.items[*].metadata.name}'); do
    k -n "${ns}" logs "${p}" -c "${ctr}" --since=10m 2>/dev/null | grep -F "/${id}" || true
  done
}

# reset_security <ns...>: remove every security and traffic policy of those
# namespaces, so each step starts from "no policy at all" (PERMISSIVE, allow all).
reset_security() {
  local ns
  for ns in "$@"; do
    k -n "${ns}" delete peerauthentication,authorizationpolicy,requestauthentication,destinationrule,serviceentry \
      --all --ignore-not-found >/dev/null
  done
}

# apply_file <file>: apply and print the file path, for the log.
apply_file() {
  note "kubectl apply -f ${1#"${REPO_ROOT}"/}"
  k apply -f "$1" >/dev/null
}

# wait_for <seconds> <expected> <command...>: re-runs the command every 2s until
# its output equals <expected>. Returns 1 on timeout (callers then assert).
wait_for() {
  local deadline=$((SECONDS + $1)) expected="$2"; shift 2
  until [ "$("$@" 2>/dev/null)" = "${expected}" ]; do
    [ "${SECONDS}" -lt "${deadline}" ] || return 1
    sleep 2
  done
}
# wait_json <seconds> <jq filter that must output true> <command...>:
# re-runs the command every 2s until the filter holds.
wait_json() {
  local deadline=$((SECONDS + $1)) filter="$2"; shift 2
  until [ "$("$@" 2>/dev/null | jq -r "${filter}" 2>/dev/null)" = "true" ]; do
    [ "${SECONDS}" -lt "${deadline}" ] || { note "timeout waiting for: ${filter}"; return 1; }
    sleep 2
  done
}

# --- observability backends, read through the API server service proxy ---
# (no port-forward needed; the same data the dashboards show)
svc_get() { # <namespace> <service:port> <path?query>
  k get --raw "/api/v1/namespaces/$1/services/$2/proxy$3"
}
# prom <PromQL> -> the raw JSON answer of the Prometheus instant query API
prom() {
  local q
  q="$(jq -rn --arg q "$1" '$q | @uri')"
  svc_get istio-system prometheus:9090 "/api/v1/query?query=${q}"
}
# prom_value <PromQL> -> the first sample value rounded to an integer ("0" if empty)
prom_value() {
  prom "$1" | jq -r '[.data.result[0].value[1] // "0" | tonumber] | .[0] | round'
}

# --- alert rules (observability/alerts.yaml) in the addon Prometheus ---
# The samples/addons Prometheus reads /etc/config/alerting_rules.yml from its
# "prometheus" ConfigMap; its config-reloader sidecar reloads Prometheus when
# the kubelet updates the mounted file (up to a minute or two).
ALERT_GROUP="istio-security"
load_alert_rules() {
  local patch
  patch="$(jq -n --rawfile r "${REPO_ROOT}/observability/alerts.yaml" '{data: {"alerting_rules.yml": $r}}')"
  k -n istio-system patch configmap prometheus --type merge -p "${patch}" >/dev/null
}
# alert_rule_names -> the alert names of observability/alerts.yaml, comma-separated
alert_rule_names() { sed -n 's/^  - alert: //p' "${REPO_ROOT}/observability/alerts.yaml" | paste -sd, -; }
# loaded_alert_rules -> the alert names Prometheus has loaded for the group, comma-separated
loaded_alert_rules() {
  svc_get istio-system prometheus:9090 '/api/v1/rules?type=alert' \
    | jq -r --arg g "${ALERT_GROUP}" '[.data.groups[] | select(.name == $g) | .rules[].name] | join(",")'
}
# alert_state <alertname> <label>=<value>... -> "firing", "pending" or
# "inactive" for the alerts with those labels (Prometheus /api/v1/alerts)
alert_state() {
  local name="$1" sel
  shift
  sel="$(printf '%s\n' "$@" | jq -R 'split("=") | {(.[0]): (.[1:] | join("="))}' | jq -s 'add // {}')"
  svc_get istio-system prometheus:9090 '/api/v1/alerts' \
    | jq -r --arg a "${name}" --argjson sel "${sel}" '[.data.alerts[]
        | select(.labels.alertname == $a)
        | select(.labels as $l | $sel | to_entries | all($l[.key] == .value))
        | .state] | if any(.[]; . == "firing") then "firing" elif length > 0 then .[0] else "inactive" end'
}
# wait_alert <seconds> <alertname> <label>=<value>...: wait until the alert is
# pending or firing; prints the state reached
wait_alert() {
  local deadline=$((SECONDS + $1)) st; shift
  while :; do
    st="$(alert_state "$@")"
    [ "${st}" = "inactive" ] || break
    [ "${SECONDS}" -lt "${deadline}" ] || break
    sleep 10
  done
  printf '%s' "${st}"
}

# --- policy propagation ---
# istiod pushes a new policy to each proxy within seconds, not at once (the
# lab measured 5 to 20 seconds, replica by replica). Asserting before the
# push proves nothing, so every scenario waits until the proxies that enforce
# the policy have it in their listener config.
# policy_pods <ns> <app label> <policy name> -> how many pods of that app have
# the policy in their listeners (sidecar mode)
policy_pods() {
  local ns="$1" app="$2" name="$3" total=0 p cfg
  for p in $(k -n "${ns}" get pod -l "app=${app}" --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}'); do
    # capture first: grep -q would close the pipe early and, under pipefail,
    # turn a match into a failure
    cfg="$(ictl proxy-config listener "${p}.${ns}" -o json 2>/dev/null || true)"
    if grep -qF "ns[${ns}]-policy[${name}]-" <<< "${cfg}"; then
      total=$((total + 1))
    fi
  done
  printf '%s' "${total}"
}
# app_pods <ns> <app label> -> number of running pods of that app
app_pods() { k -n "$1" get pod -l "app=$2" --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l | tr -d ' '; }
# wait_policy <ns> <app label> <policy name> [absent]: wait (90s) until every
# pod of the app has the policy (or, with "absent", none has it any more).
wait_policy() {
  local want
  if [ "${4:-}" = "absent" ]; then want=0; else want="$(app_pods "$1" "$2")"; fi
  wait_for 90 "${want}" policy_pods "$1" "$2" "$3" || note "timeout waiting for policy $3 on app=$2 (${4:-present})"
}
# draining <ns> <app label> -> sum over the app's pods of the Envoy gauge
# listener_manager.total_filter_chains_draining. After a policy push the
# filter chains it replaced keep serving the connections opened before it,
# until Envoy closes them at the end of its drain time (45s in Istio 1.31).
draining() {
  local total=0 v p
  for p in $(k -n "$1" get pod -l "app=$2" --field-selector=status.phase=Running -o name); do
    v="$(k -n "$1" exec "${p}" -c istio-proxy -- pilot-agent request GET stats 2>/dev/null \
      | awk -F': ' '$1 == "listener_manager.total_filter_chains_draining" { print $2 }')"
    total=$((total + ${v:-0}))
  done
  printf '%s' "${total}"
}
# push_wait <ns> <app label> <policy name> [absent]: wait until every pod of
# the app has the policy (or no longer has it) AND no old filter chain is
# still draining there, so every request from now on meets the new policy.
push_wait() {
  wait_policy "$@"
  wait_for 120 "0" draining "$1" "$2" || note "app=$2 still draining old filter chains after 120s"
}

# settle <seconds> <expected histogram> <ns> <deployment> <requests> <url> [curl args...]:
# repeat the batch of requests until its histogram is the expected one twice
# in a row. A proxy that already has the new listener keeps serving
# connections opened before the change with the old filter chain until they
# drain (Envoy drain_time 45s in Istio 1.31), so requests right after a push
# can still see the previous policy, one pooled connection at a time.
settle() {
  local deadline=$((SECONDS + $1)) want="$2" ok=0; shift 2
  while [ "${ok}" -lt 2 ]; do
    if [ "$(codes "$@")" = "${want}" ]; then ok=$((ok + 1)); else ok=0; fi
    [ "${ok}" -lt 2 ] || break
    [ "${SECONDS}" -lt "${deadline}" ] || { note "not settled on ${want} after the timeout"; return 1; }
    sleep 3
  done
}
