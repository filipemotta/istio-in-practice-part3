#!/usr/bin/env bash
# Step 4: authorization in the payments namespace (sidecar mode, STRICT).
#   1. deny by default: authz/00-allow-nothing.yaml (spec: {});
#   2. open each path by name: who (principal) may call what (method, path);
#   3. an explicit DENY wins over every ALLOW;
#   4. allow-nothing vs an ALLOW with an empty rule (silent error), and the
#      real deny-all;
#   5. principals that never match (silent errors) and notPrincipals;
#   6. AUDIT and the istio.io/dry-run annotation, and how to observe them.
# Leaves payments in STRICT + deny by default + the allow/deny policies.
set -euo pipefail
# shellcheck source=/dev/null
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
assert_lab_context

NS="payments"
FC="http://fraud-check:8080"
RS="http://risk-score:8080"
N=5
reset_security "${NS}"
apply_file "${REPO_ROOT}/mtls/peer-authentication-strict.yaml"
# Whatever a previous run left is gone: let the proxies drop it, then drain.
sleep 10
for a in payments-api fraud-check risk-score; do wait_for 120 "0" draining "${NS}" "${a}" || true; done

# api <n> <url> [curl args] -> histogram of n requests from payments-api
api() { local n="$1"; shift; codes "${NS}" payments-api "${n}" "$@"; }
# check <description> <expected histogram> <url> [curl args]: settle on the
# expected answer (the push reaches each proxy at its own time), then assert
# on a fresh batch of N requests.
check() {
  local desc="$1" want="$2"; shift 2
  settle 90 "${want}" "${NS}" payments-api "${N}" "$@" || true
  expect_eq "${desc}" "${want}" "$(api "${N}" "$@")"
}
ready_pods() { k -n "${NS}" get pod -o json | jq '[.items[] | select(any(.status.conditions[]; .type == "Ready" and .status == "True"))] | length'; }
# rbac_stat <app> <stat suffix> -> sum over the pods of the app, port 8080 listener
rbac_stat() {
  local total=0 v p
  for p in $(k -n "${NS}" get pod -l "app=$1" -o name); do
    v="$(k -n "${NS}" exec "${p}" -c istio-proxy -- pilot-agent request GET stats 2>/dev/null \
      | awk -v n="http.inbound_0.0.0.0_8080;.rbac.$2" -F': ' '$1 == n { print $2 }')"
    total=$((total + ${v:-0}))
  done
  printf '%s' "${total}"
}
# fc_proxy_logs <since RFC3339> -> istio-proxy logs of every fraud-check pod since then
fc_proxy_logs() {
  local q
  for q in $(k -n "${NS}" get pod -l app=fraud-check -o name); do k -n "${NS}" logs "${q}" -c istio-proxy --since-time="$1" 2>/dev/null; done
}
# rbac_log_count <fixed string> <since> -> matching rbac debug lines of fraud-check's proxies
rbac_log_count() { fc_proxy_logs "$2" | grep -cF "$1" || true; }
# rbac_log_level <app> <level>: Envoy log level of the rbac logger on every pod of the app
rbac_log_level() {
  local p
  for p in $(k -n "${NS}" get pod -l "app=$1" -o jsonpath='{.items[*].metadata.name}'); do
    ictl proxy-config log "${p}.${NS}" --level "rbac:$2" >/dev/null
  done
}

step "Before any AuthorizationPolicy: every caller in the mesh is allowed"
check "payments-api -> risk-score directly (nobody meant this path)" "200=${N}" "${RS}/v1/score/1"

step "Deny by default: authz/00-allow-nothing.yaml (spec: {})"
apply_file "${REPO_ROOT}/authz/00-allow-nothing.yaml"
for a in payments-api fraud-check risk-score; do push_wait "${NS}" "${a}" allow-nothing; done
check "payments-api -> fraud-check" "403=${N}" "${FC}/v1/check/1"
check "payments-api -> risk-score" "403=${N}" "${RS}/v1/score/1"
body="$(req_full "${NS}" payments-api "${FC}/v1/check/1")"
expect_eq "response body" "RBAC: access denied" "${body}"
id="$(run_id)"; api 1 "${FC}/v1/check/${id}" >/dev/null
log="$(proxy_log "${NS}" app=fraud-check "${id}" | tail -1)"; note "fraud-check sidecar: ${log:0:200}"
expect_match "access log: 403, no response flag, details rbac_access_denied_matched_policy[none]" \
  '" 403 - rbac_access_denied_matched_policy\[none\] ' "${log}"
expect_eq "the request never reached the fraud-check container" "0" "$(reached "${NS}" fraud-check "${id}")"
sleep 25
expect_eq "probes are not requests through the inbound listener: every pod still Ready" \
  "$(k -n "${NS}" get pod --no-headers | wc -l | tr -d ' ')" "$(ready_pods)"

step "Open the paths by name: authz/10, 11, 12 (principal + method + path)"
for f in 10-fraud-check-allow 11-risk-score-allow 12-payments-api-allow-ingress; do apply_file "${REPO_ROOT}/authz/${f}.yaml"; done
push_wait "${NS}" fraud-check fraud-check-allow
push_wait "${NS}" risk-score risk-score-allow
push_wait "${NS}" payments-api payments-api-allow-ingress
check "payments-api GET /v1/check/1 -> fraud-check (allowed)" "200=${N}" "${FC}/v1/check/1"
check "payments-api POST /v1/check -> fraud-check (allowed)" "200=${N}" "${FC}/v1/check" -X POST -d '{}'
check "payments-api DELETE /v1/check/1 (method not listed)" "403=${N}" "${FC}/v1/check/1" -X DELETE
check "payments-api GET /admin (path not listed)" "403=${N}" "${FC}/admin"
check "payments-api -> fraud-check:8090 -> risk-score (both hops allowed)" "200=${N}" "http://fraud-check:8090/v1/score/1"
id="$(run_id)"; api "${N}" "http://fraud-check:8090/v1/score/${id}" >/dev/null
expect_eq "risk-score served ${N} requests carrying a fresh id, called by fraud-check" "${N}" "$(reached "${NS}" risk-score "${id}")"
check "payments-api -> risk-score directly (not listed)" "403=${N}" "${RS}/v1/score/1"
c="$(codes legacy settlement-batch "${N}" "http://fraud-check.${NS}:8080/v1/check/1")"
expect_eq "legacy -> fraud-check: no identity, reset by STRICT before any policy runs" "000=${N}" "${c}"

step "DENY wins over ALLOW: authz/20-fraud-check-deny-export.yaml"
out="$(yq 'del(.spec.rules[0].to[0].operation.ports)' "${REPO_ROOT}/authz/20-fraud-check-deny-export.yaml" | k apply --dry-run=server -f - 2>&1)"
note "the same DENY without ports, server dry run: ${out}"
expect_match "istiod warns: an HTTP-only DENY rule also denies all TCP traffic in its scope" \
  'will deny all traffic to TCP ports under its scope due to the use of only HTTP attributes in a DENY rule' "${out}"
apply_file "${REPO_ROOT}/authz/20-fraud-check-deny-export.yaml"
push_wait "${NS}" fraud-check fraud-check-deny-export
check "GET /v1/check/export matches fraud-check-allow (/v1/check/*) and the DENY: denied" "403=${N}" "${FC}/v1/check/export"
id="$(run_id)"; api 1 "${FC}/v1/check/export/${id}" >/dev/null
log="$(proxy_log "${NS}" app=fraud-check "${id}" | tail -1)"; note "fraud-check sidecar: ${log:0:220}"
expect_match "access log names the DENY policy" 'rbac_access_denied_matched_policy\[ns\[payments\]-policy\[fraud-check-deny-export\]-rule\[0\]\]' "${log}"
check "GET /v1/check/1 still allowed" "200=${N}" "${FC}/v1/check/1"

step "Silent error: silent-errors/03-ap-allow-empty-rule.yaml (an ALLOW named deny-all, rules: [{}])"
apply_file "${REPO_ROOT}/silent-errors/03-ap-allow-empty-rule.yaml"
for a in fraud-check risk-score; do push_wait "${NS}" "${a}" deny-all; done
check "payments-api -> risk-score directly: allowed now" "200=${N}" "${RS}/v1/score/1"
check "GET /admin on fraud-check: allowed now" "200=${N}" "${FC}/admin"
check "the explicit DENY still holds (/v1/check/export)" "403=${N}" "${FC}/v1/check/export"
k -n "${NS}" delete authorizationpolicy deny-all >/dev/null
for a in fraud-check risk-score; do push_wait "${NS}" "${a}" deny-all absent; done
check "removed: payments-api -> risk-score denied again" "403=${N}" "${RS}/v1/score/1"

step "The real deny-all: authz/90-deny-all-emergency.yaml (action DENY, rules: [{}])"
apply_file "${REPO_ROOT}/authz/90-deny-all-emergency.yaml"
push_wait "${NS}" fraud-check deny-all
check "even the allowed path is refused" "403=${N}" "${FC}/v1/check/1"
id="$(run_id)"; api 1 "${FC}/v1/check/${id}" >/dev/null
expect_match "matched policy: deny-all" 'rbac_access_denied_matched_policy\[ns\[payments\]-policy\[deny-all\]-rule\[0\]\]' \
  "$(proxy_log "${NS}" app=fraud-check "${id}" | tail -1)"
k -n "${NS}" delete authorizationpolicy deny-all >/dev/null
push_wait "${NS}" fraud-check deny-all absent
check "removed: the allowed path works again" "200=${N}" "${FC}/v1/check/1"

step "Silent errors: principals that never match"
for f in 04-ap-principal-without-trust-domain 05-ap-principal-wrong-namespace; do
  apply_file "${REPO_ROOT}/silent-errors/${f}.yaml"
  push_wait "${NS}" risk-score risk-score-allow-payments-api
  pn="$(ictl proxy-config listener "$(k -n "${NS}" get pod -l app=risk-score -o jsonpath='{.items[0].metadata.name}').${NS}" -o json \
    | jq -r '[.. | objects | select(has("policies")) | .policies | to_entries[] | select(.key | contains("risk-score-allow-payments-api"))
             | .value.principals[] | .. | objects | select(has("principalName")) | .principalName.exact] | first')"
  note "${f}: Envoy matches the peer certificate URI exactly against ${pn}"
  expect_eq "${f}: accepted, and payments-api -> risk-score stays denied" "403=${N}" "$(api "${N}" "${RS}/v1/score/1")"
  k -n "${NS}" delete authorizationpolicy risk-score-allow-payments-api >/dev/null
  push_wait "${NS}" risk-score risk-score-allow-payments-api absent
done
expect_eq "for reference, the identity payments-api presents" "spiffe://cluster.local/ns/payments/sa/payments-api" \
  "$(prom 'sum by (source_principal) (istio_requests_total{reporter="destination", source_workload="payments-api", destination_workload="risk-score"})' | jq -r '.data.result[0].metric.source_principal')"

step "Silent error: silent-errors/06-ap-deny-not-principals.yaml (DENY with notPrincipals)"
apply_file "${REPO_ROOT}/silent-errors/06-ap-deny-not-principals.yaml"
push_wait "${NS}" risk-score deny-legacy
check "fraud-check -> risk-score, the path that was meant to keep working: denied" "403=${N}" "http://fraud-check:8090/v1/score/1"
id="$(run_id)"; api 1 "http://fraud-check:8090/v1/score/${id}" >/dev/null
expect_match "risk-score's sidecar: matched policy deny-legacy" 'rbac_access_denied_matched_policy\[ns\[payments\]-policy\[deny-legacy\]-rule\[0\]\]' \
  "$(proxy_log "${NS}" app=risk-score "${id}" | tail -1)"
k -n "${NS}" delete authorizationpolicy deny-legacy >/dev/null
push_wait "${NS}" risk-score deny-legacy absent
check "removed: fraud-check -> risk-score works again" "200=${N}" "http://fraud-check:8090/v1/score/1"

step "AUDIT: authz/30-fraud-check-audit.yaml (action AUDIT on POST)"
apply_file "${REPO_ROOT}/authz/30-fraud-check-audit.yaml"
push_wait "${NS}" fraud-check fraud-check-audit-writes
p="$(k -n "${NS}" get pod -l app=fraud-check -o jsonpath='{.items[0].metadata.name}')"
expect_eq "Istio programs it as an Envoy RBAC filter with action LOG" "LOG" \
  "$(ictl proxy-config listener "${p}.${NS}" -o json | jq -r '[.. | objects | select(.name? == "envoy.filters.http.rbac") | .typedConfig.rules | select(.policies["ns[payments]-policy[fraud-check-audit-writes]-rule[0]"] != null) | .action] | first')"
rbac_log_level fraud-check debug
mark="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; sleep 1
c="$(api "${N}" "${FC}/v1/check" -X POST -d '{}')"
expect_eq "AUDIT changes no decision: POST /v1/check still 200" "200=${N}" "${c}"
expect_eq "and DELETE still 403" "403=${N}" "$(api "${N}" "${FC}/v1/check/1" -X DELETE)"
# Envoy writes its debug log asynchronously: give the lines a moment to land.
wait_for 20 "${N}" rbac_log_count 'enforced allowed, matched policy ns[payments]-policy[fraud-check-audit-writes]-rule[0]' "${mark}" || true
expect_eq "rbac debug log: the LOG filter matched each POST (${N})" "${N}" \
  "$(rbac_log_count 'enforced allowed, matched policy ns[payments]-policy[fraud-check-audit-writes]-rule[0]' "${mark}")"
hint="$(fc_proxy_logs "${mark}" | grep -A2 'key: "access_log_hint"' | grep -c 'bool_value: true' || true)"
# The rbac debug log dumps the request's dynamic metadata at each RBAC filter
# that runs after the mark is set, so a request can show it more than once.
expect_between "and set the dynamic metadata envoy.common access_log_hint=true, the mark an audit plugin would read (none is installed)" \
  "${N}" "$((N * 3))" "${hint}"
k -n "${NS}" delete authorizationpolicy fraud-check-audit-writes >/dev/null
push_wait "${NS}" fraud-check fraud-check-audit-writes absent

step "Dry run: authz/40-fraud-check-deny-post-dry-run.yaml (DENY POST /v1/check, istio.io/dry-run: \"true\")"
apply_file "${REPO_ROOT}/authz/40-fraud-check-deny-post-dry-run.yaml"
push_wait "${NS}" fraud-check fraud-check-deny-post
# Let Prometheus scrape the shadow counter at its starting value first: a
# series first seen with its increments already in it shows no rate().
sleep 20
before="$(rbac_stat fraud-check istio_dry_run_deny_.shadow_denied)"
mark="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; sleep 1
c="$(api 10 "${FC}/v1/check" -X POST -d '{}')"; note "POST /v1/check x10 -> ${c}"
expect_eq "not enforced: all 10 POSTs answered 200" "200=10" "${c}"
after="$(rbac_stat fraud-check istio_dry_run_deny_.shadow_denied)"
expect_eq "Envoy stat rbac.istio_dry_run_deny_.shadow_denied counted the 10 requests it would deny" "10" "$((after - before))"
wait_for 20 "10" rbac_log_count 'shadow denied, matched policy ns[payments]-policy[fraud-check-deny-post]-rule[0]' "${mark}" || true
expect_eq "rbac debug log: 'shadow denied, matched policy ns[payments]-policy[fraud-check-deny-post]-rule[0]' x10" "10" \
  "$(rbac_log_count 'shadow denied, matched policy ns[payments]-policy[fraud-check-deny-post]-rule[0]' "${mark}")"
rbac_log_level fraud-check warning
q='sum(envoy_http_rbac{namespace="payments", app="fraud-check", authz_dry_run_action="deny", authz_dry_run_result="denied"})'
wait_for 90 "true" eval "[ \"\$(prom_value '${q}')\" -ge 10 ] && echo true" || true
note "Prometheus: ${q} = $(prom_value "${q}")"
expect_between "the same counter in Prometheus (envoy_http_rbac, labels authz_dry_run_action/result)" 10 100000 "$(prom_value "${q}")"
started=${SECONDS}; deadline=$((SECONDS + 240)); st=inactive
while [ "${SECONDS}" -lt "${deadline}" ]; do
  api 2 "${FC}/v1/check" -X POST -d '{}' >/dev/null
  st="$(alert_state IstioAuthzDryRunWouldDeny namespace=payments app=fraud-check)"
  [ "${st}" = "inactive" ] || break
  sleep 10
done
note "after $((SECONDS - started))s: IstioAuthzDryRunWouldDeny=${st}"
expect_match "alert IstioAuthzDryRunWouldDeny pending or firing" '^(pending|firing)$' "${st}"
k -n "${NS}" annotate --overwrite authorizationpolicy fraud-check-deny-post istio.io/dry-run=false >/dev/null
note "kubectl annotate --overwrite authorizationpolicy fraud-check-deny-post istio.io/dry-run=false"
# enforced_pods -> fraud-check pods whose RBAC filters hold the policy as an
# enforced rule (not a shadow rule)
enforced_pods() {
  local n=0 q
  for q in $(k -n "${NS}" get pod -l app=fraud-check -o jsonpath='{.items[*].metadata.name}'); do
    if [ "$(ictl proxy-config listener "${q}.${NS}" -o json 2>/dev/null | jq '[.. | objects | select(.name? == "envoy.filters.http.rbac") | (.typedConfig.rules.policies // {}) | keys[]] | any(. == "ns[payments]-policy[fraud-check-deny-post]-rule[0]")')" = "true" ]; then
      n=$((n + 1))
    fi
  done
  printf '%s' "${n}"
}
wait_for 90 "$(app_pods "${NS}" fraud-check)" enforced_pods || true
wait_for 120 "0" draining "${NS}" fraud-check || true
expect_eq "the policy moved from the shadow rules to the enforced rules on every fraud-check pod" "$(app_pods "${NS}" fraud-check)" "$(enforced_pods)"
check "enforced: POST /v1/check now 403" "403=${N}" "${FC}/v1/check" -X POST -d '{}'
check "GET /v1/check/1 unaffected" "200=${N}" "${FC}/v1/check/1"

step "GHSA-w44g-8m76-8gc5: the DENY method rule against a lowercase method over HTTP/2"
# Before Istio 1.31.2 a DENY rule with methods compiled to a case-sensitive
# :method matcher, so "post" over HTTP/2 slipped past it. HTTP/1.1 was never
# affected: Envoy's HTTP/1 codec rejects a non-uppercase method first.
expect_eq "the DENY rule matches :method case-insensitively" '{"exact":"POST","ignoreCase":true}' \
  "$(ictl proxy-config listener "${p}.${NS}" -o json | jq -c '[.. | objects | select(.name? == "envoy.filters.http.rbac") | .typedConfig.rules.policies["ns[payments]-policy[fraud-check-deny-post]-rule[0]"] // empty | .permissions[] | .. | objects | select(.header?.name == ":method") | .header.stringMatch] | first')"
H2=(--http2-prior-knowledge -X post -d '{}')
mark="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; sleep 1
c="$(api "${N}" "${FC}/v1/check" "${H2[@]}")"; note "post over HTTP/2, default HTTP/1.1 hop between the sidecars -> ${c}"
expect_eq "refused before authorization: the hop to fraud-check is HTTP/1.1 and its codec rejects \"post\" (400)" "400=${N}" "${c}"
sleep 2
expect_between "fraud-check's sidecar logged 400 DPE http1.codec_error for them" "${N}" "$((N * 2))" \
  "$(fc_proxy_logs "${mark}" | grep -c '" 400 DPE http1.codec_error ' || true)"
apply_file "${REPO_ROOT}/authz/41-fraud-check-keep-client-protocol.yaml"
wait_json 90 '. == true' eval "ictl proxy-config cluster deploy/payments-api -n ${NS} --fqdn fraud-check.${NS}.svc.cluster.local --port 8080 -o json | jq '[.. | objects | select(has(\"useDownstreamProtocolConfig\"))] | length > 0'" || true
check "useClientProtocol: \"post\" over HTTP/2 now reaches fraud-check's sidecar, and the DENY refuses it" "403=${N}" "${FC}/v1/check" "${H2[@]}"
id="$(run_id)"; api 1 "${FC}/v1/check?id=${id}" "${H2[@]}" >/dev/null
sleep 2
log="$(fc_proxy_logs "${mark}" | grep -F "${id}" | tail -1 || true)"; note "fraud-check sidecar: ${log:0:230}"
expect_match "fraud-check's sidecar saw \"post\" over HTTP/2 and matched the DENY policy" \
  '"post /v1/check\?id=r[0-9]+ HTTP/2" 403 - rbac_access_denied_matched_policy\[ns\[payments\]-policy\[fraud-check-deny-post\]-rule\[0\]\]' "${log}"
expect_eq "none of them reached the fraud-check container" "0" "$(reached "${NS}" fraud-check "${id}")"
check "GET over HTTP/2 on the same path unaffected" "200=${N}" "${FC}/v1/check/1" --http2-prior-knowledge
k -n "${NS}" delete destinationrule fraud-check-keep-client-protocol >/dev/null
k -n "${NS}" delete authorizationpolicy fraud-check-deny-post >/dev/null
push_wait "${NS}" fraud-check fraud-check-deny-post absent

step "Alert IstioAuthorizationDenied (sustained denials on fraud-check)"
st="$(wait_alert 240 IstioAuthorizationDenied namespace=payments app=fraud-check)"
note "IstioAuthorizationDenied=${st}"
expect_match "pending or firing for payments/fraud-check" '^(pending|firing)$' "${st}"

step "End state"
expect_eq "AuthorizationPolicies left in payments" "allow-nothing,fraud-check-allow,fraud-check-deny-export,payments-api-allow-ingress,risk-score-allow" \
  "$(k -n "${NS}" get authorizationpolicy -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | sort | paste -sd, -)"
finish
