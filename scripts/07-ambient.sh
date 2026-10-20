#!/usr/bin/env bash
# Step 7: authorization in ambient mode (payments-ambient).
#   1. ztunnel alone enforces L4 policy (principals) with a workload selector;
#   2. an L7 rule (methods, paths) enforced by ztunnel fails safe: the
#      allowed caller is cut off too (silent-errors/07);
#   3. with the waypoint in the path, the same L7 rule attached with
#      targetRefs works (ambient/20);
#   4. traffic that skips the waypoint skips its policy, and an L4 policy
#      naming the original caller breaks once the waypoint is in the path:
#      ztunnel sees the waypoint's identity (ambient/10 then ambient/30).
# The other caller is risk-score, through "fortio curl" (its image has no
# shell or curl): it prints the status, or "Error status -1" on a reset.
set -euo pipefail
# shellcheck source=/dev/null
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
assert_lab_context

NS="payments-ambient"
FC="http://fraud-check:8080"
N=5

reset_security "${NS}"
k label ns "${NS}" istio.io/use-waypoint- >/dev/null 2>&1 || true

# fc_waypoint -> the waypoint ztunnel uses for fraud-check ("None" without one)
fc_waypoint() { ictl ztunnel-config service --service-namespace "${NS}" | awk '$2 == "fraud-check" { print $4 }'; }
# zt_policy <name> -> that policy as the ztunnels hold it (compact JSON, "" if absent)
zt_policy() { ictl ztunnel-config policy -o json 2>/dev/null | jq -c --arg n "$1" --arg ns "${NS}" '[.[] | select(.name == $n and .namespace == $ns)] | first // empty'; }
zt_has() { if [ -n "$(zt_policy "$1")" ]; then echo yes; else echo no; fi; }
# rs_call <path> -> what risk-score gets calling fraud-check (fortio curl)
rs_call() {
  local out
  out="$(k -n "${NS}" exec deploy/risk-score -c fortio -- fortio curl -quiet "${FC}$1" 2>&1 || true)"
  if grep -q 'Error status -1' <<< "${out}"; then echo "reset"; else sed -n 's/^HTTP\/1\.1 \([0-9]*\).*/\1/p' <<< "${out}" | head -1; fi
}
api() { local n="$1"; shift; codes "${NS}" payments-api "${n}" "$@"; }
check() {
  local desc="$1" want="$2"; shift 2
  settle 90 "${want}" "${NS}" payments-api "${N}" "$@" || true
  expect_eq "${desc}" "${want}" "$(api "${N}" "$@")"
}
# zt_log_errors <since> <src identity substring> -> distinct error= values ztunnels logged for it
zt_log_errors() {
  local z
  for z in $(k -n istio-system get pod -l app=ztunnel -o name); do
    k -n istio-system logs "${z}" --since-time="$1" 2>/dev/null
  done | grep 'connection complete' | grep -F "$2" | grep -F 'dst.namespace="payments-ambient"' | grep -o 'error="[^"]*"' | sort -u
}

step "No policy, no waypoint: ztunnel only (mTLS over HBONE)"
expect_eq "fraud-check has no waypoint" "None" "$(fc_waypoint)"
check "payments-api -> fraud-check" "200=${N}" "${FC}/v1/check/1"
expect_eq "risk-score -> fraud-check" "200" "$(rs_call /v1/check/1)"
expect_eq "legacy (plain text) -> fraud-check" "200=${N}" "$(codes legacy settlement-batch "${N}" "http://fraud-check.${NS}:8080/v1/check/1")"

step "L4 policy enforced by ztunnel: ambient/10-fraud-check-l4-allow.yaml (principals only)"
apply_file "${REPO_ROOT}/ambient/10-fraud-check-l4-allow.yaml"
wait_for 90 yes zt_has fraud-check-l4-allow || true
note "ztunnel holds: $(zt_policy fraud-check-l4-allow)"
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
check "payments-api (named) -> 200" "200=${N}" "${FC}/v1/check/1"
expect_eq "risk-score (not named) -> connection reset" "reset" "$(rs_call /v1/check/1)"
expect_eq "legacy (no identity) -> curl 56" "000=${N}" "$(codes legacy settlement-batch "${N}" "http://fraud-check.${NS}:8080/v1/check/1")"
sleep 2
errs="$(zt_log_errors "${since}" 'src.identity="spiffe://cluster.local/ns/payments-ambient/sa/risk-score"')"
note "ztunnel: ${errs}"
expect_match "ztunnel logs the refusal of risk-score's identity" 'connection closed due to policy rejection: allow policies exist, but none allowed' "${errs}"
k -n "${NS}" delete authorizationpolicy fraud-check-l4-allow >/dev/null
wait_for 90 no zt_has fraud-check-l4-allow || true

step "Silent error: silent-errors/07-ap-l7-enforced-by-ztunnel.yaml (methods/paths with a selector)"
apply_file "${REPO_ROOT}/silent-errors/07-ap-l7-enforced-by-ztunnel.yaml"
wait_for 90 yes zt_has fraud-check-l7-on-ztunnel || true
zp="$(zt_policy fraud-check-l7-on-ztunnel)"; note "ztunnel holds: ${zp}"
expect_eq "ztunnel received the ALLOW with its rules stripped (it cannot see methods or paths)" '{"action":"Allow","rules":[]}' \
  "$(jq -c '{action, rules}' <<< "${zp}")"
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
check "payments-api GET /v1/check/1, the exact request the rule allows -> no HTTP answer" "000=${N}" "${FC}/v1/check/1"
expect_eq "curl exit code" "000 56" "$(req "${NS}" payments-api "${FC}/v1/check/1")"
sleep 2
errs="$(zt_log_errors "${since}" 'src.identity="spiffe://cluster.local/ns/payments-ambient/sa/payments-api"')"
note "ztunnel: ${errs}"
expect_match "ztunnel: policy rejection for payments-api's identity" 'allow policies exist, but none allowed' "${errs}"
k -n "${NS}" delete authorizationpolicy fraud-check-l7-on-ztunnel >/dev/null
wait_for 90 no zt_has fraud-check-l7-on-ztunnel || true

step "Waypoint in the path: label istio.io/use-waypoint=waypoint, then ambient/20-fraud-check-l7-waypoint.yaml (targetRefs)"
k label ns "${NS}" istio.io/use-waypoint=waypoint --overwrite >/dev/null
note "kubectl label ns ${NS} istio.io/use-waypoint=waypoint"
wait_for 90 waypoint fc_waypoint || true
expect_eq "ztunnel now sends fraud-check traffic to the waypoint" "waypoint" "$(fc_waypoint)"
apply_file "${REPO_ROOT}/ambient/20-fraud-check-l7-waypoint.yaml"
wait_for 90 True eval "k -n ${NS} get authorizationpolicy fraud-check-l7 -o jsonpath='{.status.conditions[?(@.type==\"WaypointAccepted\")].status}'" || true
note "status: $(k -n "${NS}" get authorizationpolicy fraud-check-l7 -o jsonpath='{.status.conditions[0].type}={.status.conditions[0].status} {.status.conditions[0].message}')"
expect_eq "policy bound to the waypoint (condition WaypointAccepted)" "True" \
  "$(k -n "${NS}" get authorizationpolicy fraud-check-l7 -o jsonpath='{.status.conditions[?(@.type=="WaypointAccepted")].status}')"
check "payments-api GET /v1/check/1 -> 200" "200=${N}" "${FC}/v1/check/1"
check "payments-api POST /v1/check/1 -> 403" "403=${N}" "${FC}/v1/check/1" -X POST -d '{}'
# GHSA-w44g-8m76-8gc5 (fixed in 1.31.2): method rules and the method case
# over HTTP/2. ztunnel carries the client's bytes, so an HTTP/2 client reaches
# the waypoint over HTTP/2. This policy is an ALLOW list, a shape the advisory
# says was never bypassable; the check pins that it keeps refusing "post".
wp="$(k -n "${NS}" get pod -l gateway.networking.k8s.io/gateway-name=waypoint -o jsonpath='{.items[0].metadata.name}')"
expect_eq "the waypoint matches :method case-insensitively" '{"exact":"GET","ignoreCase":true}' \
  "$(ictl proxy-config listener "${wp}.${NS}" -o json | jq -c '[.. | objects | select(.name? == "envoy.filters.http.rbac") | .typedConfig.rules.policies["ns[payments-ambient]-policy[fraud-check-l7]-rule[0]"] // empty | .permissions[] | .. | objects | select(.header?.name == ":method") | .header.stringMatch] | first')"
check "payments-api \"post\" over HTTP/2 -> 403" "403=${N}" "${FC}/v1/check/1" --http2-prior-knowledge -X post -d '{}'
id="$(run_id)"; api 1 "${FC}/v1/check/${id}" --http2-prior-knowledge -X post -d '{}' >/dev/null
log="$(proxy_log "${NS}" gateway.networking.k8s.io/gateway-name=waypoint "${id}" istio-proxy | tail -1)"
note "waypoint: ${log:0:200}"
expect_match "the waypoint saw \"post\" over HTTP/2 and denied it" '"post /v1/check/r[0-9]+ HTTP/2" 403 - rbac_access_denied_matched_policy\[none\] ' "${log}"
check "and \"get\" over HTTP/2 is GET for the policy: 200" "200=${N}" "${FC}/v1/check/1" --http2-prior-knowledge -X get
check "payments-api GET /admin -> 403" "403=${N}" "${FC}/admin"
expect_eq "body" "RBAC: access denied" "$(req_full "${NS}" payments-api "${FC}/admin")"
expect_eq "risk-score -> 403 (an HTTP answer now: the waypoint speaks HTTP)" "403" "$(rs_call /v1/check/1)"
id="$(run_id)"; api 1 "${FC}/admin/${id}" >/dev/null
log="$(proxy_log "${NS}" gateway.networking.k8s.io/gateway-name=waypoint "${id}" istio-proxy | tail -1)"
note "waypoint: ${log:0:200}"
expect_match "the waypoint logs the denial" '" 403 - rbac_access_denied_matched_policy\[none\] .* inbound-vip\|8080\|http\|fraud-check\.payments-ambient\.svc\.cluster\.local ' "${log}"

step "What skips the waypoint skips its policy"
POD_IP="$(k -n "${NS}" get pod -l app=fraud-check -o jsonpath='{.items[0].status.podIP}')"
c="$(codes legacy settlement-batch "${N}" "http://fraud-check.${NS}:8080/admin")"
expect_eq "legacy (outside the mesh) -> fraud-check Service /admin: 200, no waypoint on its path" "200=${N}" "${c}"
c="$(api "${N}" "http://${POD_IP}:8080/admin")"
expect_eq "payments-api -> fraud-check pod IP /admin: 200 (the waypoint serves the Service, not the pod)" "200=${N}" "${c}"

step "An L4 policy that names the caller, with the waypoint in the path: ambient/10 again"
# The waypoint holds pooled HBONE connections to both fraud-check pods,
# opened while no L4 policy existed; use them right before the update and
# keep them busy (3 requests every 4s) for a minute after it.
api 4 "${FC}/v1/check/1" >/dev/null
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
apply_file "${REPO_ROOT}/ambient/10-fraud-check-l4-allow.yaml"
warm=""
deadline=$((SECONDS + 90))
until [ "$(zt_has fraud-check-l4-allow)" = "yes" ] || [ "${SECONDS}" -ge "${deadline}" ]; do warm="${warm} $(api 3 "${FC}/v1/check/1")"; sleep 2; done
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do warm="${warm} $(api 3 "${FC}/v1/check/1")"; sleep 4; done
warm="$(tr ' ' '\n' <<< "${warm}" | grep . | cut -d= -f1 | sort -u | paste -sd, -)"
note "requests over the waypoint's existing connections, 60s after the update: ${warm}"
expect_eq "connections opened before the policy keep the old decision while they stay in use (status codes seen)" "200" "${warm}"
closed="$(for z in $(k -n istio-system get pod -l app=ztunnel -o name); do k -n istio-system logs "${z}" --since-time="${since}"; done | grep -c "no longer allowed after a policy update" || true)"
expect_eq "ztunnel closed none of them after the update" "0" "${closed}"
note "idle for 40s: the waypoint's pooled connections close"
sleep 40
c="$(api "${N}" "${FC}/v1/check/1")"; note "new connections -> ${c}"
expect_eq "new connections through the waypoint are refused: 503" "503=${N}" "${c}"
id="$(run_id)"; api 1 "${FC}/v1/check/${id}" >/dev/null
sleep 2
wl="$(k -n "${NS}" logs deploy/waypoint --since=30s 2>/dev/null | grep -F 'tunnel_response:401' | tail -1 || true)"
note "waypoint: ${wl:0:200}"
expect_match "the waypoint's HBONE CONNECT to fraud-check is refused (401): ztunnel sees the waypoint's identity" 'UF,URX .*"tunnel_response:401"' "${wl}"
errs="$(zt_log_errors "${since}" 'src.identity="spiffe://cluster.local/ns/payments-ambient/sa/waypoint"')"
expect_match "ztunnel: policy rejection for the waypoint's identity" 'allow policies exist, but none allowed' "${errs}"
c="$(api "${N}" "http://${POD_IP}:8080/admin")"
expect_eq "while the pod IP path, which skips the waypoint, still gets /admin" "200=${N}" "${c}"

step "The fix: ambient/30-fraud-check-ztunnel-allow-waypoint.yaml (ztunnel admits only the waypoint)"
apply_file "${REPO_ROOT}/ambient/30-fraud-check-ztunnel-allow-waypoint.yaml"
wait_for 90 '["cluster.local/ns/payments-ambient/sa/waypoint"]' eval \
  "zt_policy fraud-check-l4-allow | jq -c '[.rules[][][] | .principals[]? | .. | strings]'" || true
check "GET /v1/check/1 -> 200" "200=${N}" "${FC}/v1/check/1"
check "POST /v1/check/1 -> 403 (waypoint L7)" "403=${N}" "${FC}/v1/check/1" -X POST -d '{}'
c="$(api "${N}" "http://${POD_IP}:8080/admin")"
expect_eq "pod IP /admin, skipping the waypoint -> reset" "000=${N}" "${c}"
c="$(codes legacy settlement-batch "${N}" "http://fraud-check.${NS}:8080/admin")"
expect_eq "legacy -> reset" "000=${N}" "${c}"
finish
