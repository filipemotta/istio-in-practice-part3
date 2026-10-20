#!/usr/bin/env bash
# Step 3: from PERMISSIVE to STRICT in the payments namespace.
#   1. the default accepts plain text: legacy/settlement-batch (no sidecar)
#      calls fraud-check and gets 200;
#   2. inventory before closing: Prometheus (connection_security_policy),
#      Kiali (isMTLS on the edge), mtls/plaintext-inventory.sh, the alert;
#   3. STRICT (mtls/peer-authentication-strict.yaml): the legacy caller is
#      reset, the mesh callers keep working;
#   4. kubelet probes under STRICT: Istio's probe rewrite keeps pods Ready;
#      a pod that opts out of the rewrite goes NotReady;
#   5. a scoped port exception (portLevelMtls), and the silent version of it
#      that names the Service port instead of the container port.
# Leaves payments in STRICT.
set -euo pipefail
# shellcheck source=/dev/null
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
assert_lab_context

NS="payments"
FC="http://fraud-check.${NS}:8080"
reset_security "${NS}" payments-ingress
k -n "${NS}" delete deploy ledger --ignore-not-found >/dev/null
k -n "${NS}" wait --for=delete pod -l app=ledger --timeout=180s >/dev/null 2>&1 || true

# legacy_req <url> [curl args] / api_req: one request from each side
legacy_req() { req legacy settlement-batch "$@"; }
# kiali_edges -> "src ns/workload -> dst ns/workload isMTLS=<value>" lines (last 10 minutes)
kiali_edges() {
  svc_get istio-system kiali:20001 "/kiali/api/namespaces/graph?namespaces=${NS}&graphType=workload&duration=600s&appenders=securityPolicy" \
    | jq -r '(.elements.nodes | map({key: .data.id, value: "\(.data.namespace)/\(.data.workload // .data.nodeType)"}) | from_entries) as $n
             | .elements.edges[] | "\($n[.data.source]) -> \($n[.data.target]) isMTLS=\(.data.isMTLS // "none")"'
}

# trickle_until <seconds> <command...>: keep a little traffic flowing (one
# plain-text call from legacy, one mTLS call to fraud-check and one to
# risk-score) until the command succeeds. Rates and increase() need two
# samples of a series: on a fresh cluster the first scrape is not enough.
trickle_until() {
  local deadline=$((SECONDS + $1)); shift
  until "$@" >/dev/null 2>&1; do
    [ "${SECONDS}" -lt "${deadline}" ] || return 1
    legacy_req "${FC}/v1/check/trickle" >/dev/null
    req "${NS}" payments-api "${FC}/v1/check/trickle" >/dev/null
    req "${NS}" payments-api "http://risk-score.${NS}:8080/v1/score/trickle" >/dev/null
    sleep 10
  done
}
inventory_names_legacy() { bash "${REPO_ROOT}/mtls/plaintext-inventory.sh" "${NS}" "${KUBE_CONTEXT}" 1h | grep -Eq 'none +legacy/settlement-batch +-> fraud-check '; }
inventory_risk_score_mtls() { bash "${REPO_ROOT}/mtls/plaintext-inventory.sh" "${NS}" "${KUBE_CONTEXT}" 1h risk-score | grep -Eq 'mutual_tls +payments/payments-api +-> risk-score '; }
kiali_has_both() {
  local e; e="$(kiali_edges)"
  grep -qF 'legacy/settlement-batch -> payments/fraud-check' <<< "${e}" && grep -qF 'payments/payments-api -> payments/fraud-check' <<< "${e}"
}

step "PERMISSIVE (no PeerAuthentication): who gets in"
wait_for 90 "200 0" legacy_req "${FC}/v1/check/permissive" || true
id_plain="$(run_id)"; id_mtls="$(run_id)"
c="$(codes legacy settlement-batch 10 "${FC}/v1/check/${id_plain}")"; note "legacy/settlement-batch (plain text) x10 -> ${c}"
expect_eq "the caller outside the mesh is accepted" "200=10" "${c}"
c="$(codes "${NS}" payments-api 10 "${FC}/v1/check/${id_mtls}")"; note "payments/payments-api (mTLS) x10 -> ${c}"
expect_eq "the mesh caller too" "200=10" "${c}"
expect_eq "fraud-check served all 10 plain-text requests" "10" "$(reached "${NS}" fraud-check "${id_plain}")"
xfcc="$(fortio_log "${NS}" fraud-check "${id_mtls}" | tail -1 | jq -r '."header.x-forwarded-client-cert" // "absent"')"
note "x-forwarded-client-cert seen by the fraud-check app (mTLS): ${xfcc}"
expect_match "behind mTLS the application receives the caller's identity in x-forwarded-client-cert" \
  ';URI=spiffe://cluster.local/ns/payments/sa/payments-api$' "${xfcc}"
expect_eq "behind plain text it receives none" "absent" \
  "$(fortio_log "${NS}" fraud-check "${id_plain}" | tail -1 | jq -r '."header.x-forwarded-client-cert" // "absent"')"
log="$(proxy_log "${NS}" app=fraud-check "${id_plain}" | tail -1)"; note "plain text: ${log:0:240}"
expect_match "fraud-check's sidecar logs the plain-text request with no TLS server name ('-')" \
  ' inbound\|8080\|\| [0-9.:]+ [0-9.:]+ [0-9.:]+ - default$' "${log}"
log="$(proxy_log "${NS}" app=fraud-check "${id_mtls}" | tail -1)"; note "mTLS:       ${log:0:240}"
expect_match "and the mTLS request with the SNI istio uses between sidecars" \
  ' outbound_\.8080_\._\.fraud-check\.payments\.svc\.cluster\.local default$' "${log}"

step "Inventory before closing: Prometheus, connection_security_policy at reporter=destination"
q='sum by (source_workload_namespace, source_workload, source_principal, connection_security_policy) (istio_requests_total{reporter="destination", destination_workload_namespace="payments", destination_workload="fraud-check"})'
note "${q}"
# The addon Prometheus scrapes every 15s; wait for the plain-text series.
# plain_policy -> the connection_security_policy of settlement-batch's series
plain_policy() { prom "${q}" | jq -r '.data.result[] | select(.metric.source_workload == "settlement-batch") | .metric.connection_security_policy'; }
wait_for 120 "none" plain_policy || true
res="$(prom "${q}" | jq -r '.data.result[] | "\(.metric.source_workload_namespace)/\(.metric.source_workload) \(.metric.connection_security_policy) \(.metric.source_principal) \(.value[1])"' | sort)"
printf '%s\n' "${res}" | sed 's/^/      /'
expect_match "legacy/settlement-batch: connection_security_policy none, principal unknown" \
  '^legacy/settlement-batch none unknown [0-9]+$' "${res}"
expect_match "payments/payments-api: mutual_tls, principal spiffe://cluster.local/ns/payments/sa/payments-api" \
  '^payments/payments-api mutual_tls spiffe://cluster.local/ns/payments/sa/payments-api [0-9]+$' "${res}"

step "Inventory: mtls/plaintext-inventory.sh (the gate to run before STRICT)"
trickle_until 180 inventory_names_legacy || true
trickle_until 120 inventory_risk_score_mtls || true
set +e; inv="$(bash "${REPO_ROOT}/mtls/plaintext-inventory.sh" "${NS}" "${KUBE_CONTEXT}" 1h)"; rc=$?; set -e
printf '%s\n' "${inv}" | sed 's/^/    /'
expect_eq "exits 1 while a plain-text caller is in the window" "1" "${rc}"
expect_match "and names it" 'none +legacy/settlement-batch +-> fraud-check ' "${inv}"
set +e; inv="$(bash "${REPO_ROOT}/mtls/plaintext-inventory.sh" "${NS}" "${KUBE_CONTEXT}" 1h risk-score)"; rc=$?; set -e
printf '%s\n' "${inv}" | sed 's/^/    /'
expect_eq "exits 0 for a destination that only mesh callers used (risk-score)" "0" "${rc}"
expect_match "and says so, with the callers it saw" 'ready for STRICT: every caller in the window used mutual TLS' "${inv}"

step "Inventory: Kiali graph (security appender, isMTLS per edge)"
trickle_until 180 kiali_has_both || true
edges="$(kiali_edges | sort)"
printf '%s\n' "${edges}" | sed 's/^/      /'
expect_match "Kiali: the edge from settlement-batch has no mTLS" 'legacy/settlement-batch -> payments/fraud-check isMTLS=none' "${edges}"
expect_match "Kiali: payments-api -> fraud-check is 100% mTLS" 'payments/payments-api -> payments/fraud-check isMTLS=100' "${edges}"

step "Alert IstioPlaintextInbound (observability/alerts.yaml)"
# The rate needs a few samples; keep a trickle of plain text until Prometheus evaluates it.
started=${SECONDS}; deadline=$((SECONDS + 240)); st=inactive
while [ "${SECONDS}" -lt "${deadline}" ]; do
  legacy_req "${FC}/v1/check/trickle" >/dev/null
  st="$(alert_state IstioPlaintextInbound source_workload=settlement-batch destination_workload=fraud-check)"
  [ "${st}" = "inactive" ] || break
  sleep 10
done
note "after $((SECONDS - started))s: IstioPlaintextInbound=${st}"
expect_match "IstioPlaintextInbound is pending or firing for legacy/settlement-batch -> fraud-check" '^(pending|firing)$' "${st}"

step "STRICT for the namespace: mtls/peer-authentication-strict.yaml"
apply_file "${REPO_ROOT}/mtls/peer-authentication-strict.yaml"
wait_for 90 "000 56" legacy_req "${FC}/v1/check/strict" || true
id="$(run_id)"
c="$(codes legacy settlement-batch 10 "${FC}/v1/check/${id}")"; note "legacy x10 -> ${c}"
expect_eq "the plain-text caller gets no HTTP answer at all" "000=10" "${c}"
r="$(legacy_req "${FC}/v1/check/${id}")"
expect_eq "curl exit code 56" "000 56" "${r}"
err="$(req_full legacy settlement-batch "${FC}/v1/check/${id}" -o /dev/null | head -1)"; note "curl: ${err}"
expect_eq "curl's error" "curl: (56) Recv failure: Connection reset by peer" "${err}"
expect_eq "no request reached fraud-check" "0" "$(reached "${NS}" fraud-check "${id}")"
legacy_ip="$(k -n legacy get pod -l app=settlement-batch -o jsonpath='{.items[0].status.podIP}')"
sleep 2
nr="$(for p in $(k -n "${NS}" get pod -l app=fraud-check -o name); do k -n "${NS}" logs "${p}" -c istio-proxy --since=1m; done \
  | grep -F " ${legacy_ip}:" | grep -F 'NR filter_chain_not_found' | tail -1 || true)"
note "fraud-check sidecar: ${nr}"
expect_match "the sidecar logs a TCP-level rejection: no filter chain for plain text (NR filter_chain_not_found)" \
  '^\[[^]]+\] "- - -" 0 NR filter_chain_not_found ' "${nr}"
c="$(codes "${NS}" payments-api 10 "${FC}/v1/check/strict-ok")"; note "payments-api x10 -> ${c}"
expect_eq "the mesh caller still works" "200=10" "${c}"

step "Kubelet probes under STRICT: Istio rewrites them to the sidecar agent"
sleep 25 # more than two readiness periods (10s) after the switch
expect_eq "every payments pod is still Ready" "$(k -n "${NS}" get pod --no-headers | wc -l | tr -d ' ')" \
  "$(k -n "${NS}" get pod -o json | jq '[.items[] | select(any(.status.conditions[]; .type == "Ready" and .status == "True"))] | length')"
probe="$(k -n "${NS}" get pod -l app=fraud-check -o json | jq -c '.items[0].spec.containers[] | select(.name == "fortio") | .readinessProbe.httpGet')"
note "fraud-check readinessProbe as the kubelet sees it: ${probe}"
expect_eq "probe sent to the agent (port 15020, /app-health/<container>/readyz)" '{"path":"/app-health/fortio/readyz","port":15020,"scheme":"HTTP"}' "${probe}"
expect_eq "the original probe is kept for the agent in ISTIO_KUBE_APP_PROBERS" '{"/app-health/fortio/readyz":{"httpGet":{"path":"/debug","port":8080,"scheme":"HTTP"},"timeoutSeconds":1}}' \
  "$(k -n "${NS}" get pod -l app=fraud-check -o json | jq -c '.items[0].spec.initContainers[] | select(.name == "istio-proxy") | .env[] | select(.name == "ISTIO_KUBE_APP_PROBERS") | .value | fromjson')"

step "A pod that opts out of the rewrite: apps/probe-no-rewrite.yaml (ledger)"
apply_file "${REPO_ROOT}/apps/probe-no-rewrite.yaml"
wait_for 120 "Running" eval "k -n ${NS} get pod -l app=ledger -o jsonpath='{.items[0].status.phase}'" || true
sleep 30
expect_eq "ledger's probe goes straight to the app port" '{"path":"/debug","port":8080,"scheme":"HTTP"}' \
  "$(k -n "${NS}" get pod -l app=ledger -o json | jq -c '.items[0].spec.containers[] | select(.name == "fortio") | .readinessProbe.httpGet')"
expect_eq "ledger never becomes Ready" "False" \
  "$(k -n "${NS}" get pod -l app=ledger -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}')"
ev="$(k -n "${NS}" get events --field-selector reason=Unhealthy -o json | jq -r '[.items[] | select(.involvedObject.name | startswith("ledger-")) | .message] | last // ""')"
note "event: ${ev}"
expect_match "the kubelet's plain-text probe is reset by the sidecar" 'Readiness probe failed: Get "http://[0-9.]+:8080/debug": read tcp [0-9.:]+->[0-9.:]+: read: connection reset by peer' "${ev}"
k -n "${NS}" delete deploy ledger --wait=false >/dev/null

step "A scoped exception: mtls/fraud-check-port-exception.yaml (portLevelMtls 8090: PERMISSIVE)"
apply_file "${REPO_ROOT}/mtls/fraud-check-port-exception.yaml"
wait_for 90 "200 0" legacy_req "http://fraud-check.${NS}:8090/v1/score/port-exception" || true
c="$(codes legacy settlement-batch 5 "http://fraud-check.${NS}:8090/v1/score/port-exception")"
expect_eq "legacy -> fraud-check:8090 accepted again (fraud-check forwards to risk-score over mTLS)" "200=5" "${c}"
c="$(codes legacy settlement-batch 5 "${FC}/v1/check/port-exception")"
expect_eq "legacy -> fraud-check:8080 still reset" "000=5" "${c}"
k -n "${NS}" delete peerauthentication fraud-check-legacy-port >/dev/null
wait_for 90 "000 56" legacy_req "http://fraud-check.${NS}:8090/v1/score/port-exception" || true
expect_eq "exception removed: 8090 reset again" "000 56" "$(legacy_req "http://fraud-check.${NS}:8090/v1/score/port-exception")"

step "Silent error: silent-errors/02-pa-port-level-service-port.yaml (Service port 8080, container port 9080)"
apply_file "${REPO_ROOT}/silent-errors/02-pa-port-level-service-port.yaml"
expect_eq "accepted by the API server" "payments-api-legacy-port" "$(k -n "${NS}" get peerauthentication payments-api-legacy-port -o jsonpath='{.metadata.name}')"
sleep 10
c="$(codes legacy settlement-batch 5 "http://payments-api.${NS}:8080/v1/payments/1")"
expect_eq "and does nothing: legacy -> payments-api:8080 still reset" "000=5" "${c}"
note "the same policy with the container port (9080), applied from a yq edit of the file:"
yq '.spec.portLevelMtls = {"9080": {"mode": "PERMISSIVE"}}' "${REPO_ROOT}/silent-errors/02-pa-port-level-service-port.yaml" | k apply -f - >/dev/null
wait_for 90 "200 0" legacy_req "http://payments-api.${NS}:8080/v1/payments/1" || true
expect_eq "with 9080 the exception applies (legacy -> payments-api:8080 -> 200)" "200 0" "$(legacy_req "http://payments-api.${NS}:8080/v1/payments/1")"
k -n "${NS}" delete peerauthentication payments-api-legacy-port >/dev/null

step "portLevelMtls without a selector is rejected (ci/testdata/pa-port-level-without-selector.yaml)"
out="$(k apply --dry-run=server -f "${REPO_ROOT}/ci/testdata/pa-port-level-without-selector.yaml" 2>&1 || true)"
note "${out}"
expect_match "the API server refuses it" 'Invalid value: portLevelMtls requires selector' "${out}"

step "End state: payments is STRICT"
expect_eq "PeerAuthentication payments/default" "STRICT" "$(k -n "${NS}" get peerauthentication default -o jsonpath='{.spec.mtls.mode}')"
finish
