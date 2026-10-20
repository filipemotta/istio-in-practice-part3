#!/usr/bin/env bash
# Step 5: end-user identity at the edge. A Gateway API Gateway in front of
# payments-api; RequestAuthentication with a JWKS generated locally
# (tools/gen-jwt.sh); then the AuthorizationPolicy that actually requires a
# token. The client is legacy/settlement-batch playing an outside caller: it
# reaches the gateway's ClusterIP (kind has no load balancer).
# Expects payments in STRICT + deny by default (re-applied here so the step
# also runs on its own).
set -euo pipefail
# shellcheck source=/dev/null
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
assert_lab_context

NS="payments"
GW_NS="payments-ingress"
HOST="api.payments.example"
JWT_DIR="${OUT}/jwt"
N=5

step "payments as step 04 left it: STRICT, deny by default, paths opened by name"
apply_file "${REPO_ROOT}/mtls/peer-authentication-strict.yaml"
for f in 00-allow-nothing 10-fraud-check-allow 11-risk-score-allow 20-fraud-check-deny-export; do
  apply_file "${REPO_ROOT}/authz/${f}.yaml"
done
k -n "${NS}" delete authorizationpolicy payments-api-allow-ingress --ignore-not-found >/dev/null
push_wait "${NS}" payments-api payments-api-allow-ingress absent
reset_security "${GW_NS}" 2>/dev/null || true

step "Ingress: ingress/gateway.yaml (HTTP listener, ClusterIP service) + ingress/httproute.yaml"
apply_file "${REPO_ROOT}/ingress/gateway.yaml"
apply_file "${REPO_ROOT}/ingress/httproute.yaml"
k -n "${GW_NS}" wait --for=condition=Programmed gateway/payments-gateway --timeout=180s >/dev/null
k -n "${GW_NS}" rollout status deploy/payments-gateway-istio --timeout=180s >/dev/null
k -n "${GW_NS}" get gateway payments-gateway | sed 's/^/    /'
IP="$(k -n "${GW_NS}" get svc payments-gateway-istio -o jsonpath='{.spec.clusterIP}')"
URL="http://${HOST}/v1/payments/1"
# edge [curl args] -> histogram of N requests from outside the mesh to the gateway
edge() { codes legacy settlement-batch "${N}" "${URL}" --resolve "${HOST}:80:${IP}" "$@"; }
edge_body() { req_full legacy settlement-batch "${URL}" --resolve "${HOST}:80:${IP}" "$@"; }
bearer() { printf 'Authorization: Bearer %s' "$(cat "${JWT_DIR}/$1.jwt")"; }
# edge_check <description> <expected histogram> [curl args]
edge_check() {
  local desc="$1" want="$2"; shift 2
  settle 90 "${want}" legacy settlement-batch "${N}" "${URL}" --resolve "${HOST}:80:${IP}" "$@" || true
  expect_eq "${desc}" "${want}" "$(edge "$@")"
}
expect_eq "the generated Service is a ClusterIP (ingress/gateway.yaml ConfigMap)" "ClusterIP" \
  "$(k -n "${GW_NS}" get svc payments-gateway-istio -o jsonpath='{.spec.type}')"
expect_eq "HTTPRoute accepted by the Gateway" "True" \
  "$(k -n "${NS}" get httproute payments-api -o jsonpath='{.status.parents[0].conditions[?(@.type=="Accepted")].status}')"

step "The gateway is a caller too: deny by default refuses it until it is named"
edge_check "gateway -> payments-api without an ALLOW for the gateway identity" "403=${N}"
apply_file "${REPO_ROOT}/authz/12-payments-api-allow-ingress.yaml"
push_wait "${NS}" payments-api payments-api-allow-ingress
edge_check "with authz/12 (principal cluster.local/ns/payments-ingress/sa/payments-gateway-istio)" "200=${N}"

step "Tokens: tools/gen-jwt.sh (RSA key, JWKS and RS256 tokens generated with openssl)"
bash "${REPO_ROOT}/tools/gen-jwt.sh" "${JWT_DIR}" | sed 's/^/    /'
expect_eq "valid token expires in about 10 years" "10" \
  "$(cut -d. -f2 "${JWT_DIR}/valid.jwt" | tr '_-' '/+' | awk '{ while (length($0) % 4) $0 = $0 "="; print }' | openssl base64 -d -A | jq -r --argjson now "$(date +%s)" '((.exp - $now) / 31536000) | round')"

step "RequestAuthentication alone: jwt/request-authentication.yaml (JWKS injected at apply time)"
jwks="$(cat "${JWT_DIR}/jwks.json")" yq '.spec.jwtRules[0].jwks = strenv(jwks)' "${REPO_ROOT}/jwt/request-authentication.yaml" | k apply -f - >/dev/null
note "kubectl apply -f jwt/request-authentication.yaml (jwks from ${JWT_DIR#"${REPO_ROOT}"/}/jwks.json)"
wait_for 90 "1" eval "ictl proxy-config listener deploy/payments-gateway-istio -n ${GW_NS} -o json | grep -c 'issuer.payments.example' | awk '{ print (\$1 > 0) }'" || true
edge_check "a token signed by the issuer -> 200" "200=${N}" -H "$(bearer valid)"
edge_check "an expired token -> 401" "401=${N}" -H "$(bearer expired)"
expect_eq "body" "Jwt is expired" "$(edge_body -H "$(bearer expired)")"
expect_eq "a token from another issuer -> body" "Jwt issuer is not configured" "$(edge_body -H "$(bearer wrong-issuer)")"
expect_eq "a token signed by another key (same kid) -> body" "Jwt verification fails" "$(edge_body -H "$(bearer forged)")"
expect_eq "a token that is not a JWT -> body" "Jwt is not in the form of Header.Payload.Signature with two dots and 3 sections" \
  "$(edge_body -H 'Authorization: Bearer not-a-jwt')"
edge_check "the forged token -> 401" "401=${N}" -H "$(bearer forged)"
id="$(run_id)"
req legacy settlement-batch "http://${HOST}/v1/payments/${id}" --resolve "${HOST}:80:${IP}" -H "$(bearer expired)" >/dev/null
log="$(proxy_log "${GW_NS}" gateway.networking.k8s.io/gateway-name=payments-gateway "${id}" istio-proxy | tail -1)"
note "gateway access log: ${log:0:160}"
expect_match "access log: 401 jwt_authn_access_denied{Jwt_is_expired}" '" 401 - jwt_authn_access_denied\{Jwt_is_expired\} ' "${log}"
edge_check "and NO token at all -> 200: the silent default" "200=${N}"

step "Require a token: jwt/require-jwt.yaml (requestPrincipals)"
apply_file "${REPO_ROOT}/jwt/require-jwt.yaml"
wait_for 90 "403" eval "edge_body -o /dev/null -w '%{http_code}'" || true
edge_check "no token -> 403" "403=${N}"
expect_eq "body" "RBAC: access denied" "$(edge_body)"
edge_check "valid token -> 200" "200=${N}" -H "$(bearer valid)"
edge_check "expired token -> still 401 (authentication fails before authorization)" "401=${N}" -H "$(bearer expired)"
id="$(run_id)"
req legacy settlement-batch "http://${HOST}/v1/payments/${id}" --resolve "${HOST}:80:${IP}" >/dev/null
expect_match "access log: 403 rbac_access_denied_matched_policy[none] at the gateway" '" 403 - rbac_access_denied_matched_policy\[none\] ' \
  "$(proxy_log "${GW_NS}" gateway.networking.k8s.io/gateway-name=payments-gateway "${id}" istio-proxy | tail -1)"
id="$(run_id)"
req legacy settlement-batch "http://${HOST}/v1/payments/${id}" --resolve "${HOST}:80:${IP}" -H "$(bearer valid)" >/dev/null
expect_eq "the valid request reached payments-api (its sidecar logged it)" "1" \
  "$(proxy_log "${NS}" app=payments-api "${id}" | grep -c '" 200 ' || true)"
finish
