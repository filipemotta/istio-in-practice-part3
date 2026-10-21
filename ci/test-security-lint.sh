#!/usr/bin/env bash
# Tests for ci/security-lint.sh. No cluster needed.
# Every working set of the lab must pass; every statically detectable silent
# error must fail with its own message. Each case lints the set of files that
# would be applied together (policies with the workloads, namespaces and
# gateways they refer to).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="${REPO_ROOT}/bin:${PATH}"
LINT="${REPO_ROOT}/ci/security-lint.sh"
cd "${REPO_ROOT}" || exit 2

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '    [PASS] %s\n' "$1"; }
fail() { FAILED=$((FAILED + 1)); printf '    [FAIL] %s\n' "$1"; }

APPS="apps/payments-sidecar.yaml apps/legacy.yaml"
AMBIENT="apps/payments-ambient.yaml ambient/waypoint.yaml"
WAYPOINT_ON="ci/testdata/ns-payments-ambient-use-waypoint.yaml"

# expect_pass <description> <files...>
expect_pass() {
  local desc="$1" out; shift
  if out="$(bash "${LINT}" "$@" 2>&1)"; then
    pass "${desc}"
  else
    fail "${desc}"; printf '%s\n' "${out}" | sed 's/^/        /'
  fi
}
# expect_fail <description> <expected message (fixed string)> <files...>
expect_fail() {
  local desc="$1" msg="$2" out; shift 2
  if out="$(bash "${LINT}" "$@" 2>&1)"; then
    fail "${desc} (lint passed, expected a failure)"
  elif grep -qF -- "${msg}" <<< "${out}"; then
    pass "${desc}"
    grep -F -- "${msg}" <<< "${out}" | head -1 | sed 's/^/        /'
  else
    fail "${desc} (failed without the expected message: ${msg})"; printf '%s\n' "${out}" | sed 's/^/        /'
  fi
}

echo "== working sets must pass"
# shellcheck disable=SC2086 # word splitting of the file lists is intended
{
expect_pass "workloads alone (sidecar, ambient, legacy)" ${APPS} ${AMBIENT}
expect_pass "STRICT + port exception with an owner and an expiry date" ${APPS} mtls/peer-authentication-strict.yaml mtls/fraud-check-port-exception.yaml
expect_pass "workload-level PERMISSIVE with no STRICT above it (nothing to override)" ${APPS} ci/testdata/pa-workload-permissive-override.yaml
expect_pass "deny by default + the paths opened by name + DENY (step 04 end state)" \
  ${APPS} ingress/gateway.yaml mtls/peer-authentication-strict.yaml \
  authz/00-allow-nothing.yaml authz/10-fraud-check-allow.yaml authz/11-risk-score-allow.yaml \
  authz/12-payments-api-allow-ingress.yaml authz/20-fraud-check-deny-export.yaml
expect_pass "AUDIT, dry-run DENY and the emergency deny-all" ${APPS} authz/30-fraud-check-audit.yaml \
  authz/40-fraud-check-deny-post-dry-run.yaml authz/90-deny-all-emergency.yaml
expect_pass "gateway + RequestAuthentication + the policy that requires a token" ${APPS} ingress/ jwt/
expect_pass "TLS origination: ServiceEntry + DestinationRule" egress/
expect_pass "ambient without waypoint: L4 policy on ztunnel (principals)" ${AMBIENT} ambient/10-fraud-check-l4-allow.yaml
expect_pass "ambient with waypoint: L7 on the waypoint + ztunnel admits only the waypoint" \
  ${AMBIENT} ${WAYPOINT_ON} ambient/20-fraud-check-l7-waypoint.yaml ambient/30-fraud-check-ztunnel-allow-waypoint.yaml

echo "== silent errors must fail"
expect_fail "RequestAuthentication without an AuthorizationPolicy that requires a token" \
  "no AuthorizationPolicy in the set requires a token for Gateway/payments-gateway (requestPrincipals): requests without a token are accepted" \
  ${APPS} ingress/ jwt/request-authentication.yaml
expect_fail "portLevelMtls on the Service port (8080) instead of the container port (9080)" \
  "portLevelMtls port 8080 is not a container port of the selected workloads (9080)" \
  ${APPS} silent-errors/02-pa-port-level-service-port.yaml
expect_fail "ALLOW with an empty rule, named deny-all" \
  "rule #0 is empty: an empty rule matches every request, so this ALLOW allows everything" \
  ${APPS} silent-errors/03-ap-allow-empty-rule.yaml
expect_fail "principal without the trust domain" \
  "principal \"ns/payments/sa/payments-api\" has no trust domain" \
  ${APPS} silent-errors/04-ap-principal-without-trust-domain.yaml
expect_fail "principal with the wrong namespace" \
  "principal \"cluster.local/ns/payment/sa/payments-api\" names no ServiceAccount of the analyzed set (payment/payments-api): it never matches" \
  ${APPS} silent-errors/05-ap-principal-wrong-namespace.yaml
expect_fail "DENY with notPrincipals" \
  "DENY with notPrincipals/notNamespaces denies every caller that is not listed" \
  ${APPS} silent-errors/06-ap-deny-not-principals.yaml
expect_fail "L7 attributes in a policy enforced by ztunnel" \
  "L7 attributes in a policy enforced by ztunnel (ambient namespace, workload selector)" \
  ${AMBIENT} silent-errors/07-ap-l7-enforced-by-ztunnel.yaml
expect_fail "ztunnel policy naming the caller while the waypoint is in the path" \
  "ztunnel policy names callers other than the waypoint in a namespace that uses the waypoint \"waypoint\"" \
  ${AMBIENT} ${WAYPOINT_ON} ambient/10-fraud-check-l4-allow.yaml
expect_fail "DENY with only HTTP attributes and no port (ci/testdata)" \
  "DENY rule #0 uses HTTP attributes without a port: it also denies all TCP traffic in its scope" \
  ${APPS} ci/testdata/ap-deny-http-only-no-port.yaml
expect_fail "portLevelMtls without a selector (ci/testdata; the API server rejects it too)" \
  "portLevelMtls without a selector" \
  ${APPS} ci/testdata/pa-port-level-without-selector.yaml
expect_fail "workload-level PERMISSIVE left under a namespace-wide STRICT (ci/testdata)" \
  "mode PERMISSIVE overrides the STRICT of payments/default for the pods it selects" \
  ${APPS} mtls/peer-authentication-strict.yaml ci/testdata/pa-workload-permissive-override.yaml
expect_fail "workload-level PERMISSIVE under a mesh-wide STRICT (ci/testdata)" \
  "mode PERMISSIVE overrides the STRICT of istio-system/default for the pods it selects" \
  ${APPS} ci/testdata/pa-mesh-wide-strict.yaml ci/testdata/pa-workload-permissive-override.yaml
expect_fail "the same override read from kubectl get -o yaml (kind: List, ci/testdata)" \
  "mode PERMISSIVE overrides the STRICT of payments/default for the pods it selects" \
  ${APPS} mtls/peer-authentication-strict.yaml ci/testdata/pa-list-from-cluster.yaml
expect_fail "port exception under STRICT with no owner or expiry date (ci/testdata)" \
  "port 8090 PERMISSIVE overrides the STRICT of payments/default for the pods it selects" \
  ${APPS} mtls/peer-authentication-strict.yaml ci/testdata/pa-port-exception-no-owner.yaml
expect_fail "port exception past its expiry date (ci/testdata)" \
  "exception expired on 2026-01-01 (owner team-payments): port 8090 PERMISSIVE still overrides the STRICT of payments/default" \
  ${APPS} mtls/peer-authentication-strict.yaml ci/testdata/pa-port-exception-expired.yaml
expect_fail "ServiceEntry sending HTTP to 443 without the TLS-originating DestinationRule" \
  "port 80 of api.github.com is HTTP sent to targetPort 443 with no DestinationRule originating TLS" \
  egress/serviceentry-github.yaml

echo "== not detectable offline (proved by the lab, scripts/03-mtls.sh)"
expect_pass "STRICT while a plain-text caller is still in the traffic passes the lint (gate: mtls/plaintext-inventory.sh)" \
  ${APPS} mtls/peer-authentication-strict.yaml
}

printf '\n    result: %s passed, %s failed\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
