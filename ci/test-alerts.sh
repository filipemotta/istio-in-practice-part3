#!/usr/bin/env bash
# Offline tests of observability/alerts.yaml (no cluster):
#   1. promtool check rules: syntax and PromQL;
#   2. promtool test rules: the unit tests in observability/alerts_test.yaml;
#   3. mutants: copies of the rules with one deliberate mistake each, which the
#      unit tests must reject (proves the tests can fail).
# Uses the promtool pinned by tools/install-cli.sh (same version as the
# Prometheus of the Istio 1.31.2 addons).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bash "${REPO_ROOT}/tools/install-cli.sh" >/dev/null
PROMTOOL="${REPO_ROOT}/bin/promtool"
RULES="${REPO_ROOT}/observability/alerts.yaml"
TESTS="${REPO_ROOT}/observability/alerts_test.yaml"

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '    [PASS] %s\n' "$1"; }
fail() { FAILED=$((FAILED + 1)); printf '    [FAIL] %s\n' "$1"; }

echo "==> promtool $("${PROMTOOL}" --version 2>&1 | sed -n '1s/^promtool, version \([^ ]*\).*/\1/p')"
if out="$("${PROMTOOL}" check rules "${RULES}" 2>&1)"; then
  pass "promtool check rules: $(grep -o '[0-9]* rules found' <<< "${out}")"
else
  fail "promtool check rules"; echo "${out}"
fi
if out="$("${PROMTOOL}" test rules "${TESTS}" 2>&1)"; then
  pass "promtool test rules: $(grep -c '^- name:' "${TESTS}") test groups"
else
  fail "promtool test rules"; echo "${out}"
fi

# mutant <description> <sed expression>: the tests must fail on the mutated rules.
mutant() {
  local tmp
  tmp="$(mktemp -d)"
  sed -E "$2" "${RULES}" > "${tmp}/alerts.yaml"
  cp "${TESTS}" "${tmp}/alerts_test.yaml"
  if cmp -s "${RULES}" "${tmp}/alerts.yaml"; then
    fail "mutant '$1': the sed expression changed nothing"
  elif "${PROMTOOL}" test rules "${tmp}/alerts_test.yaml" >/dev/null 2>&1; then
    fail "mutant '$1' was not caught by the tests"
  else
    pass "mutant '$1' is caught by the tests"
  fi
  rm -rf "${tmp}"
}
echo "==> mutants"
mutant "plain text matched as any policy" 's/connection_security_policy="none"/connection_security_policy=~".+"/'
mutant "plain text without for (fires on one request)" '/alert: IstioPlaintextInbound/,/for:/ s/for: 5m/for: 0m/'
mutant "denials counted with allowed requests" 's/authz_enforce_result="denied"/authz_enforce_result=~".+"/'
mutant "denial alert after 5m instead of 10m" '/alert: IstioAuthorizationDenied/,/for:/ s/for: 10m/for: 5m/'
mutant "dry run: any shadow result" 's/authz_dry_run_result="denied"/authz_dry_run_result=~".+"/'

printf '\n    result: %s passed, %s failed\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
