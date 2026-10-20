#!/usr/bin/env bash
# Runs the whole lab end to end, in the order of the article, and exits non-zero
# if any assertion fails. Leaves the lab running; scripts/teardown.sh removes it.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

start="$(date +%s)"
failed=()

# Offline checks first: they need no cluster (ci/security-lint.sh and its
# tests, the alert rules and their promtool unit tests, the JWT and TLS
# generators, the context guard).
bash "${DIR}/../tools/install-cli.sh" >/dev/null
for t in test-security-lint test-alerts test-tools test-context-guard; do
  printf '\n######## ci/%s ########\n' "${t}"
  if ! bash "${DIR}/../ci/${t}.sh"; then
    failed+=("ci/${t}")
  fi
done

for s in 01-cluster 02-identity 03-mtls 04-authz 05-jwt 06-tls-edges 07-ambient; do
  printf '\n######## %s ########\n' "${s}"
  if ! bash "${DIR}/${s}.sh"; then
    failed+=("${s}")
    # Every later step needs the cluster from step 1.
    [ "${s}" = "01-cluster" ] && break
  fi
done

printf '\n######## summary ########\n'
echo "duration: $(( $(date +%s) - start ))s"
if [ "${#failed[@]}" -eq 0 ]; then
  echo "all steps passed"
else
  echo "failed steps: ${failed[*]}"
  exit 1
fi
