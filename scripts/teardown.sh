#!/usr/bin/env bash
# Removes everything the lab created: the kind cluster istio-p3 (and with it
# every namespace, addon and policy), and the generated keys, tokens and
# certificates in out/. Nothing else on the machine is touched.
set -uo pipefail
# shellcheck source=/dev/null
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

step "kind cluster ${CLUSTER_NAME}"
kind delete cluster --name "${CLUSTER_NAME}" || true
step "generated key material (out/jwt, out/tls)"
rm -rf "${OUT}/jwt" "${OUT}/tls"
note "done"
