#!/usr/bin/env bash
# Regenerates apps/payments-ambient.yaml from apps/payments-sidecar.yaml: same
# workloads and ServiceAccounts, namespace payments-ambient, ambient data
# plane label instead of sidecar injection.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
sed -e "1,4c\\
# Ambient-mode namespace: no sidecar. The node's ztunnel carries the traffic\\
# (mTLS over HBONE) and enforces L4 policy; the waypoint in ambient/ enforces\\
# L7 policy once the namespace opts in with istio.io/use-waypoint.\\
# Identities: spiffe://cluster.local/ns/payments-ambient/sa/<service account>." \
    -e 's/^    istio-injection: enabled$/    istio.io\/dataplane-mode: ambient/' \
    -e 's/^  namespace: payments$/  namespace: payments-ambient/' \
    -e 's/^  name: payments$/  name: payments-ambient/' \
    "${REPO_ROOT}/apps/payments-sidecar.yaml" > "${REPO_ROOT}/apps/payments-ambient.yaml"
