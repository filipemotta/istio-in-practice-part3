#!/usr/bin/env bash
# Step 1: kind cluster, Gateway API CRDs (standard channel), Istio with the
# ambient profile (istiod + istio-cni + ztunnel) and no mTLS setting at all,
# the Prometheus and Kiali addons of the Istio release, the alert rules of
# observability/alerts.yaml, and the workloads:
#   payments          sidecar mode (payments-api, fraud-check, risk-score)
#   payments-ambient  the same workloads in ambient mode, plus a waypoint
#   legacy            a pod outside the mesh (settlement-batch)
set -euo pipefail
# shellcheck source=/dev/null
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

ensure_clis

step "kind cluster ${CLUSTER_NAME}"
if grep -qx "${CLUSTER_NAME}" <<< "$(kind get clusters 2>/dev/null)"; then
  note "already exists"
else
  kind create cluster --config "${REPO_ROOT}/kind/cluster.yaml"
fi
assert_lab_context
k get nodes -o wide

step "Gateway API ${GATEWAY_API_VERSION} CRDs, standard channel"
k apply --server-side -f \
  "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml" >/dev/null
k get crd -l gateway.networking.k8s.io/channel=standard \
  -o custom-columns='CRD:.metadata.name,VERSION:.metadata.annotations.gateway\.networking\.k8s\.io/bundle-version'

step "Istio ${ISTIO_VERSION}, ambient profile (istio/install.yaml)"
ictl install -y -f "${REPO_ROOT}/istio/install.yaml"
k -n istio-system get pods -o wide

step "Observability addons from the Istio ${ISTIO_VERSION} release (samples/addons)"
for addon in prometheus kiali; do
  k apply -f "https://raw.githubusercontent.com/istio/istio/${ISTIO_VERSION}/samples/addons/${addon}.yaml" >/dev/null
done
for d in prometheus kiali; do
  k -n istio-system rollout status "deploy/${d}" --timeout=300s
done
note "observability/alerts.yaml -> ConfigMap istio-system/prometheus, key alerting_rules.yml"
load_alert_rules

step "Workloads: payments (sidecar), payments-ambient (ambient), legacy (no mesh)"
k apply -f "${REPO_ROOT}/apps/payments-sidecar.yaml"
k apply -f "${REPO_ROOT}/apps/payments-ambient.yaml"
k apply -f "${REPO_ROOT}/apps/legacy.yaml"
for ns in payments payments-ambient; do
  for d in payments-api fraud-check risk-score; do
    k -n "${ns}" rollout status "deploy/${d}" --timeout=300s
  done
done
k -n legacy rollout status deploy/settlement-batch --timeout=300s

step "Waypoint for payments-ambient (ambient/waypoint.yaml); the namespace opts in later, in step 07"
apply_file "${REPO_ROOT}/ambient/waypoint.yaml"
k -n payments-ambient wait --for=condition=Programmed gateway/waypoint --timeout=180s
k -n payments-ambient rollout status deploy/waypoint --timeout=180s
k label ns payments-ambient istio.io/use-waypoint- >/dev/null 2>&1 || true
k get pods -A -o wide | grep -E '^(payments|payments-ambient|legacy) '

step "Checks"
expect_eq "istiod ready" "1" "$(k -n istio-system get deploy istiod -o jsonpath='{.status.readyReplicas}')"
nodes="$(k get nodes --no-headers | wc -l | tr -d ' ')"
expect_eq "one ztunnel per node" "${nodes}" "$(k -n istio-system get ds ztunnel -o jsonpath='{.status.numberReady}')"
expect_eq "Gateway API CRDs from bundle ${GATEWAY_API_VERSION}, standard" "${GATEWAY_API_VERSION}/standard" \
  "$(k get crd httproutes.gateway.networking.k8s.io -o jsonpath='{.metadata.annotations.gateway\.networking\.k8s\.io/bundle-version}/{.metadata.annotations.gateway\.networking\.k8s\.io/channel}')"
for d in prometheus kiali; do
  expect_eq "addon ${d} ready" "1" "$(k -n istio-system get deploy "${d}" -o jsonpath='{.status.readyReplicas}')"
done
# The kubelet refreshes the mounted ConfigMap with a delay; the reloader then reloads.
wait_for 240 "$(alert_rule_names)" loaded_alert_rules || true
expect_eq "Prometheus loaded the alert rules of observability/alerts.yaml" "$(alert_rule_names)" "$(loaded_alert_rules)"
expect_eq "no PeerAuthentication anywhere (mesh-wide mode unset = PERMISSIVE)" "0" \
  "$(k get peerauthentication -A --no-headers 2>/dev/null | wc -l | tr -d ' ')"
expect_eq "no AuthorizationPolicy anywhere (allow all)" "0" \
  "$(k get authorizationpolicy -A --no-headers 2>/dev/null | wc -l | tr -d ' ')"
expect_eq "payments-api (sidecar ns) runs app + load + istio-proxy" "app,load,istio-proxy" \
  "$(k -n payments get pod -l app=payments-api -o json | jq -r '.items[0] | [(.spec.initContainers[] | select(.name == "istio-proxy") | .name), .spec.containers[].name] | sort_by(. == "istio-proxy") | join(",")')"
expect_eq "fraud-check (sidecar ns): 2 ready replicas" "2" "$(k -n payments get deploy fraud-check -o jsonpath='{.status.readyReplicas}')"
expect_eq "fraud-check (ambient ns): 2 ready replicas" "2" "$(k -n payments-ambient get deploy fraud-check -o jsonpath='{.status.readyReplicas}')"
expect_eq "settlement-batch (legacy) has no proxy" "app" \
  "$(k -n legacy get pod -l app=settlement-batch -o json | jq -r '.items[0] | [(.spec.initContainers // [])[].name, .spec.containers[].name] | join(",")')"
expect_eq "ambient payments-api has no injected proxy" "app,load" \
  "$(k -n payments-ambient get pod -l app=payments-api -o jsonpath='{.items[0].spec.containers[*].name}' | tr ' ' ',')"
expect_eq "payments-ambient does not use the waypoint yet" "" \
  "$(k get ns payments-ambient -o jsonpath='{.metadata.labels.istio\.io/use-waypoint}')"
# istioctl talks XDS to istiod for proxy-status. Since Istio 1.31.2 it verifies
# istiod's certificate against the root in the istio-ca-root-cert ConfigMap
# and the expected server name (istiod.istio-system.svc over a port-forward);
# --insecure or ISTIOCTL_INSECURE=true would skip that, and the lab uses neither.
ps_out="$(env -u ISTIOCTL_INSECURE istioctl --context "${KUBE_CONTEXT}" proxy-status 2>&1 || true)"
expect_eq "istioctl proxy-status, no --insecure: 4 sidecars + the waypoint + ${nodes} ztunnels, all on ${ISTIO_VERSION}" "$((5 + nodes))" \
  "$(awk -v v="${ISTIO_VERSION}" 'NR > 1 && $4 == v' <<< "${ps_out}" | wc -l | tr -d ' ')"
ps_out="$(env -u ISTIOCTL_INSECURE istioctl --context "${KUBE_CONTEXT}" proxy-status --authority wrong.example.com 2>&1 || true)"
expect_match "and it does verify: a wrong --authority fails the TLS handshake" \
  'failed to verify certificate: x509: certificate is valid for .*istiod\.istio-system\.svc, not wrong\.example\.com' "${ps_out}"
r="$(req payments payments-api http://fraud-check:8080/warmup)"
expect_eq "payments-api -> fraud-check (sidecar)" "200 0" "${r}"
r="$(req payments-ambient payments-api http://fraud-check:8080/warmup)"
expect_eq "payments-api -> fraud-check (ambient)" "200 0" "${r}"
r="$(req legacy settlement-batch http://fraud-check.payments:8080/warmup)"
expect_eq "legacy settlement-batch -> fraud-check (plain text)" "200 0" "${r}"
finish
