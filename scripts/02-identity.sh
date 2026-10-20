#!/usr/bin/env bash
# Step 2: where a workload's identity comes from. istiod is the CA; the
# istio-agent of each sidecar (and ztunnel, for ambient pods) asks it for a
# certificate for the pod's ServiceAccount and hands it to the proxy over
# SDS. The identity is the SPIFFE URI in the certificate's SAN.
# Read-only: nothing is applied.
set -euo pipefail
# shellcheck source=/dev/null
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
assert_lab_context

NS="payments"
# secret_pem <ns> <deployment> <secret name: default|ROOTCA> -> PEM of the
# certificate the proxy is using (istioctl proxy-config secret)
secret_pem() {
  local path
  if [ "$3" = "ROOTCA" ]; then
    path='.secret.validationContext.trustedCa.inlineBytes'
  else
    path='.secret.tlsCertificate.certificateChain.inlineBytes'
  fi
  ictl proxy-config secret "deploy/$2" -n "$1" -o json \
    | jq -r --arg n "$3" --arg p "${path}" '.dynamicActiveSecrets[] | select(.name == $n) | getpath($p | ltrimstr(".") | split("."))' \
    | openssl base64 -d -A
}
# epoch <openssl date, e.g. "Oct 15 20:39:55 2026 GMT"> -> seconds since 1970
# (jq instead of date: BSD and GNU date parse dates differently)
epoch() {
  jq -rn --arg d "$1" '$d | gsub(" +"; " ") | strptime("%b %d %H:%M:%S %Y GMT") | mktime'
}
# lifetime <PEM> -> notAfter - notBefore, in seconds
lifetime() {
  local nb na
  nb="$(openssl x509 -noout -startdate <<< "$1" | cut -d= -f2)"
  na="$(openssl x509 -noout -enddate <<< "$1" | cut -d= -f2)"
  echo $(( $(epoch "${na}") - $(epoch "${nb}") ))
}
fingerprint() { openssl x509 -noout -fingerprint -sha256 <<< "$1" | cut -d= -f2; }

step "The certificates in payments-api's sidecar (istioctl proxy-config secret)"
ictl proxy-config secret deploy/payments-api -n "${NS}" | sed 's/^/    /'
summary="$(ictl proxy-config secret deploy/payments-api -n "${NS}")"
expect_match "workload certificate 'default' is ACTIVE and valid" '^default +Cert Chain +ACTIVE +true ' "${summary}"
expect_match "trust anchor 'ROOTCA' is ACTIVE and valid" '^ROOTCA +CA +ACTIVE +true ' "${summary}"

step "The identity is the SPIFFE URI in the SAN; the subject is empty"
cert="$(secret_pem "${NS}" payments-api default)"
openssl x509 -noout -subject -issuer -dates -ext subjectAltName <<< "${cert}" | sed 's/^/    /'
expect_eq "SAN URI of payments-api" "URI:spiffe://cluster.local/ns/payments/sa/payments-api" \
  "$(openssl x509 -noout -ext subjectAltName <<< "${cert}" | sed -n 's/^ *//; /^URI:/p')"
# LibreSSL (macOS) prints "issuer=O=cluster.local", OpenSSL 3 "issuer=O = cluster.local".
expect_eq "issued by the mesh CA (O=cluster.local)" "issuer=O=cluster.local" "$(openssl x509 -noout -issuer <<< "${cert}" | tr -d ' ')"
for w in fraud-check risk-score; do
  expect_eq "SAN URI of ${w}: its own ServiceAccount" "URI:spiffe://cluster.local/ns/payments/sa/${w}" \
    "$(secret_pem "${NS}" "${w}" default | openssl x509 -noout -ext subjectAltName | sed -n 's/^ *//; /^URI:/p')"
done

step "Lifetime: 24h by default (SECRET_TTL of the agent, DEFAULT_WORKLOAD_CERT_TTL of istiod)"
lt="$(lifetime "${cert}")"
note "notAfter - notBefore = ${lt}s ($((lt / 3600))h$(((lt % 3600) / 60))m): 24h TTL + notBefore set 2 minutes in the past by istiod (clock skew grace)"
expect_eq "certificate validity span in seconds (24h + 2m)" "86520" "${lt}"
expect_eq "the proxy runs with the default SECRET_TTL (no override in the pod)" "" \
  "$(k -n "${NS}" get pod -l app=payments-api -o json | jq -r '.items[0].spec.initContainers[] | select(.name == "istio-proxy") | .env[] | select(.name == "SECRET_TTL") | .value')"
na="$(epoch "$(openssl x509 -noout -enddate <<< "${cert}" | cut -d= -f2)")"
left=$(( (na - $(date +%s)) / 60 ))
expect_between "minutes of validity left (the agent rotates at half-life, ~12h)" 720 1442 "${left}"

step "Trust anchor: the same self-signed root everywhere"
root="$(secret_pem "${NS}" payments-api ROOTCA)"
ca="$(k -n istio-system get secret istio-ca-secret -o jsonpath='{.data.ca-cert\.pem}' | openssl base64 -d -A)"
cm="$(k -n "${NS}" get configmap istio-ca-root-cert -o jsonpath='{.data.root-cert\.pem}')"
openssl x509 -noout -subject -dates <<< "${root}" | sed 's/^/    /'
note "sha256 $(fingerprint "${root}")"
expect_eq "ROOTCA in the proxy = ca-cert.pem of istio-system/istio-ca-secret (istiod's self-signed CA)" \
  "$(fingerprint "${ca}")" "$(fingerprint "${root}")"
expect_eq "= istio-ca-root-cert ConfigMap published in the namespace" "$(fingerprint "${cm}")" "$(fingerprint "${root}")"
expect_eq "root validity span: 3650 days (CITADEL_SELF_SIGNED_CA_CERT_TTL 87600h)" "315360000" "$(lifetime "${root}")"
openssl verify -CAfile <(printf '%s\n' "${root}") <(printf '%s\n' "${cert}") >/dev/null 2>&1 && v=ok || v=failed
expect_eq "the workload certificate verifies against that root" "ok" "${v}"

step "Ambient: no sidecar, ztunnel holds the certificate of each pod on its node"
node="$(k -n payments-ambient get pod -l app=payments-api -o jsonpath='{.items[0].spec.nodeName}')"
zt="$(k -n istio-system get pod -l app=ztunnel --field-selector "spec.nodeName=${node}" -o jsonpath='{.items[0].metadata.name}')"
ictl ztunnel-config certificate "${zt}.istio-system" | grep -E 'NAME|payments-ambient' | sed 's/^/    /'
zcert="$(ictl ztunnel-config certificate "${zt}.istio-system" -o json \
  | jq -r '.[] | select(.identity == "spiffe://cluster.local/ns/payments-ambient/sa/payments-api") | .certChain[0].pem' \
  | openssl base64 -d -A 2>/dev/null || true)"
expect_eq "ztunnel on ${node} has payments-ambient/payments-api's certificate" \
  "URI:spiffe://cluster.local/ns/payments-ambient/sa/payments-api" \
  "$(openssl x509 -noout -ext subjectAltName <<< "${zcert}" 2>/dev/null | sed -n 's/^ *//; /^URI:/p')"
expect_eq "signed by the same root" "ok" \
  "$(openssl verify -CAfile <(printf '%s\n' "${root}") <(printf '%s\n' "${zcert}") >/dev/null 2>&1 && echo ok || echo failed)"
expect_eq "same 24h policy" "86520" "$(lifetime "${zcert}")"

step "legacy/settlement-batch: no proxy, so no certificate and no identity"
expect_eq "settlement-batch has no istio-proxy container" "0" \
  "$(k -n legacy get pod -l app=settlement-batch -o json | jq '[.items[0].spec.containers[].name, (.items[0].spec.initContainers // [])[].name] | map(select(. == "istio-proxy")) | length')"
finish
