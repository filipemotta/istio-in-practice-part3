#!/usr/bin/env bash
# Offline tests of the generators the lab uses (no cluster):
#   tools/gen-jwt.sh      the JWKS holds the issuer's public key; valid.jwt
#                         verifies with it, forged.jwt does not; claims as
#                         documented (iss, sub, aud, exp);
#   tools/gen-tls-cert.sh the server certificate verifies against the CA and
#                         carries the SAN api.payments.example;
#   mtls/plaintext-inventory.sh  exit codes against canned Prometheus answers
#                         (a stub kubectl): 1 with a plain-text caller, 0 when
#                         every caller used mTLS, 2 on an empty window.
# Everything is generated in a temporary directory and removed.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

PASSED=0
FAILED=0
pass() { PASSED=$((PASSED + 1)); printf '    [PASS] %s\n' "$1"; }
fail() { FAILED=$((FAILED + 1)); printf '    [FAIL] %s\n' "$1"; }
expect_eq() { if [ "$2" = "$3" ]; then pass "$1 (got $3)"; else fail "$1 (expected $2, got $3)"; fi; }

# b64url_decode: standard input (base64url, no padding) -> bytes
b64url_decode() { tr '_-' '/+' | awk '{ while (length($0) % 4) $0 = $0 "="; print }' | openssl base64 -d -A; }
# verify <token> <public key PEM file> -> "ok" or "bad"
verify() {
  local t="$1"
  printf '%s' "${t%.*}" > "${TMP}/signed"
  printf '%s' "${t##*.}" | b64url_decode > "${TMP}/sig"
  if openssl dgst -sha256 -verify "$2" -signature "${TMP}/sig" "${TMP}/signed" >/dev/null 2>&1; then echo ok; else echo bad; fi
}

echo "==> tools/gen-jwt.sh"
bash "${REPO_ROOT}/tools/gen-jwt.sh" "${TMP}/jwt" >/dev/null
openssl rsa -in "${TMP}/jwt/issuer.key" -pubout -out "${TMP}/issuer.pub" 2>/dev/null
# The public key rebuilt from the JWKS (n, e) must be the issuer's.
n_hex="$(jq -r '.keys[0].n' "${TMP}/jwt/jwks.json" | b64url_decode | od -An -v -tx1 | tr -d ' \n' | tr 'a-f' 'A-F')"
mod_hex="$(openssl rsa -in "${TMP}/jwt/issuer.key" -noout -modulus 2>/dev/null | sed 's/^Modulus=//')"
expect_eq "JWKS n = modulus of issuer.key (2048 bits, compared as hex)" "512 $(cut -c1-16 <<< "${mod_hex}")" \
  "${#n_hex} $(cut -c1-16 <<< "${n_hex}")"
if [ "${n_hex}" = "${mod_hex}" ]; then pass "all 512 hex digits equal"; else fail "JWKS n differs from the modulus"; fi
expect_eq "JWKS e, kid, alg" "AQAB payments-lab-1 RS256" "$(jq -r '.keys[0] | "\(.e) \(.kid) \(.alg)"' "${TMP}/jwt/jwks.json")"
expect_eq "valid.jwt verifies with the issuer key" "ok" "$(verify "$(cat "${TMP}/jwt/valid.jwt")" "${TMP}/issuer.pub")"
expect_eq "forged.jwt does not" "bad" "$(verify "$(cat "${TMP}/jwt/forged.jwt")" "${TMP}/issuer.pub")"
claims="$(cut -d. -f2 "${TMP}/jwt/valid.jwt" | b64url_decode)"
expect_eq "claims of valid.jwt" "https://issuer.payments.example checkout-web payments-api" "$(jq -r '"\(.iss) \(.sub) \(.aud)"' <<< "${claims}")"
now="$(date +%s)"
expect_eq "valid.jwt expires in 10 years" "10" "$(jq -r --argjson now "${now}" '((.exp - $now) / 31536000) | round' <<< "${claims}")"
expect_eq "expired.jwt is in the past" "true" "$(cut -d. -f2 "${TMP}/jwt/expired.jwt" | b64url_decode | jq --argjson now "${now}" '.exp < $now')"
expect_eq "wrong-issuer.jwt has another iss" "https://issuer.attacker.example" "$(cut -d. -f2 "${TMP}/jwt/wrong-issuer.jwt" | b64url_decode | jq -r .iss)"

echo "==> tools/gen-tls-cert.sh"
bash "${REPO_ROOT}/tools/gen-tls-cert.sh" "${TMP}/tls" >/dev/null
expect_eq "server.crt verifies against ca.crt" "${TMP}/tls/server.crt: OK" "$(openssl verify -CAfile "${TMP}/tls/ca.crt" "${TMP}/tls/server.crt" 2>&1)"
expect_eq "SAN" "DNS:api.payments.example" "$(openssl x509 -in "${TMP}/tls/server.crt" -noout -ext subjectAltName | sed -n 's/^ *//; /^DNS:/p')"
expect_eq "the key matches the certificate" \
  "$(openssl x509 -in "${TMP}/tls/server.crt" -noout -pubkey | openssl sha256)" \
  "$(openssl pkey -in "${TMP}/tls/server.key" -pubout | openssl sha256)"

echo "==> mtls/plaintext-inventory.sh (stub kubectl, canned Prometheus answers)"
mkdir -p "${TMP}/stub"
cat > "${TMP}/stub/kubectl" <<'EOF'
#!/usr/bin/env bash
cat "${PROM_FIXTURE}"
EOF
chmod +x "${TMP}/stub/kubectl"
row() { printf '{"metric":{"connection_security_policy":"%s","source_workload_namespace":"%s","source_workload":"%s","destination_workload":"fraud-check","source_principal":"%s"},"value":[0,"10"]}' "$@"; }
mtls_row="$(row mutual_tls payments payments-api spiffe://cluster.local/ns/payments/sa/payments-api)"
plain_row="$(row none legacy settlement-batch unknown)"
inventory_rc() {
  printf '{"status":"success","data":{"resultType":"vector","result":[%s]}}' "$1" > "${TMP}/prom.json"
  PROM_FIXTURE="${TMP}/prom.json" PATH="${TMP}/stub:${PATH}" bash "${REPO_ROOT}/mtls/plaintext-inventory.sh" payments >/dev/null
  echo $?
}
expect_eq "a plain-text caller in the window: exit 1 (not ready)" "1" "$(inventory_rc "${mtls_row},${plain_row}")"
expect_eq "every caller used mTLS: exit 0 (ready)" "0" "$(inventory_rc "${mtls_row}")"
expect_eq "no requests in the window: exit 2 (nothing to judge, not ready)" "2" "$(inventory_rc "")"

printf '\n    result: %s passed, %s failed\n' "${PASSED}" "${FAILED}"
[ "${FAILED}" -eq 0 ]
