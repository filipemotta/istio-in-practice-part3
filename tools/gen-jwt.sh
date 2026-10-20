#!/usr/bin/env bash
# Generates a local JWT issuer for the lab, with openssl only (no network, no
# third-party token service, nothing that expires under you):
#   <dir>/issuer.key        RSA 2048 private key (stays on your machine)
#   <dir>/jwks.json         the public key as a JWKS, inlined in the
#                           RequestAuthentication by scripts/05-jwt.sh
#   <dir>/valid.jwt         RS256, iss/sub/aud as below, exp = now + 10 years
#   <dir>/expired.jwt       same claims, exp in the past
#   <dir>/wrong-issuer.jwt  same key, another iss
#   <dir>/forged.jwt        same claims and kid, signed by another key
# Usage: tools/gen-jwt.sh [dir]   (default: out/jwt)
# A new key pair is generated only if <dir>/issuer.key is missing; tokens are
# re-signed on every run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${1:-${REPO_ROOT}/out/jwt}"
ISSUER="https://issuer.payments.example"
SUBJECT="checkout-web"
AUDIENCE="payments-api"
KID="payments-lab-1"
mkdir -p "${DIR}"

# b64url: standard input -> base64url without padding, one line
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

if [ ! -f "${DIR}/issuer.key" ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${DIR}/issuer.key" 2>/dev/null
fi
if [ ! -f "${DIR}/forger.key" ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${DIR}/forger.key" 2>/dev/null
fi
chmod 600 "${DIR}/issuer.key" "${DIR}/forger.key"

# JWKS: modulus n (big-endian bytes) and exponent e, both base64url.
modulus_hex="$(openssl rsa -in "${DIR}/issuer.key" -noout -modulus 2>/dev/null | sed 's/^Modulus=//')"
# hex -> bytes with printf %b ("\xAB" escapes), no xxd needed
# shellcheck disable=SC2001 # a per-pair rewrite, not a single substitution
escaped="$(sed 's/../\\x&/g' <<< "${modulus_hex}")"
n="$(printf '%b' "${escaped}" | b64url)"
exponent="$(openssl rsa -in "${DIR}/issuer.key" -noout -text 2>/dev/null | sed -n 's/^publicExponent: \([0-9]*\) .*/\1/p')"
[ "${exponent}" = "65537" ] || { echo "unexpected RSA exponent: ${exponent}" >&2; exit 1; }
e="AQAB" # 65537
printf '{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":"%s","n":"%s","e":"%s"}]}\n' \
  "${KID}" "${n}" "${e}" > "${DIR}/jwks.json"

# sign <key> <iss> <exp> -> compact JWS (RS256)
sign() {
  local key="$1" iss="$2" exp="$3" now header payload sig
  now="$(date +%s)"
  header="$(printf '{"alg":"RS256","typ":"JWT","kid":"%s"}' "${KID}" | b64url)"
  payload="$(printf '{"iss":"%s","sub":"%s","aud":"%s","iat":%s,"exp":%s}' \
    "${iss}" "${SUBJECT}" "${AUDIENCE}" "${now}" "${exp}" | b64url)"
  sig="$(printf '%s.%s' "${header}" "${payload}" | openssl dgst -sha256 -sign "${key}" -binary | b64url)"
  printf '%s.%s.%s\n' "${header}" "${payload}" "${sig}"
}

now="$(date +%s)"
sign "${DIR}/issuer.key" "${ISSUER}" $((now + 10 * 365 * 24 * 3600)) > "${DIR}/valid.jwt"
sign "${DIR}/issuer.key" "${ISSUER}" $((now - 3600)) > "${DIR}/expired.jwt"
sign "${DIR}/issuer.key" "https://issuer.attacker.example" $((now + 3600)) > "${DIR}/wrong-issuer.jwt"
sign "${DIR}/forger.key" "${ISSUER}" $((now + 3600)) > "${DIR}/forged.jwt"

echo "issuer ${ISSUER}, subject ${SUBJECT}, request principal ${ISSUER}/${SUBJECT}"
echo "files in ${DIR}: issuer.key jwks.json valid.jwt expired.jwt wrong-issuer.jwt forged.jwt"
