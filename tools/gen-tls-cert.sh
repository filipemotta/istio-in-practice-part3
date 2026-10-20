#!/usr/bin/env bash
# Generates a private CA and a server certificate for api.payments.example,
# with openssl only, for the HTTPS listener of the ingress Gateway:
#   <dir>/ca.crt, <dir>/ca.key          self-signed CA (the client trusts it)
#   <dir>/server.crt, <dir>/server.key  leaf for api.payments.example, SAN set
# Usage: tools/gen-tls-cert.sh [dir]   (default: out/tls). Idempotent: keeps
# existing files. Lab only: in production the certificate comes from your PKI
# or cert-manager.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${1:-${REPO_ROOT}/out/tls}"
HOST="api.payments.example"
mkdir -p "${DIR}"

if [ ! -f "${DIR}/ca.crt" ]; then
  openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 \
    -subj "/O=Payments Lab/CN=Payments Lab CA" \
    -keyout "${DIR}/ca.key" -out "${DIR}/ca.crt" 2>/dev/null
fi
if [ ! -f "${DIR}/server.crt" ]; then
  openssl req -nodes -newkey rsa:2048 -subj "/O=Payments Lab/CN=${HOST}" \
    -keyout "${DIR}/server.key" -out "${DIR}/server.csr" 2>/dev/null
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "${HOST}" > "${DIR}/server.ext"
  openssl x509 -req -sha256 -days 365 -CA "${DIR}/ca.crt" -CAkey "${DIR}/ca.key" -set_serial 1 \
    -in "${DIR}/server.csr" -extfile "${DIR}/server.ext" -out "${DIR}/server.crt" 2>/dev/null
  rm -f "${DIR}/server.csr" "${DIR}/server.ext"
fi
chmod 600 "${DIR}/ca.key" "${DIR}/server.key"
openssl verify -CAfile "${DIR}/ca.crt" "${DIR}/server.crt"
