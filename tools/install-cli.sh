#!/usr/bin/env bash
# Downloads the pinned CLIs used by the lab into ./bin (gitignored).
# Idempotent: a binary is only downloaded when missing or at another version.
# Supports darwin/linux on arm64/amd64. No sudo, nothing outside ./bin.
set -euo pipefail

ISTIO_VERSION="1.31.2"
KUBECTL_VERSION="v1.36.1"      # matches the kind v0.32.0 default node image
YQ_VERSION="v4.54.1"           # mikefarah/yq, used by ci/resilience-lint.sh
PROMTOOL_VERSION="3.10.0"      # same as the Prometheus of the Istio 1.31.2 addons

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${REPO_ROOT}/bin"
mkdir -p "${BIN}"

case "$(uname -s)" in
  Darwin) OS="darwin"; ISTIO_OS="osx" ;;
  Linux)  OS="linux";  ISTIO_OS="linux" ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  arm64|aarch64) ARCH="arm64" ;;
  x86_64|amd64)  ARCH="amd64" ;;
  *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

have_version() { # $1 binary, $2 expected substring of "version" output, rest: version args
  local out
  [ -x "${BIN}/$1" ] || return 1
  out="$("${BIN}/$1" "${@:3}" 2>/dev/null)" || return 1
  [[ "${out}" == *"$2"* ]]
}

if have_version istioctl "${ISTIO_VERSION}" version --remote=false; then
  echo "istioctl ${ISTIO_VERSION} already in bin/"
else
  echo "downloading istioctl ${ISTIO_VERSION} (${ISTIO_OS}-${ARCH})"
  tmp="$(mktemp -d)"
  base="https://github.com/istio/istio/releases/download/${ISTIO_VERSION}"
  pkg="istioctl-${ISTIO_VERSION}-${ISTIO_OS}-${ARCH}.tar.gz"
  curl -sSfL "${base}/${pkg}" -o "${tmp}/istioctl.tgz"
  # The release publishes "<sha256> <file name>" next to each archive.
  curl -sSfL "${base}/${pkg}.sha256" -o "${tmp}/istioctl.sha256"
  want="$(awk -v f="${pkg}" '$2 == f { print $1 }' "${tmp}/istioctl.sha256")"
  got="$(shasum -a 256 "${tmp}/istioctl.tgz" 2>/dev/null || sha256sum "${tmp}/istioctl.tgz")"
  got="${got%% *}"
  if [ -z "${want}" ] || [ "${want}" != "${got}" ]; then
    echo "istioctl checksum mismatch (want ${want:-none}, got ${got})" >&2
    rm -rf "${tmp}"; exit 1
  fi
  tar -xzf "${tmp}/istioctl.tgz" -C "${tmp}" istioctl
  mv "${tmp}/istioctl" "${BIN}/istioctl"
  chmod +x "${BIN}/istioctl"
  rm -rf "${tmp}"
fi

if have_version kubectl "${KUBECTL_VERSION}" version --client; then
  echo "kubectl ${KUBECTL_VERSION} already in bin/"
else
  echo "downloading kubectl ${KUBECTL_VERSION} (${OS}/${ARCH})"
  curl -sSfL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/${OS}/${ARCH}/kubectl" -o "${BIN}/kubectl"
  chmod +x "${BIN}/kubectl"
fi

if have_version yq "${YQ_VERSION}" --version; then
  echo "yq ${YQ_VERSION} already in bin/"
else
  echo "downloading yq ${YQ_VERSION} (${OS}_${ARCH})"
  tmp="$(mktemp -d)"
  base="https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}"
  curl -sSfL "${base}/yq_${OS}_${ARCH}" -o "${tmp}/yq"
  curl -sSfL "${base}/checksums" -o "${tmp}/checksums"
  # The checksums file lists many hashes per binary; SHA-256 is the 18th
  # (see checksums_hashes_order in the release), i.e. field 19 after the name.
  want="$(awk -v f="yq_${OS}_${ARCH}" '$1 == f { print $19 }' "${tmp}/checksums")"
  got="$(shasum -a 256 "${tmp}/yq" 2>/dev/null || sha256sum "${tmp}/yq")"
  got="${got%% *}"
  if [ -z "${want}" ] || [ "${want}" != "${got}" ]; then
    echo "yq checksum mismatch (want ${want:-none}, got ${got})" >&2
    rm -rf "${tmp}"; exit 1
  fi
  mv "${tmp}/yq" "${BIN}/yq"
  chmod +x "${BIN}/yq"
  rm -rf "${tmp}"
fi

if have_version promtool "${PROMTOOL_VERSION}" --version; then
  echo "promtool ${PROMTOOL_VERSION} already in bin/"
else
  echo "downloading promtool ${PROMTOOL_VERSION} (${OS}-${ARCH})"
  tmp="$(mktemp -d)"
  base="https://github.com/prometheus/prometheus/releases/download/v${PROMTOOL_VERSION}"
  pkg="prometheus-${PROMTOOL_VERSION}.${OS}-${ARCH}"
  curl -sSfL "${base}/${pkg}.tar.gz" -o "${tmp}/${pkg}.tar.gz"
  curl -sSfL "${base}/sha256sums.txt" -o "${tmp}/sha256sums.txt"
  want="$(awk -v f="${pkg}.tar.gz" '$2 == f { print $1 }' "${tmp}/sha256sums.txt")"
  got="$(shasum -a 256 "${tmp}/${pkg}.tar.gz" 2>/dev/null || sha256sum "${tmp}/${pkg}.tar.gz")"
  got="${got%% *}"
  if [ -z "${want}" ] || [ "${want}" != "${got}" ]; then
    echo "promtool checksum mismatch (want ${want:-none}, got ${got})" >&2
    rm -rf "${tmp}"; exit 1
  fi
  tar -xzf "${tmp}/${pkg}.tar.gz" -C "${tmp}" "${pkg}/promtool"
  mv "${tmp}/${pkg}/promtool" "${BIN}/promtool"
  chmod +x "${BIN}/promtool"
  rm -rf "${tmp}"
fi

echo "binaries in ${BIN}:"
"${BIN}/istioctl" version --remote=false
"${BIN}/kubectl" version --client | sed -n 1p
"${BIN}/yq" --version
"${BIN}/promtool" --version | sed -n 1p
