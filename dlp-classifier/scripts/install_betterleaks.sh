#!/usr/bin/env bash
# Installs the BetterLeaks binary used by app/service/deterministic/credentials.py.
# Source: https://github.com/betterleaks/betterleaks
set -euo pipefail

REPO="betterleaks/betterleaks"
# Pinned so builds are reproducible — bump deliberately, don't track "latest".
VERSION="${BETTERLEAKS_VERSION:-1.6.1}"
INSTALL_DIR="${BETTERLEAKS_INSTALL_DIR:-/usr/local/bin}"
INSTALL_PATH="${INSTALL_DIR}/betterleaks"

case "$(uname -s)" in
    Linux) os="linux" ;;
    Darwin) os="darwin" ;;
    *) echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
    x86_64|amd64) arch="x64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

echo "Installing BetterLeaks v${VERSION}..."

archive="betterleaks_${VERSION}_${os}_${arch}.tar.gz"
base_url="https://github.com/${REPO}/releases/download/v${VERSION}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

echo "Downloading ${archive}..."
curl -fsSL "${base_url}/${archive}" -o "${tmp_dir}/${archive}"
curl -fsSL "${base_url}/checksums.txt" -o "${tmp_dir}/checksums.txt"

echo "Verifying checksum..."
(cd "${tmp_dir}" && grep " ${archive}\$" checksums.txt | sha256sum -c -)

echo "Extracting..."
tar -xzf "${tmp_dir}/${archive}" -C "${tmp_dir}"

echo "Installing to ${INSTALL_PATH}..."
if [ "$(id -u)" -eq 0 ]; then
    install -m 0755 "${tmp_dir}/betterleaks" "${INSTALL_PATH}"
else
    sudo install -m 0755 "${tmp_dir}/betterleaks" "${INSTALL_PATH}"
fi

echo "Verifying install..."
"${INSTALL_PATH}" version

echo "BetterLeaks v${VERSION} installed at ${INSTALL_PATH}"
