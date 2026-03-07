#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="emrystech"
REPO_NAME="secryn-cli"
BINARY_NAME="secryn"

usage() {
  cat <<'USAGE'
Usage: install.sh [--version vX.Y.Z]

Installs the secryn CLI from GitHub Releases.
USAGE
}

fail() {
  echo "Error: $*" >&2
  exit 1
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "required command not found: $1"
  fi
}

VERSION=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      shift
      [[ $# -gt 0 ]] || fail "--version requires a value"
      VERSION="$1"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
  shift
done

if [[ -n "$VERSION" && "${VERSION#v}" == "$VERSION" ]]; then
  fail "version must be prefixed with v (example: v1.0.0)"
fi

case "$(uname -s)" in
  Linux)
    OS="linux"
    ;;
  Darwin)
    OS="darwin"
    ;;
  *)
    echo "Unsupported platform. This install script supports Linux and macOS only."
    echo "Download binaries manually from https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64|amd64)
    ARCH="amd64"
    ;;
  arm64|aarch64)
    ARCH="arm64"
    ;;
  *)
    echo "Unsupported architecture: $(uname -m)"
    echo "Download binaries manually from https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
    exit 1
    ;;
esac

require_cmd curl
require_cmd tar

ARCHIVE_NAME="${BINARY_NAME}_${OS}_${ARCH}.tar.gz"
RELEASE_BASE="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
if [[ -n "$VERSION" ]]; then
  DOWNLOAD_BASE="${RELEASE_BASE}/download/${VERSION}"
  DISPLAY_VERSION="$VERSION"
else
  DOWNLOAD_BASE="${RELEASE_BASE}/latest/download"
  DISPLAY_VERSION="latest"
fi

ARCHIVE_URL="${DOWNLOAD_BASE}/${ARCHIVE_NAME}"
CHECKSUM_URL="${DOWNLOAD_BASE}/checksums.txt"

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

ARCHIVE_PATH="${TMP_DIR}/${ARCHIVE_NAME}"
CHECKSUM_PATH="${TMP_DIR}/checksums.txt"

download() {
  local url="$1"
  local output="$2"
  curl -fsSL --retry 3 --retry-delay 1 --connect-timeout 15 "$url" -o "$output"
}

echo "Downloading secryn (${DISPLAY_VERSION}) for ${OS}/${ARCH}..."
download "$ARCHIVE_URL" "$ARCHIVE_PATH"
download "$CHECKSUM_URL" "$CHECKSUM_PATH"

verify_checksum() {
  local expected
  expected="$(awk -v file="$ARCHIVE_NAME" '$2 == file || $2 == "*" file {print $1; exit}' "$CHECKSUM_PATH")"
  if [[ -z "$expected" ]]; then
    fail "checksum entry not found for ${ARCHIVE_NAME}"
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s  %s\n' "$expected" "$ARCHIVE_PATH" | sha256sum --check --status
  elif command -v shasum >/dev/null 2>&1; then
    local actual
    actual="$(shasum -a 256 "$ARCHIVE_PATH" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]] || fail "checksum verification failed"
  elif command -v openssl >/dev/null 2>&1; then
    local actual
    actual="$(openssl dgst -sha256 "$ARCHIVE_PATH" | awk '{print $2}')"
    [[ "$actual" == "$expected" ]] || fail "checksum verification failed"
  else
    echo "Warning: no checksum tool found (sha256sum, shasum, openssl). Skipping checksum verification."
    return
  fi

  echo "Checksum verified"
}

verify_checksum

tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR"

BINARY_PATH="$(find "$TMP_DIR" -type f -name "$BINARY_NAME" | head -n 1 || true)"
[[ -n "$BINARY_PATH" ]] || fail "could not find extracted ${BINARY_NAME} binary"
chmod +x "$BINARY_PATH"

if [[ -d /usr/local/bin && -w /usr/local/bin ]]; then
  INSTALL_DIR="/usr/local/bin"
else
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

TARGET_PATH="${INSTALL_DIR}/${BINARY_NAME}"
if command -v install >/dev/null 2>&1; then
  install -m 0755 "$BINARY_PATH" "$TARGET_PATH"
else
  cp "$BINARY_PATH" "$TARGET_PATH"
  chmod 0755 "$TARGET_PATH"
fi

echo "Installed ${BINARY_NAME} to ${TARGET_PATH}"
if ! command -v "$BINARY_NAME" >/dev/null 2>&1; then
  echo "Add ${INSTALL_DIR} to your PATH:"
  echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
fi
echo "Run '${BINARY_NAME} --version' to verify installation."
