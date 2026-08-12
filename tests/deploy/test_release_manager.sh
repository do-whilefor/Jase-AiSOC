#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
MANAGER="$ROOT/deploy/linux/release-manager.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

make_release() {
  local version="$1"
  mkdir -p "$TMP/$version/bin"
  local binary
  for binary in aisoc-agent aisoc-ingest aisoc-api aisoc-console aisoc-web-guard aisoc-db; do
    printf '#!/bin/sh\necho %s-%s\n' "$binary" "$version" > "$TMP/$version/bin/$binary"
    chmod +x "$TMP/$version/bin/$binary"
  done
  printf '%s\n' "$version" > "$TMP/$version/VERSION"
  (cd "$TMP/$version" && sha256sum bin/* > manifest.sha256)
}

make_release v1
make_release v2
AISOC_INSTALL_PREFIX="$TMP/install" AISOC_ENVIRONMENT=development "$MANAGER" install "$TMP/v1" v1
[[ "$(readlink -f "$TMP/install/current")" == "$TMP/install/releases/v1" ]]
AISOC_INSTALL_PREFIX="$TMP/install" AISOC_ENVIRONMENT=development "$MANAGER" install "$TMP/v2" v2
[[ "$(readlink -f "$TMP/install/current")" == "$TMP/install/releases/v2" ]]
[[ "$(readlink -f "$TMP/install/previous")" == "$TMP/install/releases/v1" ]]
AISOC_INSTALL_PREFIX="$TMP/install" AISOC_ENVIRONMENT=development "$MANAGER" rollback
[[ "$(readlink -f "$TMP/install/current")" == "$TMP/install/releases/v1" ]]
[[ "$(readlink -f "$TMP/install/previous")" == "$TMP/install/releases/v2" ]]

printf 'tamper\n' >> "$TMP/v2/bin/aisoc-api"
if AISOC_INSTALL_PREFIX="$TMP/tampered" AISOC_ENVIRONMENT=development \
  "$MANAGER" install "$TMP/v2" tampered >/dev/null 2>&1; then
  echo "tampered release was accepted" >&2
  exit 1
fi

make_release signed
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TMP/signing.pem" >/dev/null 2>&1
openssl pkey -in "$TMP/signing.pem" -pubout -out "$TMP/verify.pem" >/dev/null 2>&1
"$ROOT/scripts/sign-rust-release.sh" "$TMP/signed" "$TMP/signing.pem" >/dev/null
AISOC_INSTALL_PREFIX="$TMP/signed-install" AISOC_ENVIRONMENT=production \
  AISOC_RELEASE_VERIFY_KEY="$TMP/verify.pem" "$MANAGER" install "$TMP/signed" signed

make_release unsigned
if AISOC_INSTALL_PREFIX="$TMP/unsigned-install" AISOC_ENVIRONMENT=production \
  AISOC_RELEASE_VERIFY_KEY="$TMP/verify.pem" "$MANAGER" install "$TMP/unsigned" unsigned >/dev/null 2>&1; then
  echo "unsigned production release was accepted" >&2
  exit 1
fi

printf 'release manager deployment tests: PASS\n'
