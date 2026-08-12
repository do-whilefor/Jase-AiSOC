#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 2 ]] || { echo "usage: $0 RELEASE_DIR PRIVATE_KEY_PEM" >&2; exit 2; }
release="$1"; key="$2"
[[ -d "$release" && ! -L "$release" ]] || { echo "invalid release directory" >&2; exit 1; }
[[ -f "$release/manifest.sha256" && ! -L "$release/manifest.sha256" ]] || { echo "missing manifest.sha256" >&2; exit 1; }
[[ -f "$key" && ! -L "$key" ]] || { echo "invalid private key" >&2; exit 1; }
(
  cd "$release"
  sha256sum --check --strict manifest.sha256
)
openssl dgst -sha256 -sign "$key" -out "$release/manifest.sha256.sig" "$release/manifest.sha256"
printf 'signed %s\n' "$release/manifest.sha256"
