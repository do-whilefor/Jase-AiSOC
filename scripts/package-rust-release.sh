#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-${AISOC_RELEASE_VERSION:-}}"
OUTPUT_ROOT="${AISOC_RELEASE_OUTPUT_ROOT:-dist/rust-release}"
[[ -n "$VERSION" ]] || {
  if command -v git >/dev/null 2>&1 && git rev-parse --verify HEAD >/dev/null 2>&1; then
    VERSION="$(git rev-parse --short=16 HEAD)"
  else
    VERSION="$(date -u +%Y%m%dT%H%M%SZ)"
  fi
}
[[ "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$ ]] || {
  echo "invalid release version: $VERSION" >&2; exit 1;
}

OUT="$OUTPUT_ROOT/$VERSION"
[[ ! -e "$OUT" ]] || { echo "release output already exists: $OUT" >&2; exit 1; }
install -d -m 0755 "$OUT/bin"
for binary in aisoc-agent aisoc-ingest aisoc-api aisoc-console aisoc-web-guard aisoc-db; do
  source="target/release/$binary"
  [[ -f "$source" && -x "$source" ]] || { echo "missing built release binary: $source" >&2; exit 1; }
  install -m 0755 "$source" "$OUT/bin/$binary"
done
printf '%s\n' "$VERSION" > "$OUT/VERSION"
(
  cd "$OUT"
  sha256sum bin/aisoc-agent bin/aisoc-ingest bin/aisoc-api bin/aisoc-console bin/aisoc-web-guard bin/aisoc-db > manifest.sha256
  sha256sum --check --strict manifest.sha256
)
printf '%s\n' "$OUT"
