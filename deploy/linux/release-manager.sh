#!/usr/bin/env bash
set -euo pipefail

COMMAND="${1:-}"
[[ -n "$COMMAND" ]] && shift || true

PREFIX="${AISOC_INSTALL_PREFIX:-/opt/aisoc}"
RELEASES_DIR="$PREFIX/releases"
CURRENT_LINK="$PREFIX/current"
PREVIOUS_LINK="$PREFIX/previous"
SERVICE_USER="${AISOC_SERVICE_USER:-aisoc}"
SERVICE_GROUP="${AISOC_SERVICE_GROUP:-aisoc}"
ENVIRONMENT="${AISOC_ENVIRONMENT:-development}"
REQUIRE_SIGNATURE="${AISOC_REQUIRE_RELEASE_SIGNATURE:-}"

if [[ -z "$REQUIRE_SIGNATURE" ]]; then
  if [[ "$ENVIRONMENT" == "production" ]]; then REQUIRE_SIGNATURE=1; else REQUIRE_SIGNATURE=0; fi
fi

log() { printf '[aisoc-release] %s\n' "$*"; }
die() { printf '[aisoc-release] error: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
Usage:
  sudo bash deploy/linux/release-manager.sh install RELEASE_DIR [VERSION]
  sudo bash deploy/linux/release-manager.sh rollback
  bash deploy/linux/release-manager.sh status

A release directory must contain:
  bin/aisoc-agent
  bin/aisoc-ingest
  bin/aisoc-api
  bin/aisoc-console
  bin/aisoc-web-guard
  manifest.sha256

manifest.sha256 is verified before installation. In production, a detached
manifest.sha256.sig is also required unless AISOC_REQUIRE_RELEASE_SIGNATURE=0
is explicitly set. Supply AISOC_RELEASE_VERIFY_KEY=/path/to/public.pem to
verify the signature with OpenSSL.
USAGE
}

require_root() { [[ "$EUID" -eq 0 ]] || die "run as root"; }

safe_version() {
  local value="$1"
  [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$ ]] || die "invalid release version: $value"
}

resolve_dir() {
  local value="$1" resolved
  [[ -d "$value" && ! -L "$value" ]] || die "release directory must be a real directory: $value"
  resolved="$(cd "$value" && pwd -P)"
  printf '%s\n' "$resolved"
}

verify_release() {
  local source="$1" manifest="$source/manifest.sha256" binary
  [[ -f "$manifest" && ! -L "$manifest" ]] || die "missing regular manifest.sha256"
  for binary in aisoc-agent aisoc-ingest aisoc-api aisoc-console aisoc-web-guard; do
    [[ -f "$source/bin/$binary" && ! -L "$source/bin/$binary" ]] || die "missing binary: bin/$binary"
    [[ -x "$source/bin/$binary" ]] || die "binary is not executable: bin/$binary"
  done
  (
    cd "$source"
    sha256sum --check --strict manifest.sha256
  ) || die "release checksum verification failed"

  if [[ "$REQUIRE_SIGNATURE" == "1" ]]; then
    local key="${AISOC_RELEASE_VERIFY_KEY:-}" signature="$source/manifest.sha256.sig"
    [[ -n "$key" ]] || die "AISOC_RELEASE_VERIFY_KEY is required when signature verification is enabled"
    [[ -f "$key" && ! -L "$key" ]] || die "release verification key must be a regular file"
    [[ -f "$signature" && ! -L "$signature" ]] || die "missing manifest.sha256.sig"
    command -v openssl >/dev/null 2>&1 || die "openssl is required for release signature verification"
    openssl dgst -sha256 -verify "$key" -signature "$signature" "$manifest" >/dev/null \
      || die "release signature verification failed"
  fi
}

atomic_link() {
  local target="$1" link="$2" tmp
  tmp="${link}.new.$$"
  ln -s "$target" "$tmp"
  mv -Tf "$tmp" "$link"
}

restart_installed_services() {
  command -v systemctl >/dev/null 2>&1 || return 0
  [[ "$(cat /proc/1/comm 2>/dev/null || true)" == "systemd" ]] || return 0
  local unit
  for unit in aisoc-ingest.service aisoc-api.service aisoc-console.service aisoc-web-guard.service aisoc-agent.service; do
    if systemctl is-enabled "$unit" >/dev/null 2>&1 || systemctl is-active "$unit" >/dev/null 2>&1; then
      systemctl try-restart "$unit"
    fi
  done
}

install_release() {
  require_root
  [[ $# -ge 1 && $# -le 2 ]] || { usage >&2; exit 2; }
  local source version target stage old_current=""
  source="$(resolve_dir "$1")"
  version="${2:-}"
  if [[ -z "$version" ]]; then
    if [[ -f "$source/VERSION" && ! -L "$source/VERSION" ]]; then
      version="$(tr -d '\r\n' < "$source/VERSION")"
    else
      version="$(date -u +%Y%m%dT%H%M%SZ)"
    fi
  fi
  safe_version "$version"
  verify_release "$source"

  install -d -m 0755 -o root -g root "$PREFIX" "$RELEASES_DIR"
  target="$RELEASES_DIR/$version"
  [[ ! -e "$target" ]] || die "release already exists: $target"
  stage="$RELEASES_DIR/.${version}.staging.$$"
  trap 'rm -rf -- "$stage"' EXIT
  install -d -m 0755 -o root -g root "$stage/bin"
  local binary
  for binary in aisoc-agent aisoc-ingest aisoc-api aisoc-console aisoc-web-guard; do
    install -m 0755 -o root -g root "$source/bin/$binary" "$stage/bin/$binary"
  done
  install -m 0644 -o root -g root "$source/manifest.sha256" "$stage/manifest.sha256"
  [[ ! -f "$source/manifest.sha256.sig" ]] || install -m 0644 -o root -g root \
    "$source/manifest.sha256.sig" "$stage/manifest.sha256.sig"
  printf '%s\n' "$version" > "$stage/VERSION"
  chmod 0644 "$stage/VERSION"
  mv "$stage" "$target"
  trap - EXIT

  if [[ -L "$CURRENT_LINK" ]]; then old_current="$(readlink -f "$CURRENT_LINK" || true)"; fi
  if [[ -n "$old_current" && -d "$old_current" ]]; then atomic_link "$old_current" "$PREVIOUS_LINK"; fi
  atomic_link "$target" "$CURRENT_LINK"
  restart_installed_services
  log "activated release $version"
}

rollback_release() {
  require_root
  [[ -L "$PREVIOUS_LINK" ]] || die "no previous release is available"
  local previous current=""
  previous="$(readlink -f "$PREVIOUS_LINK")"
  [[ "$previous" == "$RELEASES_DIR/"* && -d "$previous" ]] || die "previous release link is invalid"
  if [[ -L "$CURRENT_LINK" ]]; then current="$(readlink -f "$CURRENT_LINK" || true)"; fi
  atomic_link "$previous" "$CURRENT_LINK"
  if [[ -n "$current" && -d "$current" ]]; then atomic_link "$current" "$PREVIOUS_LINK"; fi
  restart_installed_services
  log "rolled back to $(basename "$previous")"
}

status_release() {
  local current="none" previous="none"
  [[ ! -L "$CURRENT_LINK" ]] || current="$(readlink -f "$CURRENT_LINK" || printf broken)"
  [[ ! -L "$PREVIOUS_LINK" ]] || previous="$(readlink -f "$PREVIOUS_LINK" || printf broken)"
  printf 'current=%s\nprevious=%s\n' "$current" "$previous"
}

case "$COMMAND" in
  install) install_release "$@" ;;
  rollback) [[ $# -eq 0 ]] || { usage >&2; exit 2; }; rollback_release ;;
  status) [[ $# -eq 0 ]] || { usage >&2; exit 2; }; status_release ;;
  -h|--help|help|'') usage ;;
  *) usage >&2; exit 2 ;;
esac
