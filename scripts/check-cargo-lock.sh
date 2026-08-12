#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail=0

# This check intentionally does not require Cargo. It catches the common V4
# failure mode where Cargo.toml gains native workspace crates but Cargo.lock is
# left at the older migration baseline. cargo metadata --locked remains the
# authoritative resolver check when the Rust toolchain is available.
default_members="$(awk '
  /^default-members[[:space:]]*=/ { in_block=1; next }
  in_block && /^]/ { exit }
  in_block {
    line=$0
    gsub(/[",[:space:]]/, "", line)
    if (line != "") print line
  }
' Cargo.toml)"

if [[ -z "$default_members" ]]; then
  echo "Cargo.lock gate: unable to read workspace default-members" >&2
  exit 1
fi

while IFS= read -r member; do
  [[ -n "$member" ]] || continue
  manifest="$member/Cargo.toml"
  if [[ ! -f "$manifest" ]]; then
    echo "Cargo.lock gate: missing workspace manifest: $manifest" >&2
    fail=1
    continue
  fi
  package="$(awk -F'=' '
    /^\[package\]/ { in_package=1; next }
    /^\[/ && in_package { exit }
    in_package && $1 ~ /^[[:space:]]*name[[:space:]]*$/ {
      value=$2
      gsub(/["[:space:]]/, "", value)
      print value
      exit
    }
  ' "$manifest")"
  if [[ -z "$package" ]]; then
    echo "Cargo.lock gate: cannot determine package name for $member" >&2
    fail=1
    continue
  fi
  if ! awk -v pkg="$package" '
      /^\[\[package\]\]/ { in_pkg=1; name=""; next }
      in_pkg && /^name = / {
        value=$0
        sub(/^name = "/, "", value)
        sub(/"$/, "", value)
        if (value == pkg) found=1
      }
      END { exit(found ? 0 : 1) }
    ' Cargo.lock; then
    echo "Cargo.lock gate: missing native workspace package: $package ($member)" >&2
    fail=1
  fi
done <<< "$default_members"


# Also catch root-level pinned workspace dependencies that are absent from the
# committed lock. This is not a resolver replacement; it prevents a manually
# inserted workspace package stanza from making the lightweight gate appear green.
workspace_dependencies="$(awk '
  /^\[workspace\.dependencies\]/ { in_block=1; next }
  in_block && /^\[/ { exit }
  in_block && /^[A-Za-z0-9_.-]+[[:space:]]*=/ {
    line=$0
    sub(/[[:space:]]*=.*/, "", line)
    print line
  }
' Cargo.toml)"

while IFS= read -r dependency; do
  [[ -n "$dependency" ]] || continue
  if ! awk -v pkg="$dependency" '
      /^\[\[package\]\]/ { in_pkg=1; next }
      in_pkg && /^name = / {
        value=$0
        sub(/^name = "/, "", value)
        sub(/"$/, "", value)
        if (value == pkg) found=1
      }
      END { exit(found ? 0 : 1) }
    ' Cargo.lock; then
    echo "Cargo.lock gate: missing pinned workspace dependency: $dependency" >&2
    fail=1
  fi
done <<< "$workspace_dependencies"

if (( fail )); then
  echo "Cargo.lock gate: FAIL - regenerate and commit Cargo.lock with Rust 1.82 before release/CI." >&2
  exit 1
fi

echo "Cargo.lock static workspace gate: OK"
