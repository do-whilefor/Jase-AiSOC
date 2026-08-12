#!/usr/bin/env bash
set -euo pipefail

[[ "$EUID" -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ $# -eq 4 ]] || {
  echo "usage: $0 AGENT_CERT TENANT_ID AGENT_ID HOST_ID" >&2; exit 2;
}
CERT="$1"; TENANT_ID="$2"; AGENT_ID="$3"; HOST_ID="$4"
CONFIG_DIR="${AISOC_CONFIG_DIR:-/etc/aisoc}"
CA_FILE="${AISOC_AGENT_CA_FILE:-$CONFIG_DIR/tls/agent-ca.crt}"

valid_id() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$ ]]; }
valid_id "$TENANT_ID" || { echo "invalid tenant id" >&2; exit 1; }
valid_id "$AGENT_ID" || { echo "invalid agent id" >&2; exit 1; }
valid_id "$HOST_ID" || { echo "invalid host id" >&2; exit 1; }
[[ -f "$CERT" && ! -L "$CERT" ]] || { echo "Agent certificate must be a regular file" >&2; exit 1; }
[[ -f "$CA_FILE" && ! -L "$CA_FILE" ]] || { echo "Agent CA certificate is unavailable" >&2; exit 1; }
openssl verify -CAfile "$CA_FILE" "$CERT" >/dev/null
serial="$(openssl x509 -in "$CERT" -noout -serial | sed 's/^serial=//' | tr '[:lower:]' '[:upper:]')"
[[ "$serial" =~ ^[0-9A-F]{2,128}$ ]] || { echo "invalid certificate serial" >&2; exit 1; }

update_map() {
  local file="$1" value="$2" tmp
  [[ -f "$file" && ! -L "$file" ]] || { echo "mapping file unavailable: $file" >&2; exit 1; }
  tmp="$(mktemp "${file}.XXXXXX")"
  awk -v serial="$serial" '$1 != serial { print }' "$file" > "$tmp"
  printf '%s "%s";\n' "$serial" "$value" >> "$tmp"
  sort -u -o "$tmp" "$tmp"
  chown root:root "$tmp"; chmod 0600 "$tmp"; mv "$tmp" "$file"
}

update_map "$CONFIG_DIR/nginx/agent-tenant.map" "$TENANT_ID"
update_map "$CONFIG_DIR/nginx/agent-id.map" "$AGENT_ID"
update_map "$CONFIG_DIR/nginx/agent-host.map" "$HOST_ID"
nginx -t
printf 'registered certificate serial %s for tenant=%s agent=%s host=%s\n' \
  "$serial" "$TENANT_ID" "$AGENT_ID" "$HOST_ID"
