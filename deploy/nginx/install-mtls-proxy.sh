#!/usr/bin/env bash
set -euo pipefail

[[ "$EUID" -eq 0 ]] || { echo "run as root" >&2; exit 1; }
command -v nginx >/dev/null 2>&1 || { echo "nginx is required" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }

SERVER_NAME="${AISOC_INGEST_SERVER_NAME:-}"
SERVER_CERT="${AISOC_INGEST_SERVER_CERT_SOURCE:-}"
SERVER_KEY="${AISOC_INGEST_SERVER_KEY_SOURCE:-}"
AGENT_CA="${AISOC_AGENT_CA_CERT_SOURCE:-}"
CONFIG_DIR="${AISOC_CONFIG_DIR:-/etc/aisoc}"
SERVICE_USER="${AISOC_SERVICE_USER:-aisoc}"
SERVICE_GROUP="${AISOC_SERVICE_GROUP:-aisoc}"
NGINX_CONF_DIR="${AISOC_NGINX_CONF_DIR:-/etc/nginx/conf.d}"
NGINX_CONF="$NGINX_CONF_DIR/aisoc-ingest.conf"

[[ "$SERVER_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$ ]] || {
  echo "AISOC_INGEST_SERVER_NAME must be an explicit safe hostname or IP" >&2; exit 1;
}
for value in "$SERVER_CERT" "$SERVER_KEY" "$AGENT_CA"; do
  [[ -n "$value" && -f "$value" && ! -L "$value" ]] || {
    echo "server certificate, private key, and Agent CA must be regular non-symlink files" >&2; exit 1;
  }
done

install -d -m 0750 -o root -g root "$CONFIG_DIR/nginx" "$CONFIG_DIR/tls"
install -d -m 0755 -o root -g root "$NGINX_CONF_DIR"
install -m 0644 -o root -g root "$SERVER_CERT" "$CONFIG_DIR/tls/ingest-server.crt"
install -m 0600 -o root -g root "$SERVER_KEY" "$CONFIG_DIR/tls/ingest-server.key"
install -m 0644 -o root -g root "$AGENT_CA" "$CONFIG_DIR/tls/agent-ca.crt"

openssl x509 -in "$CONFIG_DIR/tls/ingest-server.crt" -noout >/dev/null
openssl x509 -in "$CONFIG_DIR/tls/agent-ca.crt" -noout >/dev/null
openssl pkey -in "$CONFIG_DIR/tls/ingest-server.key" -noout >/dev/null
cert_pub="$(openssl x509 -in "$CONFIG_DIR/tls/ingest-server.crt" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)"
key_pub="$(openssl pkey -in "$CONFIG_DIR/tls/ingest-server.key" -pubout -outform DER | sha256sum | cut -d' ' -f1)"
[[ "$cert_pub" == "$key_pub" ]] || { echo "ingest certificate and private key do not match" >&2; exit 1; }

for map in tenant id host; do
  map_file="$CONFIG_DIR/nginx/agent-${map}.map"
  if [[ ! -e "$map_file" ]]; then
    install -m 0600 -o root -g root /dev/null "$map_file"
  fi
done

secret_file="$CONFIG_DIR/ingest-proxy.secret"
if [[ ! -e "$secret_file" ]]; then
  umask 077
  openssl rand -hex 32 > "$secret_file"
fi
secret="$(tr -d '\r\n' < "$secret_file")"
[[ "$secret" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "invalid ingest proxy secret" >&2; exit 1; }
chown "$SERVICE_USER":"$SERVICE_GROUP" "$secret_file"
chmod 0600 "$secret_file"
cat > "$CONFIG_DIR/nginx-ingest-proxy-secret.conf" <<EOF_SECRET
proxy_set_header X-AISOC-Proxy-Secret "$secret";
EOF_SECRET
chmod 0600 "$CONFIG_DIR/nginx-ingest-proxy-secret.conf"
chown root:root "$CONFIG_DIR/nginx-ingest-proxy-secret.conf"

staged="$(mktemp "$NGINX_CONF_DIR/.aisoc-ingest.conf.XXXXXX")"
trap 'rm -f -- "$staged"' EXIT
cat > "$staged" <<EOF_CONF
map \$ssl_client_serial \$aisoc_tenant_id {
    default "";
    include $CONFIG_DIR/nginx/agent-tenant.map;
}
map \$ssl_client_serial \$aisoc_agent_id {
    default "";
    include $CONFIG_DIR/nginx/agent-id.map;
}
map \$ssl_client_serial \$aisoc_host_id {
    default "";
    include $CONFIG_DIR/nginx/agent-host.map;
}
server {
    listen 8443 ssl;
    server_name $SERVER_NAME;
    ssl_certificate $CONFIG_DIR/tls/ingest-server.crt;
    ssl_certificate_key $CONFIG_DIR/tls/ingest-server.key;
    ssl_client_certificate $CONFIG_DIR/tls/agent-ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    client_max_body_size 8m;
    client_body_timeout 15s;
    location = /v1/agent/heartbeat {
        if (\$aisoc_agent_id = "") { return 403; }
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header X-AISOC-TLS-Verified \$ssl_client_verify;
        proxy_set_header X-AISOC-Client-Serial \$ssl_client_serial;
        proxy_set_header X-AISOC-Tenant-ID \$aisoc_tenant_id;
        proxy_set_header X-AISOC-Agent-ID \$aisoc_agent_id;
        proxy_set_header X-AISOC-Host-ID \$aisoc_host_id;
        include $CONFIG_DIR/nginx-ingest-proxy-secret.conf;
    }
    location = /v1/agent/events {
        if (\$aisoc_agent_id = "") { return 403; }
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_request_buffering on;
        proxy_set_header X-AISOC-TLS-Verified \$ssl_client_verify;
        proxy_set_header X-AISOC-Client-Serial \$ssl_client_serial;
        proxy_set_header X-AISOC-Tenant-ID \$aisoc_tenant_id;
        proxy_set_header X-AISOC-Agent-ID \$aisoc_agent_id;
        proxy_set_header X-AISOC-Host-ID \$aisoc_host_id;
        include $CONFIG_DIR/nginx-ingest-proxy-secret.conf;
    }
}
EOF_CONF
chmod 0600 "$staged"

backup=""
if [[ -e "$NGINX_CONF" ]]; then backup="${NGINX_CONF}.bak.$(date -u +%Y%m%dT%H%M%SZ)"; cp -a "$NGINX_CONF" "$backup"; fi
mv "$staged" "$NGINX_CONF"
trap - EXIT
if ! nginx -t; then
  rm -f "$NGINX_CONF"
  [[ -z "$backup" ]] || mv "$backup" "$NGINX_CONF"
  echo "nginx configuration test failed; previous config restored" >&2
  exit 1
fi
printf 'installed %s; populate certificate mappings, then reload nginx\n' "$NGINX_CONF"
