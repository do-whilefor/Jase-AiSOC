#!/usr/bin/env bash
# Rust-first installer for AI-SOC V4. Python is an explicit migration-only mode.
set -euo pipefail

ROLE="control"
ENABLE_SERVICES=0
INSTALL_SYSTEM_DEPS=0
LEGACY_PYTHON=0
RELEASE_DIR="${AISOC_RELEASE_DIR:-}"
RELEASE_VERSION="${AISOC_RELEASE_VERSION:-}"

usage() {
  cat <<'USAGE'
Usage: sudo bash deploy/linux/install.sh [options]

Options:
  --role control|agent|edge|all   Components to configure (default: control)
  --release-dir DIR               Verified Rust release bundle to activate
  --release-version VERSION       Explicit immutable release version
  --install-system-deps           Install baseline OS packages
  --enable-services               Enable/start applicable systemd services
  --legacy-python                 Explicit migration-only Python runtime setup
  -h, --help                      Show help

Normal V4 installation requires a Rust release bundle. The bundle format and
signature policy are documented by deploy/linux/release-manager.sh help.
Python is not part of the normal production runtime path.
USAGE
}

while (($#)); do
  case "$1" in
    --role) ROLE="${2:-}"; shift 2 ;;
    --release-dir) RELEASE_DIR="${2:-}"; shift 2 ;;
    --release-version) RELEASE_VERSION="${2:-}"; shift 2 ;;
    --install-system-deps) INSTALL_SYSTEM_DEPS=1; shift ;;
    --enable-services) ENABLE_SERVICES=1; shift ;;
    --legacy-python) LEGACY_PYTHON=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$ROLE" in control|agent|edge|all) ;; *) printf 'invalid --role: %s\n' "$ROLE" >&2; exit 2 ;; esac
[[ "$(uname -s)" == "Linux" ]] || { echo "AI-SOC V4 supports Linux only." >&2; exit 1; }
[[ "$EUID" -eq 0 ]] || { echo "run this installer as root." >&2; exit 1; }

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
APP_USER="${AISOC_SERVICE_USER:-aisoc}"
APP_GROUP="${AISOC_SERVICE_GROUP:-aisoc}"
INSTALL_PREFIX="${AISOC_INSTALL_PREFIX:-/opt/aisoc}"
CONFIG_DIR="${AISOC_CONFIG_DIR:-/etc/aisoc}"
AGENT_STATE_DIR="${AISOC_AGENT_STATE_DIR:-/var/lib/aisoc-agent}"
INGEST_STATE_DIR="${AISOC_INGEST_STATE_DIR:-/var/lib/aisoc-ingest}"
INGEST_OBJECT_STORE_ROOT="${AISOC_INGEST_OBJECT_STORE_ROOT:-/var/lib/aisoc-raw-evidence}"
RUST_ENV_FILE="$CONFIG_DIR/aisoc-rust.env"

[[ "$INGEST_STATE_DIR" = /* && "$INGEST_OBJECT_STORE_ROOT" = /* ]] || {
  echo "AISOC ingest state and object-store paths must be absolute Linux paths." >&2
  exit 1
}

log() { printf '[aisoc-install] %s\n' "$*"; }
warn() { printf '[aisoc-install] warning: %s\n' "$*" >&2; }
has() { command -v "$1" >/dev/null 2>&1; }

package_manager() {
  local manager
  for manager in apt-get dnf yum zypper pacman; do
    if has "$manager"; then printf '%s\n' "$manager"; return 0; fi
  done
  printf 'unknown\n'
}

install_baseline_packages() {
  local manager
  manager="$(package_manager)"
  log "detected package manager: $manager"
  case "$manager" in
    apt-get)
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl openssl nginx
      ;;
    dnf) dnf install -y ca-certificates curl openssl nginx ;;
    yum) yum install -y ca-certificates curl openssl nginx ;;
    zypper) zypper --non-interactive install ca-certificates curl openssl nginx ;;
    pacman) pacman -Sy --needed --noconfirm ca-certificates curl openssl nginx ;;
    *)
      echo "no supported package manager detected; install CA certificates, OpenSSL and Nginx manually." >&2
      exit 1
      ;;
  esac
}

create_service_account() {
  if ! getent group "$APP_GROUP" >/dev/null 2>&1; then
    has groupadd || { echo "groupadd is required." >&2; exit 1; }
    groupadd --system "$APP_GROUP"
  fi
  if ! id "$APP_USER" >/dev/null 2>&1; then
    has useradd || { echo "useradd is required." >&2; exit 1; }
    useradd --system --gid "$APP_GROUP" --no-create-home --shell /usr/sbin/nologin "$APP_USER"
  fi
}

prepare_directories() {
  install -d -m 0755 -o root -g root "$INSTALL_PREFIX" "$INSTALL_PREFIX/releases"
  install -d -m 0750 -o root -g "$APP_GROUP" "$CONFIG_DIR"
  if [[ "$ROLE" == "agent" || "$ROLE" == "all" ]]; then
    install -d -m 0700 -o "$APP_USER" -g "$APP_GROUP" "$AGENT_STATE_DIR"
  fi
  if [[ "$ROLE" == "control" || "$ROLE" == "all" ]]; then
    install -d -m 0700 -o "$APP_USER" -g "$APP_GROUP" "$INGEST_STATE_DIR"
    install -d -m 0700 -o "$APP_USER" -g "$APP_GROUP" "$INGEST_OBJECT_STORE_ROOT"
  fi
}

activate_release() {
  [[ -n "$RELEASE_DIR" ]] || {
    echo "--release-dir (or AISOC_RELEASE_DIR) is required for normal Rust installation." >&2
    exit 1
  }
  local args=(install "$RELEASE_DIR")
  [[ -z "$RELEASE_VERSION" ]] || args+=("$RELEASE_VERSION")
  AISOC_INSTALL_PREFIX="$INSTALL_PREFIX" \
  AISOC_SERVICE_USER="$APP_USER" \
  AISOC_SERVICE_GROUP="$APP_GROUP" \
    bash "$PROJECT_ROOT/deploy/linux/release-manager.sh" "${args[@]}"
}

migrate_control_database() {
  [[ "$ROLE" == "control" || "$ROLE" == "all" ]] || return 0
  local database_url="${AISOC_DATABASE_URL:-}"
  if [[ -z "$database_url" ]]; then
    if [[ "${AISOC_ENVIRONMENT:-development}" == "production" ]]; then
      echo "AISOC_DATABASE_URL is required for a production control-plane install." >&2
      exit 1
    fi
    warn "AISOC_DATABASE_URL is not set; skipping PostgreSQL migration in non-production mode"
    return 0
  fi
  local db_binary="$INSTALL_PREFIX/current/bin/aisoc-db"
  [[ -x "$db_binary" && ! -L "$db_binary" ]] || {
    echo "verified release is missing executable bin/aisoc-db." >&2
    exit 1
  }
  log "applying embedded Rust SQLx/PostgreSQL migrations"
  AISOC_DATABASE_URL="$database_url" "$db_binary" migrate
}

write_rust_environment() {
  umask 027
  cat > "$RUST_ENV_FILE" <<EOF_ENV
AISOC_ENVIRONMENT=${AISOC_ENVIRONMENT:-development}
AISOC_LOG=${AISOC_LOG:-info}
AISOC_API_BIND=${AISOC_API_BIND:-127.0.0.1:8000}
AISOC_CONSOLE_BIND=${AISOC_CONSOLE_BIND:-127.0.0.1:8088}
AISOC_INGEST_BIND=127.0.0.1:8080
AISOC_INGEST_STATE_DIR=${INGEST_STATE_DIR}
AISOC_INGEST_OBJECT_STORE_ROOT=${INGEST_OBJECT_STORE_ROOT}
AISOC_INGEST_PROXY_SECRET_FILE=${CONFIG_DIR}/ingest-proxy.secret
AISOC_INGEST_CONTROL_SECRET_FILE=${CONFIG_DIR}/ingest-control.secret
AISOC_INGEST_CONTROL_ORIGIN=http://127.0.0.1:8080
AISOC_API_AUTH_FILE=${CONFIG_DIR}/api-auth.json
AISOC_CONSOLE_API_ORIGIN=http://127.0.0.1:8000
EOF_ENV
  local name
  for name in AISOC_DATABASE_URL AISOC_API_AUTH_KEY_FILE; do
    if [[ -n "${!name:-}" ]]; then printf '%s=%s\n' "$name" "${!name}" >> "$RUST_ENV_FILE"; fi
  done
  chown root:"$APP_GROUP" "$RUST_ENV_FILE"
  chmod 0640 "$RUST_ENV_FILE"
}

install_agent_config() {
  local source="${AISOC_AGENT_CONFIG_SOURCE:-}"
  [[ -n "$source" ]] || {
    echo "AISOC_AGENT_CONFIG_SOURCE is required for agent/all roles." >&2; exit 1;
  }
  [[ -f "$source" && ! -L "$source" ]] || {
    echo "AISOC_AGENT_CONFIG_SOURCE must be a regular non-symlink file." >&2; exit 1;
  }
  install -m 0600 -o "$APP_USER" -g "$APP_GROUP" "$source" "$CONFIG_DIR/agent-rust.json"
  install -m 0640 -o root -g "$APP_GROUP" /dev/null "$CONFIG_DIR/agent.env"

  if [[ -n "${AISOC_AGENT_LOG_GROUPS:-}" ]]; then
    local group
    IFS=',' read -r -a groups <<< "$AISOC_AGENT_LOG_GROUPS"
    for group in "${groups[@]}"; do
      [[ -n "$group" ]] || continue
      if getent group "$group" >/dev/null 2>&1; then usermod -a -G "$group" "$APP_USER"; fi
    done
  fi
}


generate_control_secret() {
  local secret_file="$CONFIG_DIR/ingest-control.secret"
  if [[ ! -e "$secret_file" ]]; then
    umask 077
    openssl rand -hex 32 > "$secret_file"
  fi
  local secret
  secret="$(tr -d '\r\n' < "$secret_file")"
  [[ "$secret" =~ ^[0-9a-fA-F]{64}$ ]] || {
    echo "ingest control secret must be a 32-byte hex secret." >&2; exit 1;
  }
  chown "$APP_USER":"$APP_GROUP" "$secret_file"
  chmod 0600 "$secret_file"
}

generate_api_auth() {
  local auth_file="$CONFIG_DIR/api-auth.json"
  local source="${AISOC_API_AUTH_SOURCE:-}"
  if [[ -n "$source" ]]; then
    [[ -f "$source" && ! -L "$source" ]] || {
      echo "AISOC_API_AUTH_SOURCE must be a regular non-symlink file." >&2; exit 1;
    }
    install -m 0600 -o "$APP_USER" -g "$APP_GROUP" "$source" "$auth_file"
    return
  fi
  [[ -e "$auth_file" ]] && return
  local token="${AISOC_BOOTSTRAP_API_TOKEN:-}"
  local tenant="${AISOC_BOOTSTRAP_TENANT_ID:-}"
  [[ ${#token} -ge 32 && ${#token} -le 512 && "$token" != *$'\n'* && "$token" != *$'\r'* ]] || {
    echo "AISOC_BOOTSTRAP_API_TOKEN (32..512 non-control characters) is required for a new control-plane install." >&2
    exit 1
  }
  [[ "$tenant" =~ ^ten_[A-Za-z0-9][A-Za-z0-9._:-]{7,123}$ ]] || {
    echo "AISOC_BOOTSTRAP_TENANT_ID must be a valid ten_ identifier." >&2; exit 1;
  }
  local digest
  digest="$(printf '%s' "$token" | sha256sum | cut -d' ' -f1)"
  umask 077
  cat > "$auth_file" <<EOF_AUTH
{"principals":[{"token_sha256":"$digest","subject":"bootstrap-admin","tenant_id":"$tenant","roles":["admin"]}]}
EOF_AUTH
  chown "$APP_USER":"$APP_GROUP" "$auth_file"
  chmod 0600 "$auth_file"
}

generate_ingest_proxy_secret() {
  local secret_file="$CONFIG_DIR/ingest-proxy.secret"
  if [[ ! -e "$secret_file" ]]; then
    umask 077
    openssl rand -hex 32 > "$secret_file"
    chown "$APP_USER":"$APP_GROUP" "$secret_file"
    chmod 0600 "$secret_file"
  fi
  local secret
  secret="$(tr -d '\r\n' < "$secret_file")"
  [[ "$secret" =~ ^[0-9a-fA-F]{64}$ ]] || {
    echo "ingest proxy secret must be a 32-byte hex secret." >&2; exit 1;
  }
  umask 077
  cat > "$CONFIG_DIR/nginx-ingest-proxy-secret.conf" <<EOF_SECRET
proxy_set_header X-AISOC-Proxy-Secret "$secret";
EOF_SECRET
  chown root:root "$CONFIG_DIR/nginx-ingest-proxy-secret.conf"
  chmod 0600 "$CONFIG_DIR/nginx-ingest-proxy-secret.conf"
}

install_nginx_templates() {
  generate_ingest_proxy_secret
  install -d -m 0750 -o root -g root "$CONFIG_DIR/nginx"
  local map
  for map in tenant id host; do
    local destination="$CONFIG_DIR/nginx/agent-${map}.map"
    if [[ ! -e "$destination" ]]; then
      install -m 0600 -o root -g root \
        "$PROJECT_ROOT/deploy/nginx/nginx-agent-${map}.map.example" "$destination"
    fi
  done
  install -m 0600 -o root -g root "$PROJECT_ROOT/deploy/nginx/aisoc-ingest-mtls.conf.example" \
    "$CONFIG_DIR/nginx/aisoc-ingest-mtls.conf.example"
  warn "Nginx mTLS template installed under $CONFIG_DIR/nginx. Populate certificate-serial maps and TLS paths before enabling it."
}

install_systemd_units() {
  local unit source
  for unit in aisoc-agent.service aisoc-ingest.service aisoc-api.service aisoc-console.service aisoc-web-guard.service; do
    source="$PROJECT_ROOT/deploy/systemd/$unit"
    install -m 0644 -o root -g root "$source" "/etc/systemd/system/$unit"
  done
  systemctl daemon-reload
}

enable_role_services() {
  [[ "$ENABLE_SERVICES" == "1" ]] || return 0
  case "$ROLE" in
    control) systemctl enable --now aisoc-ingest.service aisoc-api.service aisoc-console.service ;;
    agent) systemctl enable --now aisoc-agent.service ;;
    edge) systemctl enable --now aisoc-web-guard.service ;;
    all) systemctl enable --now aisoc-ingest.service aisoc-api.service aisoc-console.service aisoc-web-guard.service aisoc-agent.service ;;
  esac
}

install_legacy_python() {
  [[ "$LEGACY_PYTHON" == "1" ]] || return 0
  warn "installing migration-only Python environment; this is not the V4 production runtime"
  has python3 || { echo "python3 is required for --legacy-python." >&2; exit 1; }
  local venv="$INSTALL_PREFIX/legacy-python-venv"
  python3 -m venv "$venv"
  "$venv/bin/python" -m pip install --upgrade pip wheel setuptools
  "$venv/bin/python" -m pip install --no-cache-dir "$PROJECT_ROOT"
}

if ((INSTALL_SYSTEM_DEPS)); then install_baseline_packages; fi
has openssl || { echo "openssl is required." >&2; exit 1; }
has sha256sum || { echo "sha256sum is required." >&2; exit 1; }
create_service_account
prepare_directories
activate_release
write_rust_environment
migrate_control_database
install_legacy_python

if [[ "$ROLE" == "agent" || "$ROLE" == "all" ]]; then install_agent_config; fi
if [[ "$ROLE" == "control" || "$ROLE" == "all" ]]; then
  generate_control_secret
  generate_api_auth
  install_nginx_templates
fi

SYSTEMD=0
if [[ "$(cat /proc/1/comm 2>/dev/null || true)" == "systemd" ]] && has systemctl; then SYSTEMD=1; fi
if ((SYSTEMD)); then
  install_systemd_units
  enable_role_services
else
  warn "systemd was not detected; units were not installed or enabled"
fi

cat <<EOF_DONE
AI-SOC Rust-first installation completed.
role:          $ROLE
release:       $(readlink -f "$INSTALL_PREFIX/current" 2>/dev/null || true)
configuration: $CONFIG_DIR
rollback:      sudo AISOC_INSTALL_PREFIX=$INSTALL_PREFIX bash $PROJECT_ROOT/deploy/linux/release-manager.sh rollback
EOF_DONE
