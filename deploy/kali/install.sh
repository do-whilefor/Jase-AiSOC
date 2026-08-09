#!/usr/bin/env bash
# Native Kali/Debian install for the Blue Team AI Agent platform.
#
# Installs system dependencies, a dedicated unprivileged service user, a Python
# virtual environment, a local PostgreSQL database, Alembic migrations, mTLS
# certificates for the Agent <-> Ingest gateway, and systemd units. Re-runnable:
# each step is guarded so it only acts when the target state is missing.
#
# Usage:
#   sudo bash deploy/kali/install.sh
#
# This script is Linux-only. It must NOT run on Windows.

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "install.sh is Linux-only (got $(uname -s)). Aborting." >&2
  exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "install.sh must run as root (use sudo). Aborting." >&2
  exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP_USER="blue-team"
APP_GROUP="blue-team"
INSTALL_PREFIX="/opt/blue-team"
VENV_DIR="${INSTALL_PREFIX}/.venv"
STATE_DIR="/var/lib/blue-team"
AGENT_STATE_DIR="/var/lib/blue-team-agent"
CONFIG_DIR="/etc/blue-team"
PG_DB="blue_team"
PG_USER="blue_team"
PG_PASSWORD="blue_team_dev"

log() { printf '\033[1;34m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }

# 1. System dependencies -----------------------------------------------------
log "installing apt dependencies"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates curl python3 python3-venv python3-pip python3-dev \
  build-essential libssl-dev libffi-dev \
  postgresql postgresql-contrib \
  libsqlite3-0 \
  >/dev/null

# Optional collectors the operator may want. Not required for the API server.
for pkg in suricata auditd nginx; do
  if ! dpkg -l "$pkg" >/dev/null 2>&1; then
    warn "optional collector package '$pkg' is not installed; enabling its collector requires it."
  fi
done

# 2. Service user -----------------------------------------------------------
if ! id "$APP_USER" >/dev/null 2>&1; then
  log "creating service user '$APP_USER'"
  groupadd --system "$APP_GROUP"
  useradd --system --gid "$APP_GROUP" --no-create-home --shell /usr/sbin/nologin "$APP_USER"
fi

# 3. Directories ------------------------------------------------------------
log "preparing directories"
install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" "$INSTALL_PREFIX"
install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" "$STATE_DIR"
install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" "$AGENT_STATE_DIR"
install -d -m 0750 -o root -g "$APP_GROUP" "$CONFIG_DIR"

# 4. Virtual environment + install ------------------------------------------
log "building Python virtual environment at $VENV_DIR"
if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  python3 -m venv "$VENV_DIR"
fi
"${VENV_DIR}/bin/pip" install --upgrade pip wheel setuptools >/dev/null

log "installing blue-team-ai-agent into the venv"
"${VENV_DIR}/bin/pip" install --no-cache-dir "$PROJECT_ROOT" >/dev/null

# 5. PostgreSQL -------------------------------------------------------------
log "starting PostgreSQL"
systemctl enable --now postgresql >/dev/null

if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${PG_USER}'" | grep -q 1; then
  log "creating database role '${PG_USER}'"
  sudo -u postgres psql -c "CREATE ROLE \"${PG_USER}\" LOGIN PASSWORD '${PG_PASSWORD}';" >/dev/null
fi
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${PG_DB}'" | grep -q 1; then
  log "creating database '${PG_DB}'"
  sudo -u postgres createdb -O "$PG_USER" "$PG_DB"
fi

# 6. Configuration + migrations --------------------------------------------
log "writing server environment file"
install -m 0640 -o root -g "$APP_GROUP" /dev/stdin "${CONFIG_DIR}/blue-team.env" <<EOF
BLUE_TEAM_ENVIRONMENT=production
BLUE_TEAM_API_HOST=127.0.0.1
BLUE_TEAM_API_PORT=8000
BLUE_TEAM_LOG_FORMAT=json
BLUE_TEAM_DATABASE_URL=postgresql+asyncpg://${PG_USER}:${PG_PASSWORD}@127.0.0.1:5432/${PG_DB}
BLUE_TEAM_OBJECT_STORE_ROOT=${STATE_DIR}/evidence
BLUE_TEAM_INGEST_HOST=127.0.0.1
BLUE_TEAM_INGEST_PORT=8001
EOF

log "running Alembic migrations"
sudo -u "$APP_USER" env \
  BLUE_TEAM_DATABASE_URL="postgresql+asyncpg://${PG_USER}:${PG_PASSWORD}@127.0.0.1:5432/${PG_DB}" \
  BLUE_TEAM_OBJECT_STORE_ROOT="${STATE_DIR}/evidence" \
  "${VENV_DIR}/bin/alembic" -c "${INSTALL_PREFIX}/alembic.ini" upgrade head

# Copy alembic config + migrations next to the venv so the systemd unit path works.
install -m 0644 -o root -g "$APP_GROUP" "${PROJECT_ROOT}/alembic.ini" "${INSTALL_PREFIX}/alembic.ini"
cp -a "${PROJECT_ROOT}/migrations" "${INSTALL_PREFIX}/migrations"
chown -R root:"$APP_GROUP" "${INSTALL_PREFIX}/migrations"

# 7. mTLS certificates for the Agent transport -----------------------------
log "generating local mTLS CA and Agent certificate"
if [[ ! -f "${CONFIG_DIR}/ca.crt" ]]; then
  openssl genrsa -out "${CONFIG_DIR}/ca.key" 4096 2>/dev/null
  openssl req -x509 -new -nodes -key "${CONFIG_DIR}/ca.key" -sha256 -days 3650 \
    -subj "/CN=blue-team-local-ca" -out "${CONFIG_DIR}/ca.crt" 2>/dev/null
fi
if [[ ! -f "${CONFIG_DIR}/agent.crt" ]]; then
  openssl genrsa -out "${CONFIG_DIR}/agent.key" 2048 2>/dev/null
  openssl req -new -key "${CONFIG_DIR}/agent.key" -subj "/CN=blue-team-agent" \
    -out "${CONFIG_DIR}/agent.csr" 2>/dev/null
  openssl x509 -req -in "${CONFIG_DIR}/agent.csr" -CA "${CONFIG_DIR}/ca.crt" \
    -CAkey "${CONFIG_DIR}/ca.key" -CAcreateserial -days 825 -sha256 \
    -out "${CONFIG_DIR}/agent.crt" 2>/dev/null
fi
chmod 0640 "${CONFIG_DIR}/ca.key" "${CONFIG_DIR}/agent.key"
chown root:"$APP_GROUP" "${CONFIG_DIR}"/*.crt "${CONFIG_DIR}"/*.key

# 8. Agent config -----------------------------------------------------------
log "writing Agent config"
BOOT_ID="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo replace-boot-id)"
install -m 0640 -o root -g "$APP_GROUP" /dev/stdin "${CONFIG_DIR}/agent.json" <<EOF
{
  "format_version": 1,
  "tenant_id": "ten_kali001",
  "agent_id": "agent_kali001",
  "host_id": "host_kali001",
  "boot_id": "${BOOT_ID}",
  "state_directory": "${AGENT_STATE_DIR}",
  "heartbeat_interval_seconds": 30,
  "heartbeat_retry_seconds": 5,
  "poll_interval_seconds": 0.25,
  "ingest_url": "https://127.0.0.1:8001",
  "client_certificate_path": "${CONFIG_DIR}/agent.crt",
  "client_private_key_path": "${CONFIG_DIR}/agent.key",
  "ca_certificate_path": "${CONFIG_DIR}/ca.crt",
  "transport_timeout_seconds": 15.0,
  "upload_backoff_seconds": 5.0,
  "journald_enabled": true,
  "journald_units": ["sshd.service"],
  "suricata_enabled": false,
  "suricata_log_path": "/var/log/suricata/eve.json",
  "service_log_enabled": false,
  "service_log_path": "/var/log/nginx/access.log",
  "service_log_name": "nginx",
  "auditd_enabled": true,
  "auditd_log_path": "/var/log/audit/audit.log",
  "auditctl_path": "/usr/sbin/auditctl"
}
EOF
install -m 0640 -o root -g "$APP_GROUP" /dev/stdin "${CONFIG_DIR}/agent.env" <<'EOF'
# Reserved for future Agent environment overrides.
EOF

# 9. systemd units ----------------------------------------------------------
log "installing systemd units"
install -m 0644 "${PROJECT_ROOT}/deploy/systemd/blue-team-api.service" \
  /etc/systemd/system/blue-team-api.service
install -m 0644 "${PROJECT_ROOT}/deploy/systemd/blue-team-ingest.service" \
  /etc/systemd/system/blue-team-ingest.service
install -m 0644 "${PROJECT_ROOT}/deploy/systemd/blue-team-agent.service" \
  /etc/systemd/system/blue-team-agent.service
systemctl daemon-reload

cat <<'POSTINSTALL'

[install] Blue Team AI Agent installed successfully.

Next steps:
  1. Start the central services (API + Ingest gateway):
       sudo systemctl enable --now blue-team-api blue-team-ingest
  2. Start the endpoint Agent:
       sudo systemctl enable --now blue-team-agent
  3. Verify:
       sudo systemctl status blue-team-api blue-team-ingest blue-team-agent
       curl -s http://127.0.0.1:8000/health/live
       sudo journalctl -u blue-team-agent -f

To enable optional collectors, edit /etc/blue-team/agent.json
(set suricata_enabled / service_log_enabled to true and ensure the
corresponding log files exist and are readable by the blue-team user),
then: sudo systemctl restart blue-team-agent
POSTINSTALL
