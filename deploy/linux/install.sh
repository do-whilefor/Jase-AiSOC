#!/usr/bin/env bash
# Generic Linux installer for AI-SOC. It intentionally avoids assuming a
# distribution, package manager, init system, database layout, or log groups.
set -euo pipefail

ROLE="control"
INSTALL_SYSTEM_DEPS=0
ENABLE_SERVICES=0
ALLOW_PYTHON_CORE_FALLBACK=0

usage() {
  cat <<'EOF'
Usage: sudo bash deploy/linux/install.sh [options]

Options:
  --role control|agent|all   Components to install (default: control)
  --install-system-deps      Install baseline packages with the detected package manager
  --enable-services          Enable/start systemd units when systemd is available
  --allow-python-core-fallback Allow the deterministic Python fallback (development only)
  -h, --help                 Show this help

Control-plane configuration is read from AISOC_* environment variables. At
minimum AISOC_DATABASE_URL is required for control/all roles. Agent/all roles
require AISOC_AGENT_CONFIG_SOURCE pointing to a pre-enrolled private agent JSON.
For the Rust core, set AISOC_RUST_WHEEL to a prebuilt compatible wheel or provide
Cargo 1.82+; the installer will build the PyO3 bridge with maturin.
EOF
}

while (($#)); do
  case "$1" in
    --role)
      ROLE="${2:-}"; shift 2 ;;
    --install-system-deps)
      INSTALL_SYSTEM_DEPS=1; shift ;;
    --enable-services)
      ENABLE_SERVICES=1; shift ;;
    --allow-python-core-fallback)
      ALLOW_PYTHON_CORE_FALLBACK=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$ROLE" in control|agent|all) ;; *) echo "invalid --role: $ROLE" >&2; exit 2 ;; esac
[[ "$(uname -s)" == "Linux" ]] || { echo "AI-SOC supports Linux only." >&2; exit 1; }
[[ "$EUID" -eq 0 ]] || { echo "run this installer as root." >&2; exit 1; }

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP_USER="${AISOC_SERVICE_USER:-aisoc}"
APP_GROUP="${AISOC_SERVICE_GROUP:-aisoc}"
INSTALL_PREFIX="${AISOC_INSTALL_PREFIX:-/opt/aisoc}"
VENV_DIR="${INSTALL_PREFIX}/.venv"
STATE_DIR="${AISOC_STATE_DIR:-/var/lib/aisoc}"
AGENT_STATE_DIR="${AISOC_AGENT_STATE_DIR:-/var/lib/aisoc-agent}"
CONFIG_DIR="${AISOC_CONFIG_DIR:-/etc/aisoc}"
ENV_FILE="${CONFIG_DIR}/aisoc.env"

log() { printf '[aisoc-install] %s\n' "$*"; }
warn() { printf '[aisoc-install] warning: %s\n' "$*" >&2; }
has() { command -v "$1" >/dev/null 2>&1; }

verify_rust_core() {
  "$VENV_DIR/bin/python" - <<'PY'
import aisoc_rust
print(aisoc_rust.version())
PY
}

install_rust_core() {
  if [[ -n "${AISOC_RUST_WHEEL:-}" ]]; then
    [[ -f "$AISOC_RUST_WHEEL" && ! -L "$AISOC_RUST_WHEEL" ]] || {
      echo "AISOC_RUST_WHEEL must be a regular non-symlink wheel file." >&2
      exit 1
    }
    log "installing prebuilt AI-SOC Rust core: ${AISOC_RUST_WHEEL}"
    "$VENV_DIR/bin/python" -m pip install --no-deps "$AISOC_RUST_WHEEL"
    verify_rust_core
    return
  fi

  if has cargo; then
    log "building AI-SOC Rust core from source"
    "$VENV_DIR/bin/python" -m pip install --no-cache-dir "maturin==1.14.1"
    VIRTUAL_ENV="$VENV_DIR" "$VENV_DIR/bin/maturin" develop --locked --release \
      --manifest-path "$PROJECT_ROOT/crates/aisoc-python/Cargo.toml"
    verify_rust_core
    return
  fi

  if ((ALLOW_PYTHON_CORE_FALLBACK)); then
    warn "Rust core unavailable; using the deterministic Python fallback by explicit request."
    return
  fi

  cat >&2 <<'EOF'
AI-SOC Rust core is required for a normal installation.
Provide AISOC_RUST_WHEEL=/path/to/aisoc_python-*.whl, or install Rust/Cargo 1.82+
and rerun. Use --allow-python-core-fallback only for development or diagnostics.
EOF
  exit 1
}

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
  log "detected package manager: ${manager}"
  case "$manager" in
    apt-get)
      apt-get update
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl openssl python3 python3-venv python3-pip
      ;;
    dnf)
      dnf install -y ca-certificates curl openssl python3 python3-pip
      ;;
    yum)
      yum install -y ca-certificates curl openssl python3 python3-pip
      ;;
    zypper)
      zypper --non-interactive install ca-certificates curl openssl python3 python3-pip
      ;;
    pacman)
      pacman -Sy --needed --noconfirm ca-certificates curl openssl python python-pip
      ;;
    *)
      echo "no supported package manager detected; install Python 3.12+, venv/pip, CA certificates and OpenSSL manually." >&2
      exit 1
      ;;
  esac
}

if ((INSTALL_SYSTEM_DEPS)); then
  install_baseline_packages
fi

has python3 || { echo "python3 is required; use --install-system-deps or install it manually." >&2; exit 1; }
python3 - <<'PY'
import sys
if sys.version_info < (3, 12):
    raise SystemExit("Python 3.12 or newer is required")
PY

if ! getent group "$APP_GROUP" >/dev/null 2>&1; then
  has groupadd || { echo "groupadd is required to create the service group." >&2; exit 1; }
  groupadd --system "$APP_GROUP"
fi
if ! id "$APP_USER" >/dev/null 2>&1; then
  has useradd || { echo "useradd is required to create the service account." >&2; exit 1; }
  useradd --system --gid "$APP_GROUP" --no-create-home --shell /usr/sbin/nologin "$APP_USER"
fi

install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" "$INSTALL_PREFIX" "$STATE_DIR"
install -d -m 0750 -o root -g "$APP_GROUP" "$CONFIG_DIR"
if [[ "$ROLE" == "agent" || "$ROLE" == "all" ]]; then
  install -d -m 0750 -o "$APP_USER" -g "$APP_GROUP" "$AGENT_STATE_DIR"
fi

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  log "creating virtual environment: ${VENV_DIR}"
  python3 -m venv "$VENV_DIR" || {
    echo "python3 -m venv failed; install the distribution's Python venv package." >&2
    exit 1
  }
fi
log "installing AI-SOC Python service layer"
"$VENV_DIR/bin/python" -m pip install --upgrade pip wheel setuptools
"$VENV_DIR/bin/python" -m pip install --no-cache-dir "$PROJECT_ROOT"
install_rust_core

# Alembic needs its config and migration package next to the installation root.
install -m 0644 -o root -g "$APP_GROUP" "$PROJECT_ROOT/alembic.ini" "$INSTALL_PREFIX/alembic.ini"
rm -rf "$INSTALL_PREFIX/migrations"
cp -a "$PROJECT_ROOT/migrations" "$INSTALL_PREFIX/migrations"
chown -R root:"$APP_GROUP" "$INSTALL_PREFIX/migrations"

if [[ "$ROLE" == "control" || "$ROLE" == "all" ]]; then
  : "${AISOC_DATABASE_URL:?AISOC_DATABASE_URL is required for control/all roles}"
  umask 027
  cat >"$ENV_FILE" <<EOF
AISOC_ENVIRONMENT=${AISOC_ENVIRONMENT:-development}
AISOC_API_HOST=${AISOC_API_HOST:-127.0.0.1}
AISOC_API_PORT=${AISOC_API_PORT:-8000}
AISOC_INGEST_HOST=${AISOC_INGEST_HOST:-127.0.0.1}
AISOC_INGEST_PORT=${AISOC_INGEST_PORT:-8001}
AISOC_LOG_FORMAT=${AISOC_LOG_FORMAT:-json}
AISOC_DATABASE_URL=${AISOC_DATABASE_URL}
AISOC_OBJECT_STORE_ROOT=${AISOC_OBJECT_STORE_ROOT:-${STATE_DIR}/evidence}
EOF
  for name in \
    AISOC_INGEST_SERVER_NAME \
    AISOC_BOOTSTRAP_ADMIN_TOKEN \
    AISOC_AGENT_CA_CERTIFICATE_PATH \
    AISOC_AGENT_CA_PRIVATE_KEY_PATH \
    AISOC_DETECTION_IOC_FEED_PATH \
    AISOC_DETECTION_IOC_FEED_SHA256; do
    if [[ -n "${!name:-}" ]]; then printf '%s=%s\n' "$name" "${!name}" >>"$ENV_FILE"; fi
  done
  chown root:"$APP_GROUP" "$ENV_FILE"
  chmod 0640 "$ENV_FILE"

  log "applying database migrations"
  runuser -u "$APP_USER" -- env AISOC_DATABASE_URL="$AISOC_DATABASE_URL" \
    "$VENV_DIR/bin/alembic" -c "$INSTALL_PREFIX/alembic.ini" upgrade head
fi

if [[ "$ROLE" == "agent" || "$ROLE" == "all" ]]; then
  : "${AISOC_AGENT_CONFIG_SOURCE:?AISOC_AGENT_CONFIG_SOURCE is required for agent/all roles}"
  [[ -f "$AISOC_AGENT_CONFIG_SOURCE" && ! -L "$AISOC_AGENT_CONFIG_SOURCE" ]] || {
    echo "AISOC_AGENT_CONFIG_SOURCE must be a regular non-symlink file." >&2; exit 1;
  }
  install -m 0600 -o "$APP_USER" -g "$APP_GROUP" "$AISOC_AGENT_CONFIG_SOURCE" "$CONFIG_DIR/agent.json"
  install -m 0640 -o root -g "$APP_GROUP" /dev/null "$CONFIG_DIR/agent.env"
fi

SYSTEMD=0
if [[ "$(cat /proc/1/comm 2>/dev/null || true)" == "systemd" ]] && has systemctl; then
  SYSTEMD=1
fi
if ((SYSTEMD)); then
  log "installing systemd units"
  for unit in aisoc-api.service aisoc-ingest.service aisoc-agent.service; do
    install -m 0644 "$PROJECT_ROOT/deploy/systemd/$unit" "/etc/systemd/system/$unit"
  done
  systemctl daemon-reload
  if ((ENABLE_SERVICES)); then
    if [[ "$ROLE" == "control" || "$ROLE" == "all" ]]; then
      systemctl enable --now aisoc-api.service aisoc-ingest.service
    fi
    if [[ "$ROLE" == "agent" || "$ROLE" == "all" ]]; then
      systemctl enable --now aisoc-agent.service
    fi
  fi
else
  warn "systemd was not detected; service units were not installed. Use the commands below with your init/supervisor."
fi

cat <<EOF

AI-SOC installation completed for role: ${ROLE}
Python environment: ${VENV_DIR}
Configuration:      ${CONFIG_DIR}
State:              ${STATE_DIR}
EOF
if ((!SYSTEMD)); then
  cat <<EOF
Manual control-plane commands:
  ${VENV_DIR}/bin/aisoc-api
  ${VENV_DIR}/bin/aisoc-ingest
Manual Agent command:
  ${VENV_DIR}/bin/aisoc-agent run --config ${CONFIG_DIR}/agent.json
EOF
fi
