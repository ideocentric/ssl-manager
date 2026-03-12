#!/usr/bin/env bash
# =============================================================================
# SSL Manager — Ubuntu installer
#
# Usage:
#   sudo bash install.sh               # interactive install
#   sudo bash install.sh --upgrade     # re-copy app files and restart service
#   sudo bash install.sh --uninstall   # remove service, files, and user
#
# What it does:
#   - Installs system packages (Python 3, pip, openssl, gcc)
#   - Creates a dedicated 'ssl-manager' service account
#   - Copies app files to /opt/ssl-manager
#   - Creates a Python venv and installs dependencies (incl. gunicorn)
#   - Writes environment config to /etc/ssl-manager/env
#   - Installs and starts a systemd service
#   - Optionally configures an nginx reverse proxy
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths and defaults
# ---------------------------------------------------------------------------
APP_NAME="ssl-manager"
APP_DIR="/opt/ssl-manager"
DATA_DIR="/var/lib/ssl-manager"
CONF_DIR="/etc/ssl-manager"
ENV_FILE="${CONF_DIR}/env"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
SERVICE_USER="${APP_NAME}"
NGINX_CONF="/etc/nginx/sites-available/${APP_NAME}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DEFAULT_PORT=5001
DEFAULT_WORKERS=2

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()    { echo -e "\e[32m[+]\e[0m $*"; }
warn()    { echo -e "\e[33m[!]\e[0m $*"; }
error()   { echo -e "\e[31m[✗]\e[0m $*" >&2; exit 1; }
confirm() {
    local prompt="$1" default="${2:-y}"
    local yn_hint; [[ "$default" == "y" ]] && yn_hint="[Y/n]" || yn_hint="[y/N]"
    read -rp "    ${prompt} ${yn_hint} " answer
    answer="${answer:-$default}"
    [[ "$answer" =~ ^[Yy]$ ]]
}

require_root() {
    [[ "$(id -u)" -eq 0 ]] || error "This script must be run as root (use sudo)."
}

require_ubuntu() {
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot detect OS. This installer requires Ubuntu 20.04 or later."
    fi
    # shellcheck source=/dev/null
    source /etc/os-release
    if [[ "${ID}" != "ubuntu" ]]; then
        error "This installer requires Ubuntu. Detected: ${PRETTY_NAME:-unknown}"
    fi
    local major; major=$(echo "${VERSION_ID}" | cut -d. -f1)
    if [[ "${major}" -lt 20 ]]; then
        error "Ubuntu 20.04 or later is required. Detected: ${PRETTY_NAME}"
    fi
    info "Detected: ${PRETTY_NAME}"
}

generate_secret() {
    python3 -c "import secrets; print(secrets.token_hex(32))"
}

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------
do_uninstall() {
    warn "This will stop and remove the ${APP_NAME} service and all installed files."
    warn "The database at ${DATA_DIR} will NOT be deleted unless you confirm below."
    echo
    confirm "Proceed with uninstall?" n || { info "Aborted."; exit 0; }

    if systemctl is-active --quiet "${APP_NAME}" 2>/dev/null; then
        info "Stopping service…"
        systemctl stop "${APP_NAME}"
    fi
    if systemctl is-enabled --quiet "${APP_NAME}" 2>/dev/null; then
        info "Disabling service…"
        systemctl disable "${APP_NAME}"
    fi

    [[ -f "${SERVICE_FILE}" ]] && { info "Removing systemd unit…"; rm -f "${SERVICE_FILE}"; systemctl daemon-reload; }
    [[ -d "${APP_DIR}" ]]      && { info "Removing app files…";    rm -rf "${APP_DIR}"; }
    [[ -d "${CONF_DIR}" ]]     && { info "Removing config…";       rm -rf "${CONF_DIR}"; }

    if [[ -f "${NGINX_CONF}" ]]; then
        info "Removing nginx config…"
        rm -f "${NGINX_CONF}" "/etc/nginx/sites-enabled/${APP_NAME}"
        systemctl reload nginx 2>/dev/null || true
    fi

    if confirm "Also delete the database directory (${DATA_DIR})?" n; then
        rm -rf "${DATA_DIR}"
        info "Database removed."
    else
        info "Database kept at ${DATA_DIR}."
    fi

    if id "${SERVICE_USER}" &>/dev/null; then
        confirm "Remove service user '${SERVICE_USER}'?" n && userdel "${SERVICE_USER}" && info "User removed."
    fi

    info "Uninstall complete."
    exit 0
}

do_upgrade() {
    [[ -d "${APP_DIR}" ]] || error "No existing installation found at ${APP_DIR}. Run without --upgrade to install."
    info "Upgrading app files…"
    copy_app_files
    info "Updating Python dependencies…"
    "${APP_DIR}/venv/bin/pip" install --quiet -r "${APP_DIR}/requirements.txt"
    info "Restarting service…"
    systemctl restart "${APP_NAME}"
    info "Upgrade complete. Service status:"
    systemctl status "${APP_NAME}" --no-pager -l
    exit 0
}

# ---------------------------------------------------------------------------
# Installation steps
# ---------------------------------------------------------------------------
install_packages() {
    info "Updating apt and installing system packages…"
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        openssl gcc python3-dev \
        nginx 2>/dev/null || \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        openssl gcc python3-dev
}

create_user() {
    if id "${SERVICE_USER}" &>/dev/null; then
        info "Service user '${SERVICE_USER}' already exists."
    else
        info "Creating service user '${SERVICE_USER}'…"
        useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
    fi
}

create_directories() {
    info "Creating directories…"
    mkdir -p "${APP_DIR}" "${DATA_DIR}" "${CONF_DIR}"
    chown "${SERVICE_USER}:${SERVICE_USER}" "${DATA_DIR}"
    chmod 750 "${DATA_DIR}"
    chmod 750 "${CONF_DIR}"
}

copy_app_files() {
    info "Copying application files to ${APP_DIR}…"
    cp "${SCRIPT_DIR}/app.py"           "${APP_DIR}/"
    cp "${SCRIPT_DIR}/requirements.txt" "${APP_DIR}/"
    cp -r "${SCRIPT_DIR}/templates"     "${APP_DIR}/"
    cp -r "${SCRIPT_DIR}/static"        "${APP_DIR}/"
    chown -R root:"${SERVICE_USER}" "${APP_DIR}"
    chmod -R 750 "${APP_DIR}"
}

create_venv() {
    if [[ -d "${APP_DIR}/venv" ]]; then
        info "Python venv already exists, skipping creation."
    else
        info "Creating Python virtual environment…"
        python3 -m venv "${APP_DIR}/venv"
    fi
    info "Installing Python dependencies…"
    "${APP_DIR}/venv/bin/pip" install --quiet --upgrade pip
    "${APP_DIR}/venv/bin/pip" install --quiet -r "${APP_DIR}/requirements.txt"
}

write_env_file() {
    local port="$1" secret="$2"
    info "Writing environment config to ${ENV_FILE}…"
    cat > "${ENV_FILE}" <<EOF
# SSL Manager environment configuration
# Generated by install.sh — edit as needed, then: sudo systemctl restart ssl-manager

SECRET_KEY=${secret}
DATABASE_URL=sqlite:///${DATA_DIR}/ssl_manager.db
PORT=${port}
EOF
    chmod 640 "${ENV_FILE}"
    chown root:"${SERVICE_USER}" "${ENV_FILE}"
}

write_systemd_unit() {
    local port="$1" workers="$2"
    info "Writing systemd unit to ${SERVICE_FILE}…"
    cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=SSL Manager
Documentation=https://github.com/your-org/ssl-manager
After=network.target

[Service]
Type=notify
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${APP_DIR}/venv/bin/gunicorn \\
    --workers ${workers} \\
    --bind 127.0.0.1:${port} \\
    --timeout 120 \\
    --access-logfile - \\
    --error-logfile - \\
    app:app
ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
NoNewPrivileges=true
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

configure_nginx() {
    local port="$1" domain="$2"
    info "Writing nginx config to ${NGINX_CONF}…"
    cat > "${NGINX_CONF}" <<EOF
server {
    listen 80;
    server_name ${domain};

    # Increase upload size for certificate PEM pastes
    client_max_body_size 1m;

    location / {
        proxy_pass         http://127.0.0.1:${port};
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;
    }
}
EOF
    ln -sf "${NGINX_CONF}" "/etc/nginx/sites-enabled/${APP_NAME}"
    # Remove default site if it's still there
    rm -f /etc/nginx/sites-enabled/default
    nginx -t && systemctl reload nginx
    info "nginx configured. SSL Manager will be available at http://${domain}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
MODE="install"
for arg in "$@"; do
    case "$arg" in
        --uninstall) MODE="uninstall" ;;
        --upgrade)   MODE="upgrade"   ;;
        --help|-h)
            sed -n '2,15p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) error "Unknown option: $arg" ;;
    esac
done

require_root
require_ubuntu

[[ "$MODE" == "uninstall" ]] && do_uninstall
[[ "$MODE" == "upgrade"   ]] && do_upgrade

# ---- Interactive install ----
echo
echo "=============================================="
echo "  SSL Manager — Installer"
echo "=============================================="
echo

# Port
read -rp "    Listen port [${DEFAULT_PORT}]: " PORT
PORT="${PORT:-${DEFAULT_PORT}}"
[[ "$PORT" =~ ^[0-9]+$ ]] && [[ "$PORT" -ge 1 ]] && [[ "$PORT" -le 65535 ]] || error "Invalid port: ${PORT}"

# Workers
read -rp "    Gunicorn worker processes [${DEFAULT_WORKERS}]: " WORKERS
WORKERS="${WORKERS:-${DEFAULT_WORKERS}}"
[[ "$WORKERS" =~ ^[0-9]+$ ]] && [[ "$WORKERS" -ge 1 ]] || error "Invalid worker count."

# Secret key
read -rp "    Secret key (leave blank to auto-generate): " SECRET_KEY
if [[ -z "${SECRET_KEY}" ]]; then
    SECRET_KEY="$(generate_secret)"
    info "Generated secret key."
fi

# nginx
SETUP_NGINX=false
if command -v nginx &>/dev/null || confirm "Install and configure nginx as a reverse proxy?"; then
    SETUP_NGINX=true
    read -rp "    Server name / domain (e.g. ssl.example.com or _): " NGINX_DOMAIN
    NGINX_DOMAIN="${NGINX_DOMAIN:-_}"
fi

echo
info "Installation summary:"
echo "    App directory : ${APP_DIR}"
echo "    Data directory: ${DATA_DIR}"
echo "    Config file   : ${ENV_FILE}"
echo "    Service port  : ${PORT}"
echo "    Workers       : ${WORKERS}"
echo "    nginx proxy   : ${SETUP_NGINX}"
echo
confirm "Proceed with installation?" || { info "Aborted."; exit 0; }
echo

install_packages
create_user
create_directories
copy_app_files
create_venv
write_env_file  "${PORT}" "${SECRET_KEY}"
write_systemd_unit "${PORT}" "${WORKERS}"

info "Enabling and starting ${APP_NAME} service…"
systemctl daemon-reload
systemctl enable --quiet "${APP_NAME}"
systemctl restart "${APP_NAME}"

if [[ "${SETUP_NGINX}" == true ]]; then
    configure_nginx "${PORT}" "${NGINX_DOMAIN}"
fi

echo
echo "=============================================="
info "Installation complete!"
echo "=============================================="
echo
if [[ "${SETUP_NGINX}" == true ]]; then
    echo "    URL            : http://${NGINX_DOMAIN}"
else
    echo "    URL            : http://<server-ip>:${PORT}"
    warn "gunicorn is bound to 127.0.0.1 only. Use nginx or a firewall rule to expose it."
fi
echo "    Service status : sudo systemctl status ${APP_NAME}"
echo "    Logs           : sudo journalctl -u ${APP_NAME} -f"
echo "    Config         : ${ENV_FILE}"
echo "    Database       : ${DATA_DIR}/ssl_manager.db"
echo
warn "To upgrade after pulling new code:  sudo bash install.sh --upgrade"
warn "To remove everything:               sudo bash install.sh --uninstall"
