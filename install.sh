#!/usr/bin/env bash
# =============================================================================
# SSL Manager — Ubuntu installer
#
# Usage:
#   sudo bash install.sh               # interactive install
#   sudo bash install.sh --upgrade     # re-copy app files and restart service
#   sudo bash install.sh --uninstall   # remove service, files, and user
#
# Architecture
#   browser / SSH tunnel
#       → nginx  (127.0.0.1:PORT, listens on loopback only)
#           → Unix socket  (/run/ssl-manager/ssl-manager.sock)
#               → gunicorn  (WSGI workers, run as ssl-manager user)
#                   → Flask app  (/opt/ssl-manager/)
#                       → SQLite  (/var/lib/ssl-manager/, mode 700)
#
# Remote access (no direct exposure needed):
#   ssh -L <localport>:127.0.0.1:<PORT> user@server
#   then open http://localhost:<localport> in your browser
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths and defaults
# ---------------------------------------------------------------------------
APP_NAME="ssl-manager"
APP_DIR="/opt/ssl-manager"
DATA_DIR="/var/lib/ssl-manager"
LOG_DIR="/var/log/ssl-manager"
CONF_DIR="/etc/ssl-manager"
ENV_FILE="${CONF_DIR}/env"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
SERVICE_USER="${APP_NAME}"
SOCKET_PATH="/run/ssl-manager/ssl-manager.sock"
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
    [[ -f /etc/os-release ]] || error "Cannot detect OS. Ubuntu 20.04+ required."
    # shellcheck source=/dev/null
    source /etc/os-release
    [[ "${ID}" == "ubuntu" ]] || error "Ubuntu required. Detected: ${PRETTY_NAME:-unknown}"
    local major; major=$(echo "${VERSION_ID}" | cut -d. -f1)
    [[ "${major}" -ge 20 ]] || error "Ubuntu 20.04+ required. Detected: ${PRETTY_NAME}"
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

    systemctl is-active  --quiet "${APP_NAME}" 2>/dev/null && { info "Stopping service…";   systemctl stop    "${APP_NAME}"; }
    systemctl is-enabled --quiet "${APP_NAME}" 2>/dev/null && { info "Disabling service…";  systemctl disable "${APP_NAME}"; }

    [[ -f "${SERVICE_FILE}" ]] && { info "Removing systemd unit…"; rm -f "${SERVICE_FILE}"; systemctl daemon-reload; }
    [[ -d "${APP_DIR}"      ]] && { info "Removing app files…";    rm -rf "${APP_DIR}"; }
    [[ -d "${CONF_DIR}"     ]] && { info "Removing config…";       rm -rf "${CONF_DIR}"; }
    [[ -d "${LOG_DIR}"      ]] && { info "Removing logs…";         rm -rf "${LOG_DIR}"; }

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
    [[ -d "${APP_DIR}" ]] || error "No existing installation at ${APP_DIR}. Run without --upgrade to install first."
    info "Upgrading app files…"
    copy_app_files
    info "Updating Python dependencies…"
    "${APP_DIR}/venv/bin/pip" install --quiet -r "${APP_DIR}/requirements.txt"
    info "Restarting service…"
    systemctl restart "${APP_NAME}"
    info "Upgrade complete."
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
        nginx
}

create_user() {
    if id "${SERVICE_USER}" &>/dev/null; then
        info "Service user '${SERVICE_USER}' already exists."
    else
        info "Creating service user '${SERVICE_USER}'…"
        # System account: no login shell, no home directory, no password
        useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
    fi

    # nginx (www-data) must be able to reach the Unix socket.
    # Adding www-data to the ssl-manager group is the minimal permission needed.
    if id www-data &>/dev/null; then
        if ! id -nG www-data | grep -qw "${SERVICE_USER}"; then
            info "Adding www-data to the '${SERVICE_USER}' group for socket access…"
            usermod -aG "${SERVICE_USER}" www-data
        fi
    fi
}

create_directories() {
    info "Creating directories…"

    # App files: readable by root and ssl-manager group, not world-readable
    mkdir -p "${APP_DIR}"
    chown root:"${SERVICE_USER}" "${APP_DIR}"
    chmod 750 "${APP_DIR}"

    # Data directory: accessible ONLY by the service user (private key material lives here)
    mkdir -p "${DATA_DIR}"
    chown "${SERVICE_USER}:${SERVICE_USER}" "${DATA_DIR}"
    chmod 700 "${DATA_DIR}"

    # Config directory: root-owned, ssl-manager group can read env file
    mkdir -p "${CONF_DIR}"
    chown root:"${SERVICE_USER}" "${CONF_DIR}"
    chmod 750 "${CONF_DIR}"

    # Log directory: writable by the service user
    mkdir -p "${LOG_DIR}"
    chown "${SERVICE_USER}:${SERVICE_USER}" "${LOG_DIR}"
    chmod 750 "${LOG_DIR}"
}

copy_app_files() {
    info "Copying application files to ${APP_DIR}…"
    cp "${SCRIPT_DIR}/app.py"           "${APP_DIR}/"
    cp "${SCRIPT_DIR}/requirements.txt" "${APP_DIR}/"
    cp -r "${SCRIPT_DIR}/templates"     "${APP_DIR}/"
    cp -r "${SCRIPT_DIR}/static"        "${APP_DIR}/"
    # root owns files; ssl-manager group can read/execute — not world-readable
    chown -R root:"${SERVICE_USER}" "${APP_DIR}"
    chmod -R 750 "${APP_DIR}"
}

create_venv() {
    if [[ ! -d "${APP_DIR}/venv" ]]; then
        info "Creating Python virtual environment…"
        python3 -m venv "${APP_DIR}/venv"
        chown -R root:"${SERVICE_USER}" "${APP_DIR}/venv"
        chmod -R 750 "${APP_DIR}/venv"
    fi
    info "Installing Python dependencies…"
    "${APP_DIR}/venv/bin/pip" install --quiet --upgrade pip
    "${APP_DIR}/venv/bin/pip" install --quiet -r "${APP_DIR}/requirements.txt"
}

write_env_file() {
    local secret="$1"
    info "Writing environment config to ${ENV_FILE}…"
    cat > "${ENV_FILE}" <<EOF
# SSL Manager environment configuration
# Generated by install.sh — edit as needed, then: sudo systemctl restart ssl-manager

SECRET_KEY=${secret}
DATABASE_URL=sqlite:///${DATA_DIR}/ssl_manager.db
EOF
    # Only root can write; ssl-manager user can read (needed by the service)
    chown root:"${SERVICE_USER}" "${ENV_FILE}"
    chmod 640 "${ENV_FILE}"
}

write_systemd_unit() {
    local workers="$1"
    info "Writing systemd unit to ${SERVICE_FILE}…"
    cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=SSL Certificate Manager
Documentation=file://${APP_DIR}/README.md
After=network.target

[Service]
Type=notify
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}

# Create /run/ssl-manager/ (mode 750) at startup; removed automatically on stop
RuntimeDirectory=ssl-manager
RuntimeDirectoryMode=0750

# Gunicorn binds to the Unix socket; umask 007 → socket mode 660
# (www-data is in the ssl-manager group so it can connect)
ExecStart=${APP_DIR}/venv/bin/gunicorn \\
    --workers ${workers} \\
    --bind unix:${SOCKET_PATH} \\
    --umask 007 \\
    --timeout 120 \\
    --access-logfile ${LOG_DIR}/access.log \\
    --error-logfile  ${LOG_DIR}/error.log \\
    app:app

ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=5
Restart=on-failure
RestartSec=5

# ---------- systemd hardening ----------
# Prevent the process from gaining new privileges (e.g. via setuid binaries)
NoNewPrivileges=true

# Give the process its own private /tmp (isolates temporary files)
PrivateTmp=true

# Mount / and /usr read-only; only explicitly listed paths are writable
ProtectSystem=strict
ReadWritePaths=${DATA_DIR} ${LOG_DIR}

# Deny access to /home and /root
ProtectHome=true

# Prevent writing to kernel variables
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true

# Restrict visible device nodes
PrivateDevices=true

# Deny acquiring new capabilities
CapabilityBoundingSet=
AmbientCapabilities=

# Restrict the set of allowed system calls to those needed by a typical service
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

# Restrict address families to those actually used (Unix sockets + TCP/IP for outbound)
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

# Misc lockdowns
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true

[Install]
WantedBy=multi-user.target
EOF
}

configure_nginx() {
    local port="$1"
    info "Writing nginx config to ${NGINX_CONF}…"

    # Rate-limit zone definition goes in the http block.
    # We add it to conf.d so it doesn't conflict with sites.
    cat > /etc/nginx/conf.d/ssl-manager-ratelimit.conf <<'EOF'
# Rate limit for SSL Manager: 10 req/s per client IP, 10 MB zone
limit_req_zone $binary_remote_addr zone=ssl_manager:10m rate=10r/s;
EOF

    cat > "${NGINX_CONF}" <<EOF
# SSL Manager reverse proxy
# Listens on loopback only — not reachable from the network.
# For remote access use SSH port forwarding:
#   ssh -L ${port}:127.0.0.1:${port} user@<server>

server {
    listen 127.0.0.1:${port};
    server_name localhost;

    access_log /var/log/nginx/ssl-manager-access.log;
    error_log  /var/log/nginx/ssl-manager-error.log warn;

    # Match Flask MAX_CONTENT_LENGTH (1 MB)
    client_max_body_size 2M;

    # Serve static assets directly — bypass gunicorn for CSS/JS/icons
    location /static/ {
        alias ${APP_DIR}/static/;
        expires 30d;
        add_header Cache-Control "public, no-transform";
        # Static files need no CSRF or auth headers
    }

    location / {
        # Apply rate limit with a burst allowance of 30
        limit_req zone=ssl_manager burst=30 nodelay;

        proxy_pass http://unix:${SOCKET_PATH};
        proxy_http_version 1.1;

        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_connect_timeout  10s;
        proxy_send_timeout     60s;
        proxy_read_timeout    120s;

        # Prevent nginx version disclosure in proxied error pages
        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
}
EOF

    ln -sf "${NGINX_CONF}" "/etc/nginx/sites-enabled/${APP_NAME}"

    # Disable the default site if still enabled
    rm -f /etc/nginx/sites-enabled/default

    nginx -t || error "nginx configuration test failed — check ${NGINX_CONF}"
    systemctl reload nginx
    info "nginx configured. Listening on 127.0.0.1:${port}"
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

# nginx port (the only port exposed — loopback only)
read -rp "    nginx listen port on 127.0.0.1 [${DEFAULT_PORT}]: " PORT
PORT="${PORT:-${DEFAULT_PORT}}"
[[ "$PORT" =~ ^[0-9]+$ ]] && [[ "$PORT" -ge 1 ]] && [[ "$PORT" -le 65535 ]] || error "Invalid port: ${PORT}"

# Gunicorn workers
read -rp "    Gunicorn worker processes [${DEFAULT_WORKERS}]: " WORKERS
WORKERS="${WORKERS:-${DEFAULT_WORKERS}}"
[[ "$WORKERS" =~ ^[0-9]+$ ]] && [[ "$WORKERS" -ge 1 ]] || error "Invalid worker count."

# Secret key
read -rp "    Secret key (leave blank to auto-generate): " SECRET_KEY
if [[ -z "${SECRET_KEY}" ]]; then
    SECRET_KEY="$(generate_secret)"
    info "Generated a random 256-bit secret key."
fi

echo
info "Installation summary:"
echo "    App directory   : ${APP_DIR}  (root:ssl-manager, mode 750)"
echo "    Data directory  : ${DATA_DIR}  (ssl-manager only, mode 700)"
echo "    Config file     : ${ENV_FILE}  (root:ssl-manager, mode 640)"
echo "    Unix socket     : ${SOCKET_PATH}"
echo "    nginx port      : 127.0.0.1:${PORT}  (loopback only)"
echo "    Gunicorn workers: ${WORKERS}"
echo
warn "The application will only be reachable from the local machine."
warn "For remote access, use SSH port forwarding:"
warn "  ssh -L ${PORT}:127.0.0.1:${PORT} user@<server>"
warn "  then open http://localhost:${PORT} in your browser."
echo
confirm "Proceed with installation?" || { info "Aborted."; exit 0; }
echo

install_packages
create_user
create_directories
copy_app_files
create_venv
write_env_file  "${SECRET_KEY}"
write_systemd_unit "${WORKERS}"
configure_nginx "${PORT}"

info "Enabling and starting ${APP_NAME} service…"
systemctl daemon-reload
systemctl enable --quiet "${APP_NAME}"
systemctl restart "${APP_NAME}"

# Brief pause so gunicorn can create the socket before nginx tries to connect
sleep 2
systemctl is-active --quiet "${APP_NAME}" || {
    warn "Service did not start cleanly. Check logs:"
    journalctl -u "${APP_NAME}" --no-pager -n 30
    exit 1
}

echo
echo "=============================================="
info "Installation complete!"
echo "=============================================="
echo
echo "    Local URL      : http://localhost:${PORT}"
echo "    Remote access  : ssh -L ${PORT}:127.0.0.1:${PORT} user@<server>"
echo "    Service status : sudo systemctl status ${APP_NAME}"
echo "    App logs       : sudo tail -f ${LOG_DIR}/error.log"
echo "    nginx logs     : sudo tail -f /var/log/nginx/ssl-manager-access.log"
echo "    Config         : ${ENV_FILE}"
echo "    Database       : ${DATA_DIR}/ssl_manager.db"
echo
warn "To upgrade after pulling new code:  sudo bash install.sh --upgrade"
warn "To remove everything:               sudo bash install.sh --uninstall"
