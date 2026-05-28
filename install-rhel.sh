#!/usr/bin/env bash
# =============================================================================
# SSL Manager — RHEL / Rocky Linux / AlmaLinux / CentOS Stream installer
#
# Usage:
#   sudo bash install-rhel.sh               # interactive install
#   sudo bash install-rhel.sh --upgrade     # re-copy app files and restart service
#   sudo bash install-rhel.sh --uninstall   # remove service, files, and user
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
#
# SELinux
#   This installer configures SELinux to allow nginx to communicate with the
#   gunicorn Unix socket.  It sets the httpd_var_run_t file context on the
#   socket directory and enables the httpd_can_network_connect boolean.
#   Requires: policycoreutils-python-utils (installed automatically).
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
BACKUP_SERVICE_FILE="/etc/systemd/system/${APP_NAME}-backup.service"
BACKUP_TIMER_FILE="/etc/systemd/system/${APP_NAME}-backup.timer"
SERVICE_USER="${APP_NAME}"
NGINX_USER="nginx"
SOCKET_PATH="/run/ssl-manager/ssl-manager.sock"
# RHEL uses /etc/nginx/conf.d/ — no sites-available/sites-enabled
NGINX_CONF="/etc/nginx/conf.d/${APP_NAME}.conf"
NGINX_RATELIMIT_CONF="/etc/nginx/conf.d/ssl-manager-ratelimit.conf"
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

require_rhel() {
    [[ -f /etc/os-release ]] || error "Cannot detect OS. RHEL 8+ / Rocky / AlmaLinux / CentOS Stream required."
    # shellcheck source=/dev/null
    source /etc/os-release
    case "${ID}" in
        rhel|centos|rocky|almalinux|fedora) ;;
        *) error "RHEL-family OS required. Detected: ${PRETTY_NAME:-unknown}" ;;
    esac
    local major; major=$(echo "${VERSION_ID}" | cut -d. -f1)
    if [[ "${ID}" != "fedora" ]] && [[ "${major}" -lt 8 ]]; then
        error "RHEL 8+ (or equivalent) required. Detected: ${PRETTY_NAME}"
    fi
    info "Detected: ${PRETTY_NAME}"
}

generate_secret() {
    python3 -c "import secrets; print(secrets.token_hex(32))"
}

selinux_active() {
    command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" != "Disabled" ]]
}

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------
do_uninstall() {
    warn "This will stop and remove the ${APP_NAME} service and all installed files."
    warn "The database at ${DATA_DIR} will NOT be deleted unless you confirm below."
    echo
    confirm "Proceed with uninstall?" n || { info "Aborted."; exit 0; }

    systemctl is-active  --quiet "${APP_NAME}-backup.timer" 2>/dev/null && { info "Stopping backup timer…";   systemctl stop    "${APP_NAME}-backup.timer"; }
    systemctl is-enabled --quiet "${APP_NAME}-backup.timer" 2>/dev/null && { info "Disabling backup timer…";  systemctl disable "${APP_NAME}-backup.timer"; }
    systemctl is-active  --quiet "${APP_NAME}" 2>/dev/null && { info "Stopping service…";   systemctl stop    "${APP_NAME}"; }
    systemctl is-enabled --quiet "${APP_NAME}" 2>/dev/null && { info "Disabling service…";  systemctl disable "${APP_NAME}"; }

    [[ -f "${BACKUP_TIMER_FILE}"   ]] && rm -f "${BACKUP_TIMER_FILE}"
    [[ -f "${BACKUP_SERVICE_FILE}" ]] && rm -f "${BACKUP_SERVICE_FILE}"
    [[ -f "${SERVICE_FILE}" ]] && { info "Removing systemd units…"; rm -f "${SERVICE_FILE}"; systemctl daemon-reload; }
    [[ -d "${APP_DIR}"      ]] && { info "Removing app files…";    rm -rf "${APP_DIR}"; }
    [[ -d "${CONF_DIR}"     ]] && { info "Removing config…";       rm -rf "${CONF_DIR}"; }
    [[ -d "${LOG_DIR}"      ]] && { info "Removing logs…";         rm -rf "${LOG_DIR}"; }

    if [[ -f "${NGINX_CONF}" ]]; then
        info "Removing nginx config…"
        rm -f "${NGINX_CONF}" "${NGINX_RATELIMIT_CONF}"
        systemctl reload nginx 2>/dev/null || true
    fi

    if selinux_active && command -v semanage &>/dev/null; then
        info "Removing SELinux file context policy for socket directory…"
        semanage fcontext -d "/var/run/ssl-manager(/.*)?" 2>/dev/null || true
        semodule -r ssl-manager-nginx 2>/dev/null || true
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

    if [[ -f "${DATA_DIR}/ssl_manager.db" ]]; then
        info "Backing up database before upgrade…"
        if bash "${SCRIPT_DIR}/backup.sh" --quiet; then
            info "Database backup complete."
        else
            warn "Database backup failed. Proceeding anyway — check /var/backups/ssl-manager manually."
        fi
    fi

    info "Upgrading app files…"
    copy_app_files
    info "Updating Python dependencies…"
    "${APP_DIR}/venv/bin/pip" install --quiet -r "${APP_DIR}/requirements.txt"
    info "Reloading systemd units…"
    systemctl daemon-reload
    systemctl enable --quiet "${APP_NAME}-backup.timer"
    systemctl restart "${APP_NAME}-backup.timer"
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
    info "Installing system packages via dnf…"

    # EPEL is only needed on CentOS/Rocky/AlmaLinux — all required packages
    # (python3, nginx, policycoreutils-python-utils) are in RHEL 9 AppStream/BaseOS.
    # On registered RHEL, 'epel-release' is not in any default repo; install it
    # via the Fedora RPM URL only if the distro is not plain RHEL.
    # shellcheck source=/dev/null
    source /etc/os-release
    if [[ "${ID}" != "rhel" ]]; then
        if ! rpm -q epel-release &>/dev/null; then
            info "Enabling EPEL…"
            dnf install -y epel-release
        fi
    fi

    dnf install -y \
        python3 python3-pip python3-devel \
        openssl gcc \
        nginx \
        policycoreutils-python-utils
}

create_user() {
    if id "${SERVICE_USER}" &>/dev/null; then
        info "Service user '${SERVICE_USER}' already exists."
    else
        info "Creating service user '${SERVICE_USER}'…"
        # System account: no login shell, no home directory, no password
        useradd --system --no-create-home --shell /sbin/nologin "${SERVICE_USER}"
    fi

    # nginx must be able to reach the Unix socket.
    # Adding the nginx user to the ssl-manager group is the minimal permission needed.
    if id "${NGINX_USER}" &>/dev/null; then
        if ! id -nG "${NGINX_USER}" | grep -qw "${SERVICE_USER}"; then
            info "Adding '${NGINX_USER}' to the '${SERVICE_USER}' group for socket access…"
            usermod -aG "${SERVICE_USER}" "${NGINX_USER}"
        fi
    fi
}

create_directories() {
    info "Creating directories…"

    mkdir -p "${APP_DIR}"
    chown root:"${SERVICE_USER}" "${APP_DIR}"
    chmod 750 "${APP_DIR}"

    mkdir -p "${DATA_DIR}"
    chown "${SERVICE_USER}:${SERVICE_USER}" "${DATA_DIR}"
    chmod 700 "${DATA_DIR}"

    mkdir -p "${CONF_DIR}"
    chown root:"${SERVICE_USER}" "${CONF_DIR}"
    chmod 750 "${CONF_DIR}"

    mkdir -p "${LOG_DIR}"
    chown "${SERVICE_USER}:${SERVICE_USER}" "${LOG_DIR}"
    chmod 750 "${LOG_DIR}"
}

copy_app_files() {
    info "Copying application files to ${APP_DIR}…"
    cp "${SCRIPT_DIR}/wsgi.py"          "${APP_DIR}/"
    cp "${SCRIPT_DIR}/requirements.txt" "${APP_DIR}/"
    cp "${SCRIPT_DIR}/backup.sh"        "${APP_DIR}/"
    cp -r "${SCRIPT_DIR}/app"           "${APP_DIR}/"

    cp "${SCRIPT_DIR}/deploy/systemd/ssl-manager-backup.service" "${BACKUP_SERVICE_FILE}"
    cp "${SCRIPT_DIR}/deploy/systemd/ssl-manager-backup.timer"   "${BACKUP_TIMER_FILE}"
    chmod 644 "${BACKUP_SERVICE_FILE}" "${BACKUP_TIMER_FILE}"
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
# Generated by install-rhel.sh — edit as needed, then: sudo systemctl restart ssl-manager

SECRET_KEY=${secret}
DATABASE_URL=sqlite:///${DATA_DIR}/ssl_manager.db
EOF
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
# (nginx user is in the ssl-manager group so it can connect)
# Timeout of 120s covers RSA-4096 CA key generation on constrained hardware
ExecStart=${APP_DIR}/venv/bin/gunicorn \\
    --workers ${workers} \\
    --bind unix:${SOCKET_PATH} \\
    --umask 007 \\
    --timeout 120 \\
    --access-logfile ${LOG_DIR}/access.log \\
    --error-logfile  ${LOG_DIR}/error.log \\
    wsgi:app

ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=mixed
TimeoutStopSec=5
Restart=on-failure
RestartSec=5

# ---------- systemd hardening ----------
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${DATA_DIR} ${LOG_DIR}
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
PrivateDevices=true
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
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

    # Rate-limit zone — goes in conf.d so it lives in the http block
    cat > "${NGINX_RATELIMIT_CONF}" <<'EOF'
# Rate limit for SSL Manager: 10 req/s per client IP, 10 MB zone
limit_req_zone $binary_remote_addr zone=ssl_manager:10m rate=10r/s;
EOF

    # On RHEL, nginx config goes directly in conf.d/ — no sites-available/sites-enabled
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

    client_max_body_size 2M;

    location /static/ {
        alias ${APP_DIR}/app/static/;
        expires 30d;
        add_header Cache-Control "public, no-transform";
    }

    location / {
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

        proxy_hide_header X-Powered-By;
        proxy_hide_header Server;
    }
}
EOF

    nginx -t || error "nginx configuration test failed — check ${NGINX_CONF}"
    systemctl enable --quiet nginx
    # nginx start/reload is deferred until after the app service creates its socket;
    # we just write the config here and let the main flow handle the start.
    info "nginx config written. Will start after app service is up."
}

configure_selinux() {
    local port="$1"

    if ! selinux_active; then
        info "SELinux is disabled — skipping SELinux configuration."
        return
    fi

    info "Configuring SELinux…"

    if ! command -v semanage &>/dev/null; then
        warn "semanage not found. Attempting to install policycoreutils-python-utils…"
        dnf install -y policycoreutils-python-utils || \
            error "Could not install policycoreutils-python-utils. SELinux configuration incomplete."
    fi

    # nginx can only bind to ports listed under http_port_t.
    # Port 5001 (and any non-standard port) must be added explicitly.
    info "SELinux: allowing nginx to bind to port ${port}…"
    if ! semanage port -l | grep -qP "http_port_t\s+tcp.*\b${port}\b"; then
        if semanage port -a -t http_port_t -p tcp "${port}" 2>/dev/null; then
            info "SELinux: port ${port} added to http_port_t."
        else
            # Port may already be defined under a different type — modify it
            semanage port -m -t http_port_t -p tcp "${port}" 2>/dev/null || \
                warn "SELinux: could not add port ${port} to http_port_t — nginx may fail to bind."
        fi
    else
        info "SELinux: port ${port} already permitted for http_port_t."
    fi

    # Allow nginx (httpd_t domain) to connect to the gunicorn Unix socket.
    # The socket lives in /run/ssl-manager/ (a RuntimeDirectory).
    # On RHEL 9, /run is a symlink to /var/run and SELinux has an equivalency
    # rule for that path — fcontext must use /var/run, not /run.
    info "SELinux: setting httpd_var_run_t context on /var/run/ssl-manager/…"
    if semanage fcontext -a -t httpd_var_run_t "/var/run/ssl-manager(/.*)?" 2>/dev/null; then
        info "SELinux: fcontext rule added."
    else
        semanage fcontext -m -t httpd_var_run_t "/var/run/ssl-manager(/.*)?" 2>/dev/null || \
            warn "SELinux: could not add fcontext rule — you may need to run this manually."
    fi

    # Belt-and-suspenders: allow nginx to proxy upstream connections
    info "SELinux: enabling httpd_can_network_connect boolean…"
    setsebool -P httpd_can_network_connect 1

    # Gunicorn runs as unconfined_service_t (no dedicated SELinux policy).
    # nginx (httpd_t) is denied 'connectto' on unix_stream_socket owned by
    # unconfined_service_t unless we explicitly allow it with a policy module.
    info "SELinux: installing nginx → gunicorn socket policy module…"
    local te_file; te_file="$(mktemp /tmp/ssl-manager-nginx-XXXXXX.te)"
    cat > "${te_file}" <<'SEPOLICY'
module ssl-manager-nginx 1.0;

require {
    type httpd_t;
    type unconfined_service_t;
    class unix_stream_socket connectto;
}

allow httpd_t unconfined_service_t:unix_stream_socket connectto;
SEPOLICY

    local mod_file="${te_file%.te}.mod"
    local pp_file="${te_file%.te}.pp"
    if checkmodule -M -m -o "${mod_file}" "${te_file}" && \
       semodule_package -o "${pp_file}" -m "${mod_file}" && \
       semodule -i "${pp_file}"; then
        info "SELinux: policy module ssl-manager-nginx installed."
    else
        warn "SELinux: could not install policy module — nginx may get 502 errors."
        warn "  Manual fix: ausearch -m avc -ts recent | audit2allow -M ssl-manager-nginx && semodule -i ssl-manager-nginx.pp"
    fi
    rm -f "${te_file}" "${mod_file}" "${pp_file}"

    info "SELinux configuration applied."
}

restorecon_socket_dir() {
    # Called after the service starts so the RuntimeDirectory exists
    if selinux_active && command -v restorecon &>/dev/null; then
        info "SELinux: applying file contexts to /run/ssl-manager/…"
        restorecon -Rv /run/ssl-manager/ 2>/dev/null || true
    fi
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
            sed -n '2,20p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) error "Unknown option: $arg" ;;
    esac
done

require_root
require_rhel

[[ "$MODE" == "uninstall" ]] && do_uninstall
[[ "$MODE" == "upgrade"   ]] && do_upgrade

# ---- Interactive install ----
echo
echo "=============================================="
echo "  SSL Manager — RHEL Installer"
echo "=============================================="
echo

read -rp "    nginx listen port on 127.0.0.1 [${DEFAULT_PORT}]: " PORT
PORT="${PORT:-${DEFAULT_PORT}}"
[[ "$PORT" =~ ^[0-9]+$ ]] && [[ "$PORT" -ge 1 ]] && [[ "$PORT" -le 65535 ]] || error "Invalid port: ${PORT}"

read -rp "    Gunicorn worker processes [${DEFAULT_WORKERS}]: " WORKERS
WORKERS="${WORKERS:-${DEFAULT_WORKERS}}"
[[ "$WORKERS" =~ ^[0-9]+$ ]] && [[ "$WORKERS" -ge 1 ]] || error "Invalid worker count."

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
if selinux_active; then
    echo "    SELinux         : will configure httpd_var_run_t + httpd_can_network_connect"
fi
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
configure_selinux "${PORT}"
configure_nginx "${PORT}"

info "Enabling and starting ${APP_NAME} service…"
systemctl daemon-reload
systemctl enable --quiet "${APP_NAME}"
systemctl restart "${APP_NAME}"

# Restore SELinux contexts now that the RuntimeDirectory and socket exist
restorecon_socket_dir

# Start (or reload) nginx now that the socket is live and contexts are applied
info "Starting nginx…"
systemctl reload nginx 2>/dev/null || systemctl start nginx || {
    warn "nginx failed to start. Check: sudo journalctl -u nginx --no-pager -n 30"
    warn "Common cause on RHEL: run 'sudo semanage port -l | grep http_port_t' to verify port ${PORT} is listed."
}

info "Enabling daily backup timer…"
systemctl enable --quiet "${APP_NAME}-backup.timer"
systemctl start  "${APP_NAME}-backup.timer"

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
warn "The database contains private key material (certificate keys AND CA private keys)."
warn "Treat backup archives at /var/backups/ssl-manager/ with the same sensitivity."
warn "Restrict backup storage access accordingly if offsite copies are made."
echo
warn "To upgrade after pulling new code:  sudo bash install-rhel.sh --upgrade"
warn "To remove everything:               sudo bash install-rhel.sh --uninstall"