#!/usr/bin/env bash
# =============================================================================
# Post-install verification — runs INSIDE the systemd container after
# install.sh has completed. Asserts the service, timers, socket, nginx proxy,
# and key file permissions are all as install.sh intends.
# =============================================================================
set -uo pipefail

. /etc/os-release
echo "=== verifying install on ${PRETTY_NAME} ($(uname -m)) ==="

fail=0
check() {  # check "label" "command…"
    if eval "$2" >/dev/null 2>&1; then
        echo "  [OK]   $1"
    else
        echo "  [FAIL] $1"
        fail=1
    fi
}

check "ssl-manager service active"     'systemctl is-active --quiet ssl-manager'
check "backup timer active"            'systemctl is-active --quiet ssl-manager-backup.timer'
check "notify timer active"            'systemctl is-active --quiet ssl-manager-notify.timer'
check "gunicorn socket present"        'test -S /run/ssl-manager/ssl-manager.sock'
check "venv gunicorn installed"        'test -x /opt/ssl-manager/venv/bin/gunicorn'
check "nginx config valid"             'nginx -t'
check "env file mode 640"              '[ "$(stat -c %a /etc/ssl-manager/env)" = "640" ]'
check "data dir mode 700"              '[ "$(stat -c %a /var/lib/ssl-manager)" = "700" ]'

# End-to-end: request through nginx (loopback) → socket → gunicorn → Flask.
# Use python3 (always present — install.sh requires it) so verification needs no
# extra packages like curl/wget on the host image.
code="$(python3 - <<'PY'
import urllib.request, urllib.error
try:
    r = urllib.request.urlopen("http://127.0.0.1:5001/", timeout=10)
    print(r.status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception:
    print("ERR")
PY
)"
check "nginx serves app (HTTP ${code})" '[[ "'"${code}"'" =~ ^(200|302|303|401)$ ]]'

if [[ "${fail}" -ne 0 ]]; then
    echo
    echo "--- systemctl status ssl-manager ---"
    systemctl status ssl-manager --no-pager -l 2>/dev/null | head -30 || true
    echo "--- journal (last 40) ---"
    journalctl -u ssl-manager --no-pager -n 40 2>/dev/null || true
    echo "INSTALL VERIFY FAILED — ${PRETTY_NAME}"
    exit 1
fi

echo "INSTALL VERIFY OK — ${PRETTY_NAME}"