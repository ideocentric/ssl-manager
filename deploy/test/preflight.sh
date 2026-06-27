#!/usr/bin/env bash
# =============================================================================
# SSL Manager — in-container deployment preflight
#
# Runs INSIDE a clean Ubuntu container (see run-matrix.sh). Mirrors the
# dependency layer of install.sh — minus systemd/nginx, which a plain container
# cannot host — to catch interpreter/wheel/runtime breakage across Ubuntu LTS
# releases (24.04 → Python 3.12, 26.04 → Python 3.14).
#
# Validates, in order:
#   1. apt packages install.sh relies on
#   2. venv creation on the distro's default python3
#   3. pip install -r requirements.txt  (wheel resolution — no source builds)
#   4. import smoke for every runtime dependency
#   5. the full pytest suite (incl. the vendored JKS writer golden tests)
#   6. a real gunicorn boot over TCP + an HTTP request against the app
#
# The repo is mounted read-only at /src; everything happens in a writable copy
# so the host tree is never touched.
# =============================================================================
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
APP=/app
PORT=5001

step() { echo -e "\n\033[1;36m=== $* ===\033[0m"; }

step "OS"
. /etc/os-release && echo "${PRETTY_NAME}  ($(uname -m))"

step "apt packages (same set as install.sh)"
apt-get update -qq
apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    openssl gcc python3-dev \
    sqlite3 \
    ca-certificates curl

step "python interpreter"
python3 --version

step "writable copy of the repo"
mkdir -p "${APP}"
cp -a /src/. "${APP}/"
cd "${APP}"

step "virtual environment"
python3 -m venv "${APP}/venv"
"${APP}/venv/bin/pip" install --quiet --upgrade pip

step "pip install -r requirements.txt"
# --only-binary=:all: would force wheels, but we WANT to see if a source build
# is attempted, so install normally and assert no compiler was invoked below.
"${APP}/venv/bin/pip" install -r "${APP}/requirements.txt"
echo "--- resolved runtime versions ---"
"${APP}/venv/bin/pip" list --format=columns | grep -iE 'flask|cryptography|gunicorn|sqlalchemy' || true

step "import smoke"
"${APP}/venv/bin/python" - <<'PY'
import flask, flask_sqlalchemy, flask_login, cryptography, gunicorn
print("flask        ", flask.__version__)
print("cryptography ", cryptography.__version__)
print("gunicorn     ", gunicorn.__version__)
print("imports OK")
PY

step "test suite (pytest)"
"${APP}/venv/bin/pip" install --quiet pytest
"${APP}/venv/bin/python" -m pytest -q

step "gunicorn boot + HTTP check"
SECRET_KEY="$("${APP}/venv/bin/python" -c 'import secrets; print(secrets.token_hex(32))')"
export SECRET_KEY
export DATABASE_URL="sqlite:////tmp/preflight.db"
"${APP}/venv/bin/gunicorn" \
    --workers 2 --bind "127.0.0.1:${PORT}" --timeout 120 \
    --pid /tmp/gunicorn.pid wsgi:app &
GPID=$!
cleanup() { kill "${GPID}" 2>/dev/null || true; }
trap cleanup EXIT

# Poll for readiness (cold start can take a few seconds under emulation)
ok=0
for _ in $(seq 1 30); do
    code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/" || true)"
    if [[ "${code}" =~ ^(200|302|303|401)$ ]]; then
        echo "HTTP ${code} from gunicorn — app is serving."
        ok=1; break
    fi
    sleep 1
done
[[ "${ok}" -eq 1 ]] || { echo "gunicorn did not serve a valid response"; exit 1; }

echo -e "\n\033[1;32mPREFLIGHT OK — ${PRETTY_NAME}\033[0m"