#!/usr/bin/env bash
# =============================================================================
# FILE:           backup.sh
# DESCRIPTION:    Online backup script for the SSL Manager SQLite database.
#                 Uses SQLite's .backup command (safe to run while the app is
#                 live) and writes timestamped, gzip-compressed archives.
#
# USAGE:          sudo bash backup.sh [--db FILE] [--dest DIR] [--days N] [--quiet]
#
# OPTIONS:
#   --db FILE     Path to the SQLite database file
#                 (default: /var/lib/ssl-manager/ssl_manager.db)
#   --dest DIR    Directory to write backups to
#                 (default: /var/backups/ssl-manager)
#   --days N      Retain backups for this many days; older files are pruned
#                 (default: 7; set to 0 to disable pruning)
#   --quiet       Suppress informational output (errors are still printed)
#
# EXAMPLES:
#   sudo bash backup.sh
#   sudo bash backup.sh --dest /mnt/nas/backups --days 30
#   sudo bash backup.sh --quiet
#
# SCHEDULING:
#   The recommended way to schedule backups is via the included systemd timer:
#     sudo systemctl enable --now ssl-manager-backup.timer
#     sudo systemctl list-timers ssl-manager-backup.timer
#
#   The timer runs daily at 02:00 and passes --days 7.  To change the
#   retention period edit /etc/systemd/system/ssl-manager-backup.service
#   and run: sudo systemctl daemon-reload
#
# NOTES:
#   - Requires sqlite3 (apt-get install -y sqlite3)
#   - Backups are taken with SQLite's .backup command — consistent snapshot
#     of the live database, no downtime required.
#   - The WAL file is checkpointed before backup so the snapshot is complete.
#   - Each backup is integrity-checked before compression.
#   - Backup filenames: ssl_manager_YYYY-MM-DD_HHMMSS.db.gz
#   - Each run is recorded in the application audit log (action=backup).
#
# AUTHOR:         Matt Comeione <matt@ideocentric.com>
# ORGANIZATION:   ideocentric
# LICENSE:        GNU Affero General Public License v3.0 (AGPL-3.0)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DATA_DIR="/var/lib/ssl-manager"
DB_FILE="${DATA_DIR}/ssl_manager.db"
DEFAULT_DEST="/var/backups/ssl-manager"
DEFAULT_DAYS=7

DEST="${DEFAULT_DEST}"
DAYS="${DEFAULT_DAYS}"
QUIET=false
# DB_FILE may be overridden by --db at parse time

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()  { $QUIET || echo -e "\e[32m[+]\e[0m $*"; }
warn()  { echo -e "\e[33m[!]\e[0m $*" >&2; }
error() { echo -e "\e[31m[✗]\e[0m $*" >&2; exit 1; }

# Write an entry directly into the application audit_log table.
# Uses sqlite3 so it works without the Flask app being involved.
# Arguments: result ("success" | "failure"), detail string
_write_audit() {
    local result="$1"
    local detail="$2"
    # Escape single quotes for SQL string literals
    detail="${detail//\'/''}"
    sqlite3 "${DB_FILE}" \
        "INSERT INTO audit_log (timestamp, username, ip_address, action, resource_type, result, detail)
         VALUES (datetime('now'), 'system', NULL, 'backup', 'database', '${result}', '${detail}');" \
        2>/dev/null || warn "Could not write audit log entry to ${DB_FILE}."
}

# EXIT trap — fires on any non-zero exit so failures are always recorded.
# Skipped when the script exits 0 (success path writes its own entry).
_AUDIT_DETAIL="backup started"
_on_exit() {
    local code=$?
    [[ ${code} -eq 0 ]] && return
    _write_audit "failure" "${_AUDIT_DETAIL} (exit code ${code})"
}
trap _on_exit EXIT

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --db)    DB_FILE="$2"; shift 2 ;;
        --dest)  DEST="$2";    shift 2 ;;
        --days)  DAYS="$2";    shift 2 ;;
        --quiet) QUIET=true;   shift   ;;
        --help|-h)
            sed -n '2,44p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) error "Unknown option: $1" ;;
    esac
done

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
[[ "$(id -u)" -eq 0 ]] || error "This script must be run as root (use sudo)."

command -v sqlite3 &>/dev/null || error "sqlite3 not found. Install with: apt-get install -y sqlite3"

[[ -f "${DB_FILE}" ]] || error "Database not found at ${DB_FILE}"

[[ "${DAYS}" =~ ^[0-9]+$ ]] || error "--days must be a non-negative integer."

# ---------------------------------------------------------------------------
# Prepare destination
# ---------------------------------------------------------------------------
mkdir -p "${DEST}"
chmod 700 "${DEST}"

# ---------------------------------------------------------------------------
# Checkpoint the WAL so the snapshot includes all committed transactions
# ---------------------------------------------------------------------------
info "Checkpointing WAL…"
_AUDIT_DETAIL="wal checkpoint failed"
sqlite3 "${DB_FILE}" "PRAGMA wal_checkpoint(FULL);" > /dev/null

# ---------------------------------------------------------------------------
# Create backup using SQLite's .backup command
# Safe while the application is running — SQLite handles locking internally.
# ---------------------------------------------------------------------------
TIMESTAMP="$(date +%Y-%m-%d_%H%M%S)"
BACKUP_DB="${DEST}/ssl_manager_${TIMESTAMP}.db"
BACKUP_GZ="${BACKUP_DB}.gz"

info "Backing up ${DB_FILE} → ${BACKUP_GZ}…"
_AUDIT_DETAIL="sqlite .backup failed"
sqlite3 "${DB_FILE}" ".backup '${BACKUP_DB}'"

# Verify the backup before compressing
_AUDIT_DETAIL="integrity check failed on backup copy"
INTEGRITY="$(sqlite3 "${BACKUP_DB}" "PRAGMA integrity_check;" 2>&1)"
if [[ "${INTEGRITY}" != "ok" ]]; then
    rm -f "${BACKUP_DB}"
    error "Backup integrity check failed: ${INTEGRITY}"
fi

_AUDIT_DETAIL="gzip compression failed"
gzip -9 "${BACKUP_DB}"
chmod 600 "${BACKUP_GZ}"

SIZE="$(du -sh "${BACKUP_GZ}" | cut -f1)"
info "Backup complete: ${BACKUP_GZ} (${SIZE})"

# ---------------------------------------------------------------------------
# Prune backups older than --days days
# ---------------------------------------------------------------------------
PRUNED=0
if [[ "${DAYS}" -gt 0 ]]; then
    while IFS= read -r OLD; do
        [[ -z "${OLD}" ]] && continue
        info "Pruning: $(basename "${OLD}")"
        rm -f "${OLD}"
        (( PRUNED++ )) || true
    done < <(find "${DEST}" -maxdepth 1 -name "ssl_manager_*.db.gz" -mtime "+${DAYS}" 2>/dev/null)

    if [[ "${PRUNED}" -gt 0 ]]; then
        info "Pruned ${PRUNED} backup(s) older than ${DAYS} day(s)."
    fi
    info "Retaining backups from the last ${DAYS} day(s) in ${DEST}."
fi

# ---------------------------------------------------------------------------
# Record success in the application audit log
# ---------------------------------------------------------------------------
_write_audit "success" "file=$(basename "${BACKUP_GZ}") size=${SIZE} days=${DAYS} pruned=${PRUNED}"

info "Done."
