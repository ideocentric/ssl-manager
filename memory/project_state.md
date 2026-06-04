---
name: project-state
description: Current project state as of 2026-06-04 — feature/password-reset-smtp merged to master
metadata:
  type: project
---

## Current state (as of 2026-06-04)

**Active branch: `master`** — clean and up to date. `feature/password-reset-smtp` branch committed, PR'd, and merged.

---

## What shipped in the merged branch

- SMTP config + password reset (see [[plan-password-reset-smtp]])
- PEM bundle splitting on cert upload — leaf cert stored cleanly, intermediates auto-added to chain with serial-number deduplication; auto-creates chain named `"{domain} (imported)"` if none assigned
- CSR removed from component ZIP export
- USER_GUIDE updated: Windows 10/11 SSH config instructions, bundle upload behaviour documented, ZIP contents corrected
- README, CHANGELOG, WORKFLOW.md all updated to remove CSR from ZIP docs

---

## Previous work

- `install-rhel.sh` committed to master — RHEL 9 installer with full SELinux support
- Live RHEL 9 deployment on `brITRHtool10p` — working, all SELinux issues resolved

---

## Docker test instance

Last tested 2026-06-04 via `docker compose up --build -d`.
- URL: http://localhost:5001
- Admin credentials: username=`admin`, password=`password`
- Container may or may not still be running; `docker compose up -d` to restart