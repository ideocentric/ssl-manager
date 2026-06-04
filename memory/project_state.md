---
name: project-state
description: Current project state as of 2026-05-30 — feature/password-reset-smtp branch ready to commit, Docker tested
metadata:
  type: project
---

## Current state (as of 2026-05-30)

**Active branch: `feature/password-reset-smtp`** — uncommitted, fully implemented and Docker-tested. All 200 tests pass. Needs a commit and PR to master.

`master` is clean and up to date with `origin/master` (last commit `4f0f7b6`).

---

## What's on feature/password-reset-smtp (ready to commit)

Full implementation of SMTP config + password reset. See [[plan-password-reset-smtp]] for detail.

### New files
- `app/mail.py` — Fernet-encrypted SMTP helper, `send_email()`, `send_test_email()`, `MailNotConfigured`
- `app/routes/smtp.py` — `GET/POST /settings/smtp`, `POST /settings/smtp/test` (superadmin only)
- `app/routes/reset.py` — `GET/POST /forgot-password`, `GET/POST /reset-password/<token>` (unauthenticated)
- `app/templates/smtp_config.html` — SMTP settings page with M365/Gmail/Custom provider presets
- `app/templates/forgot_password.html` — unauthenticated email entry form
- `app/templates/reset_password.html` — unauthenticated new-password form

### Modified files
- `app/models.py` — `User.session_version` column; new `SmtpConfig`, `PasswordResetToken`, `PasswordResetAttempt` models
- `app/__init__.py` — registered smtp + reset blueprints; session_version migration; new model imports
- `app/security.py` — `_UNAUTHENTICATED_ENDPOINTS` set; session-version invalidation check
- `app/routes/auth.py` — writes `session["session_version"]` at login
- `app/templates/base.html` — "Settings" nav item moved to superadmin Administration section, points to `/settings/smtp`; old System section removed
- `app/templates/login.html` — "Forgot your password?" link added
- `test_app.py` — fixed pre-existing `TestIntermediateUpdateRoute` fixture regex (was looking for `/edit` URL, template renders `/update`)

---

## Previous work (2026-05-28/29)

- `install-rhel.sh` committed to master — RHEL 9 installer with full SELinux support
- Live RHEL 9 deployment on `brITRHtool10p` — working, all SELinux issues resolved

---

## Docker test instance

Spun up locally via `docker compose up --build -d` on 2026-05-30.
- URL: http://localhost:5001
- Admin credentials: username=`admin`, password=`adminpass1`
- Container may or may not still be running; `docker compose up -d` to restart