---
name: plan-password-reset-smtp
description: Implementation plan for SMTP config UI + self-service password reset — feature/password-reset-smtp branch
metadata:
  type: project
---

**Branch:** `feature/password-reset-smtp`
**Planned:** 2026-05-29

---

## Design Decisions

**Fernet key derivation** — HKDF-SHA256 with fixed info label `b"ssl-manager-smtp-encryption"`, derives 32 bytes from `SECRET_KEY`, base64url-encoded for Fernet. Lives in `app/mail.py`. If `SECRET_KEY` rotates, stored SMTP password becomes unreadable — catch `InvalidToken` and show actionable error rather than 500.

**PasswordResetToken** — separate table (not a column on User). Allows multiple tokens in flight and keeps User clean.

**Rate limiting** — `PasswordResetAttempt` DB table (ip_address + created_at). Count rows for IP in last 15 min; reject if >= 3. Prune old rows on each check. No Redis, no in-memory dict (dies on gunicorn reload).

**SMTP nav placement** — the existing "Settings" nav link (currently `profiles.settings` → profiles list, visible to all users) is repurposed: it points to `/settings/smtp`, is superadmin-only, and becomes the entry point for app configuration. The certificate profiles list gets its own "Profiles" nav link visible to all logged-in users so access is not lost.

**Templates** — SMTP config is a full page (`smtp_config.html`). Forgot-password and reset-password are standalone unauthenticated pages using the existing auth-card layout.

**Session invalidation** — add `session_version INTEGER NOT NULL DEFAULT 0` to User. Increment on password reset. `security_checks()` compares `session["session_version"]` to `current_user.session_version`; mismatch forces logout. Note: Flask-Login `remember` cookies are NOT fully revoked by this — acceptable for this internal tool.

---

## New Files

| File | Purpose |
|---|---|
| `app/mail.py` | `_fernet()`, `send_email()`, `send_test_email()`, `MailNotConfigured` exception |
| `app/routes/smtp.py` | Blueprint: `GET/POST /settings/smtp`, `POST /settings/smtp/test` |
| `app/routes/reset.py` | Blueprint: `GET/POST /forgot-password`, `GET /reset-password/<token>`, `POST /reset-password/<token>` |
| `app/templates/smtp_config.html` | SMTP settings full-page form with provider presets |
| `app/templates/forgot_password.html` | Unauthenticated email entry form |
| `app/templates/reset_password.html` | Unauthenticated new-password form |

---

## Modified Files

| File | Change |
|---|---|
| `app/models.py` | Add `SmtpConfig`, `PasswordResetToken`, `PasswordResetAttempt` models; add `session_version` to `User` |
| `app/__init__.py` | Register 2 new blueprints; import new models into `db.create_all()` scope; add `session_version` to `_add_column_if_missing` + `_ALLOWED_MIGRATIONS` |
| `app/security.py` | Add reset routes to unauthenticated exemption list; add `session_version` check block |
| `app/routes/auth.py` | After `login_user()`, write `session["session_version"] = user.session_version` |
| `app/templates/base.html` | Add "Email Settings" nav link in admin section |
| `app/templates/login.html` | Add "Forgot your password?" link |

---

## Models Detail

### SmtpConfig (singleton — always query `.first()`)
- `provider` String(16): `"m365"` / `"gmail"` / `"custom"`
- `host` String(256), nullable
- `port` Integer, default 587
- `username` String(256), nullable
- `from_address` String(256), nullable
- `_password_encrypted` String(1024), nullable — Fernet ciphertext
- `auth_method` String(16): `"plain"` / `"login"` / `"none"`, default `"login"`
- `use_tls` Boolean, default True (STARTTLS)
- `use_ssl` Boolean, default False (implicit SSL)
- `enabled` Boolean, default False
- Methods: `encrypt_password(raw, fernet)`, `decrypt_password(fernet)` — fernet instance passed in, not imported

### PasswordResetToken
- `user_id` FK→User, CASCADE
- `token_hash` String(64), indexed — SHA-256 hex of raw token
- `created_at`, `expires_at`, `used_at` (nullable) — all UTC datetimes

### PasswordResetAttempt (rate-limit table, no FK)
- `ip_address` String(45), indexed
- `created_at` DateTime UTC

### User (change)
- Add `session_version` Integer, NOT NULL DEFAULT 0

---

## Provider Presets (JS in smtp_config.html)
```javascript
const PRESETS = {
  m365:   { host: 'smtp.office365.com', port: 587, auth_method: 'login', use_tls: true,  use_ssl: false },
  gmail:  { host: 'smtp.gmail.com',     port: 587, auth_method: 'plain', use_tls: true,  use_ssl: false },
  custom: { host: '',                   port: 587, auth_method: 'login', use_tls: false, use_ssl: false },
};
```
Show contextual info alert when M365 or Gmail selected: App Password required (M365 SMTP AUTH must be enabled in admin center; Gmail requires App Password when 2FA is on).

---

## Critical Path (implementation order)

1. Models + migration (`models.py`, `__init__.py`) — everything depends on this
2. `app/mail.py` — required by reset flow
3. `app/routes/smtp.py` + `smtp_config.html` — Part 1 (can do in parallel with step 4 once step 1 done)
4. `app/routes/reset.py` + `forgot_password.html` + `reset_password.html` — Part 2
5. `security.py` session_version check + endpoint exemptions
6. `auth.py` session_version write at login
7. `base.html` nav link + `login.html` forgot-password link

Steps 3 and 4 can be done in parallel.

---

## Security Notes
- Token oracle: hash input, do DB query — no timing oracle
- User enumeration: always return same message regardless of whether email exists or rate limit hit
- Single-use tokens: enforced by `used_at` check
- CSRF: `/forgot-password` and `/reset-password` POST forms must include CSRF token — works without auth since `_get_csrf_token()` writes to session regardless of login state
- TLS+SSL mutual exclusion: validated server-side, shown in UI via JS warning