---
name: project-planned-features
description: Planned development features not yet implemented — password reset, expiry email notifications, P7B intermediate import
metadata:
  type: project
---

Five features are planned for a future development session. None are started; all are greenfield.

**Why:** Identified 2026-05-28 from gaps in the v1.0.0 release, a new real-world issue with GlobalSign certificate bundles, and security hardening goals.

---

## 1. Password Reset (self-service)

The `User` model already stores a validated email address per user. Currently only a superadmin can change another user's password — no self-service "forgot password" flow exists.

**How to apply:** Build a standard token-based reset flow: user submits their email, receives a time-limited link, clicks it, sets a new password. Requires SMTP config (see feature 2). Token should be single-use and expire (e.g. 1 hour). Store token hash in DB, not plaintext.

---

## 2. Expiry Email Notifications

`days_until_expiry` is already implemented on `Certificate`, `CertificateAuthority`, and `IntermediateCert` models and drives the UI colour badges. Nothing sends alerts.

**How to apply:** Add SMTP configuration (host, port, sender address, credentials) — probably stored in the env file (`/etc/ssl-manager/env`) and surfaced in a new app-level Settings section. Add a scheduled job (companion to the existing `ssl-manager-backup.timer`) that queries certs expiring within a configurable threshold (e.g. 30/14/7 days) and emails the relevant users or a notification address. Audit log the sends.

---

## 3. P7B / PKCS#7 Intermediate Import (GlobalSign bundles)

**Problem discovered 2026-05-28:** GlobalSign (and some other CAs) return signed certificates bundled with their intermediate chain in `.p7b` (PKCS#7) format. The app currently has no way to ingest this.

**Desired behaviour — two import paths:**

- **Imported via Chains UI:** Extract all certificates from the P7B. The end-entity (signed) cert should be matched to an existing pending certificate record and imported as its signed cert. The intermediates should be added to the chain.
- **Imported as a Certificate:** Extract the end-entity cert and import it as a signed certificate. Extract the intermediates; if a matching chain does not already exist, create one and attach it. If a matching chain does exist, offer to add the intermediates to it.

**Technical notes:**
- `cryptography` library supports PKCS#7 via `cryptography.hazmat.primitives.serialization.pkcs7` — can parse DER and PEM P7B files.
- Need to distinguish end-entity cert from intermediates: end-entity will have a Subject matching the CSR's CN/SAN; intermediates will have `CA:TRUE` in Basic Constraints.
- Matt wants to think through the exact logic flow before implementation — record this as a design decision pending.

**How to apply:** Add a P7B upload option to both the certificate import flow and the chain management UI. Parse the bundle, split end-entity from intermediates, then route each piece to the appropriate existing import logic.

---

## 4. Configurable Session Timeout

The idle session timeout is currently hardcoded as `IDLE_TIMEOUT = 15 * 60` (15 minutes) in `app/security.py` line 114. The front-end modal countdown (`sessionTimeoutModal` in `base.html`) is also hardcoded to match.

**How to apply:** Move the timeout value into a new app-level `AppConfig` DB table (or extend the existing `Settings` model) so a superadmin can adjust it from the Settings UI. The value should be read at request time (or cached with a short TTL) rather than at startup so changes take effect without a restart. Both the server-side check in `security.py` and the JS countdown in `base.html` need to read the configured value — the JS should receive it via a template variable or a small JSON endpoint.

---

## 5. Multi-Factor Authentication (TOTP)

No MFA exists. Users authenticate with username + password only.

**How to apply:** Add TOTP-based MFA (RFC 6238, compatible with Google Authenticator, Authy, etc.) using the `pyotp` library. Store the TOTP secret (encrypted at rest) on the `User` model along with an `mfa_enabled` boolean. Superadmins can enforce MFA globally via the app-level settings (links to feature 4). Flow: after password check passes, if MFA is enabled for the user, redirect to a TOTP entry page before granting the session. Include backup/recovery codes generated at enrolment time. Audit log enrolment, disablement, and failed TOTP attempts.