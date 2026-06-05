---
name: project-planned-features
description: Planned development features — nine features across import, backup, help, documentation, and security hardening
metadata:
  type: project
---

Nine features planned. Password reset + SMTP shipped 2026-06-04.

---

## 2. Expiry Email Notifications

`days_until_expiry` is already implemented on `Certificate`, `CertificateAuthority`, and `IntermediateCert` models and drives the UI colour badges. SMTP is now live. Nothing sends alerts yet.

**How to apply:** Add a scheduled job (companion to the existing `ssl-manager-backup.timer`) that queries certs expiring within a configurable threshold (e.g. 30/14/7 days) and emails the relevant users or a notification address. Configurable threshold and recipient stored in `SmtpConfig` or a new `AppConfig` table. Audit log the sends.

---

## 3. Smart Bundle Import, P7B + PKCS12/Keypair Import

**Scope expanded 2026-06-04 (P7B) and again 2026-06-04 (PKCS12/keypair).** Full plan in [[plan-smart-bundle-import]]. Branch: `feature/smart-bundle-import`.

Covers four parts:
- **A — Upload improvements:** BasicConstraints leaf ID, P7B support, chain matching, AJAX preview panel
- **B — PKCS12/PFX import:** New route creates a Certificate record from a `.p12`/`.pfx` file; extracts key, leaf cert, and chain
- **C — Keypair import:** New route accepts a separate private key + cert file (PEM/bundle/P7B); validates key↔cert match before creating record
- **D — UI:** Import dropdown on Certificates page (Import CSR / Import P12 / Import Keypair)
- **E — Chain import role check:** Warn and skip leaf certs in chain bundle imports

---

## 4. Configurable Session Timeout

The idle session timeout is currently hardcoded as `IDLE_TIMEOUT = 15 * 60` (15 minutes) in `app/security.py:114`. The front-end modal countdown (`sessionTimeoutModal` in `base.html`) is also hardcoded to match.

**How to apply:** Move the timeout value into a new `AppConfig` DB table (or extend the existing `Settings` model) so a superadmin can adjust it from the Settings UI. Both the server-side check in `security.py` and the JS countdown in `base.html` need to read the configured value — the JS should receive it via a template variable or a small JSON endpoint.

---

## 5. Multi-Factor Authentication (TOTP)

No MFA exists. Users authenticate with username + password only.

**How to apply:** Add TOTP-based MFA (RFC 6238, compatible with Google Authenticator, Authy, etc.) using the `pyotp` library. Store the TOTP secret (encrypted at rest) on the `User` model along with an `mfa_enabled` boolean. Superadmins can enforce MFA globally. Flow: after password check passes, if MFA is enabled for the user, redirect to a TOTP entry page before granting the session. Include backup/recovery codes at enrolment. Audit log enrolment, disablement, and failed TOTP attempts.

---

## 6. Automated Documentation Screenshots + PDF Export

**Goal:** Automate capture of every app page as screenshots for use in admin/user documentation, and produce a publishable PDF artifact — without Chrome.

**Tooling:** Playwright with Firefox or WebKit (both available via `playwright` Python package). PDF generation via WeasyPrint (renders HTML/CSS to PDF without a browser engine; handles the Bootstrap-based templates well). Alternative: `playwright` can generate PDF via the `page.pdf()` API with Chromium — but since Chrome is excluded, WeasyPrint from the rendered HTML is cleaner.

**How to apply:**
- Add a `docs/capture/` directory containing a Playwright script (`capture.py`) that:
  1. Spins up the app in Docker or against a running dev instance
  2. Logs in as admin with test credentials
  3. Visits each documented page (defined in a manifest)
  4. Saves a screenshot to `docs/screenshots/<page_name>.png`
- Add a `docs/build_pdf.py` script that uses WeasyPrint to render `USER_GUIDE.md` and `INSTALL.md` (via a Jinja HTML wrapper with embedded screenshots) into `docs/dist/ssl-manager-user-guide.pdf` and `ssl-manager-admin-guide.pdf`.
- Screenshots are embedded in docs using `![](../screenshots/page_name.png)` references.
- CI/CD: add a GitHub Actions step (or local `make docs`) that rebuilds screenshots and PDFs when docs change.

**Dependencies:** `playwright` (Firefox driver), `weasyprint`, `markdown` or `mkdocs`.

---

## 7. In-App Contextual Help

**Goal:** Each page in the app has a help trigger (e.g. a `?` button in the page header) that opens a help panel relevant to the current page — so documentation is accessible without leaving the app.

**How to apply:**
- Add a `GET /help/<page_slug>` route that returns a rendered help partial (HTML fragment).
- Add a `help/` directory under `app/templates/help/` with one Markdown-sourced or HTML template per page slug (e.g. `certificates.html`, `chains.html`, `cert_detail.html`).
- Add a `?` icon button to each page header in the base/page templates. On click, load the help partial into a slide-in offcanvas panel (Bootstrap 5 offcanvas) via fetch — no page reload.
- Content is drawn from the existing user guide sections, broken into per-page fragments, so there's a single source of truth.
- Superadmin pages (users, audit log, SMTP) get their own help slugs.

---

## 8. Manual + Automated Backup UI

**Goal:** Surface backup controls and status inside the app — not just a CLI-only operation.

**What already exists:** `backup.sh` (WAL-safe SQLite backup with integrity check, gzip, pruning, audit log write), `ssl-manager-backup.service` / `ssl-manager-backup.timer` (daily at 02:00), `docker-compose.test.yml` backup-test container.

**What's missing:**
- **Manual trigger:** Superadmin can click "Run Backup Now" in the Settings UI, which calls `backup.sh` via `subprocess` (or reimplements the SQLite `.backup` logic in Python) and lets the user download the resulting `.db.gz` directly from the browser.
- **Backup history:** Query the audit log for `action=backup` entries and display a table showing last N backups, their file size, result, and timestamp — in the Settings UI.
- **Configurable retention:** Move the `--days` value out of the hardcoded systemd unit and into `AppConfig` (links to feature 4's `AppConfig` table).
- **Restore guidance:** Add a restore procedure to `INSTALL.md` (currently absent — only backup is documented).

**Note:** The download-from-browser path requires the Flask process to have read access to the backup destination directory — straightforward for Docker but needs a note for systemd installs where the backup dir may be root-owned.

---

## 9. Upgrade Scripts + Version Migration Process

**Goal:** Formalise the upgrade process so that moving to a new version is a documented, safe, repeatable operation — including data migration for schema changes.

**What already exists:** `install.sh --upgrade` backs up the DB, copies app files, reinstalls deps, restarts service. Basic but functional for patch releases.

**What's missing:**
- **Schema migration versioning:** The current `_add_column_if_missing` approach in `__init__.py` handles additive changes but has no version tracking. Add a `schema_version` table (single row, integer). On startup, run only the migration steps whose version number is higher than the stored version.
- **Data migration scripts:** For changes that require data transformation (not just schema), add versioned Python migration scripts in `app/migrations/v{N}.py` with `upgrade()` and `downgrade()` functions. `install.sh --upgrade` runs any pending ones after backing up.
- **Export / import for cross-instance migration:** Add a `manage.py export` command that dumps all certificates, chains, CAs, profiles, and settings to a structured JSON file (private keys included, encrypted with a user-supplied passphrase via Fernet). Add `manage.py import` to ingest this file into a fresh instance, resolving FK relationships. This supports migrating from one server to another or from an old installation to a new one.
- **Setup guidelines doc:** Add `docs/admin/MIGRATION.md` covering the full procedure: export from old, fresh install on new server, import, verify, cutover.

---

## 10. ~~Import Private Keys and PKCS#12 Files~~ — merged into feature 3

**Goal:** Import existing certificates from external sources — specifically the structured-directory SSL cert management workflow currently in use, and from PKCS#12 files received from third parties.

**Use case:** Existing SSL cert management uses structured directories (likely `domain/private_key.pem`, `domain/cert.pem`, `domain/chain.pem` or similar). The user wants to migrate this content into SSL Manager so the app becomes the single source of truth going forward.

**Import sources:**
1. **PKCS#12 / PFX (`.p12`, `.pfx`):** Encrypted archive containing private key + leaf cert + optional CA chain. Parse via `cryptography.hazmat.primitives.serialization.pkcs12.load_pkcs12()`. Extract: private key (serialize to PEM), leaf cert (PEM), CA certs list (each to PEM as intermediates).
2. **Private key + separate cert (PEM files):** Allow uploading a private key file alongside a certificate on a new "Import Certificate" form. Validate that the key matches the cert's public key.
3. **Directory bulk import:** A CLI script (`manage.py bulk-import --dir /path/to/certs`) that walks a directory structure, detects PEM/P12 files, and creates Certificate records. Configurable naming conventions (e.g. `{domain}/privkey.pem` + `{domain}/cert.pem`).

**How to apply:**
- Add `POST /certificates/import-p12` route: accepts `.p12` file + password, calls `load_pkcs12()`, creates Certificate record with private key + leaf cert, extracts intermediates to a new or matched chain (reuses [[plan-smart-bundle-import]] chain-matching logic).
- Add `POST /certificates/import-keypair` route: accepts separate PEM key file + cert file (or bundle), validates key↔cert match by comparing public keys, creates Certificate record.
- Add `manage.py bulk-import` CLI command for batch directory import with a dry-run mode.
- Audit log every import. Flash warnings for key/cert mismatches, password errors, duplicate domains.

**Key/cert validation:** `private_key.public_key() == cert.public_key()` — compare public key bytes after serializing both to DER.