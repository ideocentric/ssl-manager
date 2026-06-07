---
name: project-state
description: Current project state as of 2026-06-07 — admin documentation updated on feature/user-guide-smart-import
metadata:
  type: project
---

## Current state (as of 2026-06-07)

**Active branch: `feature/user-guide-smart-import`** — admin documentation update in progress.

### Admin docs completed (this branch)

- `docs/admin/REQUIREMENTS.md` — fully rewritten: Ubuntu + RHEL-family OS sections, arm64, corrected packages, cryptography 46.0.7, outbound SMTP network requirement, split filesystem layout table
- `docs/admin/INSTALL.md` — fully rewritten: Ubuntu bare metal, RHEL/Rocky/AlmaLinux (new), email config (SMTP + M365/Google OAuth), cloud prerequisites (Terraform/AWS CLI/Azure CLI, SSH key gen for all platforms), Upgrading from Previous Versions section (schema migrations are automatic)
- `docs/admin/DEPLOY-AWS.md` — added outbound SMTP network considerations section
- `docs/admin/DEPLOY-AZURE.md` — added outbound SMTP network considerations section
- `docs/pdf/admin-guide.css` — created
- `docs/generate_pdf.py` — Guide.source_md supports `Path | list[Path]`; admin guide entry added; `SSL_Manager_Admin_Guide.pdf` builds clean at ~298 KB

---

## Previous state (as of 2026-06-04)

**Active branch: `master`** — clean and up to date. `feature/smart-bundle-import` committed, PR'd, and merged.

---

## What shipped in feature/smart-bundle-import

- Smart bundle import: BasicConstraints-based leaf identification replaces fragile first-PEM-wins logic
- P7B/PKCS#7 support on cert upload (.p7b / .p7 extensions)
- AJAX preview panel on cert detail upload form
- New route: POST /certificates/import-p12 — PKCS#12/PFX import with AJAX preview
- New route: POST /certificates/import-keypair — raw private key + cert import with AJAX preview
- Chain matching by intermediate serial numbers — reuses existing chains instead of always creating new ones
- Chain import role check — leaf certs skipped with flash warning
- Certificates page import dropdown (Import CSR / Import P12 / Import Private Key + Certificate)
- Shared crypto helpers: split_bundle_by_role, identify_leaf_cert, find_matching_chain, parse_p7b_bundle, parse_pkcs12, keys_match, get_key_info
- P12 preview UX fix: shows "Enter password to preview" instead of error when file selected with no password; password field uses debounced input listener

---

## Previously shipped

- SMTP config + password reset (feature/password-reset-smtp)
- PEM bundle splitting on cert upload; CSR removed from ZIP export
- install-rhel.sh — RHEL 9 installer with full SELinux support
- Live RHEL 9 deployment on brITRHtool10p — working

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