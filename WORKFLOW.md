# SSL Manager — End-to-End Workflow

This document walks through the complete certificate lifecycle from first login through to a fully verified, deployment-ready certificate bundle. All UI paths and CLI commands are included.

---

## Table of Contents

1. [Docker Development Environment](#1-docker-development-environment)
   - [Starting the stack](#11-starting-the-stack)
   - [Testing backups and audit log](#12-testing-backups-and-audit-log)
   - [Common Docker commands](#13-common-docker-commands)
2. [Unit Tests](#2-unit-tests)
3. [First-Run Setup](#3-first-run-setup)
4. [Configure Certificate Profiles](#4-configure-certificate-profiles)
5. [Set Up Certificate Chains](#5-set-up-certificate-chains)
   - [Testing: Local Dev CA](#51-testing-with-the-local-dev-ca)
   - [Production: Real CA Intermediates](#52-production-real-ca-intermediates)
6. [Browse and Search Certificates](#6-browse-and-search-certificates)
7. [Create a New Certificate](#7-create-a-new-certificate)
8. [Sign the CSR](#8-sign-the-csr)
   - [Testing: Sign with dev_ca.py](#81-testing-sign-with-dev_capy)
   - [Production: Submit to a Real CA](#82-production-submit-to-a-real-ca)
9. [Upload the Signed Certificate](#9-upload-the-signed-certificate)
10. [Export Formats](#10-export-formats)
11. [Verification](#11-verification)
    - [Component ZIP / PEM files](#111-component-zip--pem-files)
    - [Full Chain PEM](#112-full-chain-pem)
    - [PKCS#12 / PFX](#113-pkcs12--pfx)
    - [JKS](#114-jks)
    - [P7B](#115-p7b)
12. [User Management](#12-user-management)

---

## 1. Docker Development Environment

Use the Docker Compose stack for all local development and feature testing. It runs the Flask app and, when using the test overlay, a backup-test service that exercises the backup and audit log pipeline.

### 1.1 Starting the stack

**App only** (no backup service):

```bash
docker compose up --build
```

The app is available at `http://localhost:5001`.

**App + backup test service** (runs `backup.sh` immediately, then every hour):

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml up --build
```

The backup-test service waits 10 seconds after startup (to let the app initialise and create the database), then runs a backup automatically. Subsequent runs occur every hour.

> **First run only:** open `http://localhost:5001`, complete the first-run setup to create the superadmin account, then log in. The backup-test container will retry until the database exists.

### 1.2 Testing backups and audit log

**Watch backup output live:**

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml logs -f backup-test
```

A successful run produces output like:

```
backup-test-1  | [backup-test] Running backup at Thu Mar 13 02:00:10 UTC 2026
backup-test-1  | [+] Checkpointing WAL…
backup-test-1  | [+] Backing up /app/instance/ssl_manager.db → /var/backups/ssl-manager/ssl_manager_2026-03-13_020010.db.gz…
backup-test-1  | [+] Backup complete: /var/backups/ssl-manager/ssl_manager_2026-03-13_020010.db.gz (48K)
backup-test-1  | [+] Retaining backups from the last 7 day(s) in /var/backups/ssl-manager.
backup-test-1  | [+] Done.
backup-test-1  | [backup-test] Done. Next run in 1 hour.
```

**Verify the audit log entry:**

1. Log in as superadmin and open **Audit Log** in the navbar.
2. The most recent entry should show:
   - **User:** `system`
   - **Action:** `backup` (with an archive icon)
   - **Resource:** `database`
   - **Result:** `success`
   - **Detail:** `file=ssl_manager_<timestamp>.db.gz size=<N>K days=7 pruned=0`
3. System-initiated rows appear with a light blue background to distinguish them from user actions.

**Trigger an immediate backup without waiting for the hour:**

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml \
  exec backup-test bash /app/backup.sh \
    --db   /app/instance/ssl_manager.db \
    --dest /var/backups/ssl-manager \
    --days 7
```

**List backup archives stored in the container volume:**

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml \
  exec backup-test ls -lh /var/backups/ssl-manager/
```

**Inspect a backup archive** (decompress in place to verify it is a valid SQLite file):

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml \
  exec backup-test bash -c \
    "gunzip -c /var/backups/ssl-manager/ssl_manager_<timestamp>.db.gz \
     | sqlite3 /dev/stdin 'PRAGMA integrity_check;'"
```

### 1.3 Common Docker commands

```bash
# Rebuild after code changes
docker compose -f docker-compose.yml -f docker-compose.test.yml up --build

# Stop everything and remove containers (volumes are preserved)
docker compose -f docker-compose.yml -f docker-compose.test.yml down

# Remove containers AND volumes (full reset — database is wiped)
docker compose -f docker-compose.yml -f docker-compose.test.yml down -v

# Open a shell in the running app container
docker compose exec ssl-manager bash

# Open a shell in the backup-test container
docker compose -f docker-compose.yml -f docker-compose.test.yml exec backup-test bash

# Tail all service logs together
docker compose -f docker-compose.yml -f docker-compose.test.yml logs -f

# Check database integrity from outside the app
docker compose exec ssl-manager \
  sqlite3 /app/instance/ssl_manager.db "PRAGMA integrity_check;"
```

---

## 2. Unit Tests

The test suite uses pytest with an in-memory SQLite database via `StaticPool`. No running app instance is required.

### Install test dependencies

```bash
pip install -r requirements.txt
pip install pytest
```

### Run all tests

```bash
pytest test_app.py
```

### Common options

```bash
# Verbose — one line per test
pytest test_app.py -v

# Stop on first failure
pytest test_app.py -x

# Compact tracebacks
pytest test_app.py --tb=short

# Run a specific test class
pytest test_app.py -k "TestAuditLog"

# Run a specific test
pytest test_app.py -k "test_login_valid"

# Combine options
pytest test_app.py -v --tb=short -k "TestCertificate"
```

### Test structure

| File | Purpose |
|---|---|
| `conftest.py` | Session-scoped `flask_app` fixture (factory pattern), `client`, `anon_client`, `clean_db` |
| `test_app.py` | All test classes: crypto helpers, model properties, route integration tests |

Tests that exercise the JKS download format require `pyjks` to be installed. If `pyjks` is absent those three tests will fail; all others pass independently.

---

## 3. First-Run Setup

On the very first visit the app detects that no users exist and redirects to `/setup`.

**Steps:**

1. Open the app URL in your browser.
2. You are redirected to the **Initial Setup** page.
3. Fill in:
   - **Username** — your login name (e.g. `admin`)
   - **Email** — used for identification only
   - **Password** — minimum 8 characters
   - **Confirm Password**
4. Click **Create Admin Account**.

You are logged in automatically and land on the **Certificates** page. This account has the `superadmin` role. All future users must log in at `/login`.

---

## 4. Configure Certificate Profiles

**Navigate:** Navbar → **Profiles**

A profile is a named template of Distinguished Name (DN) fields. Rather than configuring a single global default, you can maintain as many profiles as your organisation needs — for example one per legal entity, region, or certificate type.

### Creating a profile

Click **New Profile**. Fill in:

| Field | Notes |
|---|---|
| **Name** | Required. A human-readable label, e.g. "Acme Corp — US" or "EU Subsidiary" |
| Key Size | RSA key size in bits (`2048` or `4096`) |
| Country | Two-letter ISO country code |
| State | State or province |
| City | Locality |
| Org Name | Organisation name (O=) |
| Org Unit | Organisational unit (OU=) |
| Email | Contact email embedded in the CSR subject |

Click **Save**. The profile now appears in the Profiles table.

### Default profile

Exactly one profile carries the **default** badge (displayed in green). When only one profile exists it is automatically the default. To promote a different profile, click **Set Default** next to it.

The default profile is pre-selected in the certificate creation form when multiple profiles exist.

### Applying a profile when creating a certificate

- **One profile exists** — its values are applied to the subject fields automatically; no selection UI is shown.
- **Multiple profiles exist** — a profile dropdown appears at the top of the New Certificate form. Choose a profile and click **Apply** to populate the subject fields. This does not submit the form; you can adjust any field before saving.

Profiles are templates only. No persistent link is stored between a profile and the certificates created from it. Each certificate stores a snapshot of the subject fields at creation time.

### Deleting a profile

The last remaining profile cannot be deleted. All others can be removed at any time without affecting existing certificates.

> **Legacy note:** The old `/settings` URL redirects to `/profiles` so that any saved bookmarks continue to work.

---

## 5. Set Up Certificate Chains

**Navigate:** Navbar → **Chains**

A chain is a named, ordered collection of intermediate and root CA certificates that get bundled with your domain certificates. You can maintain multiple independent chains — useful when rotating CA providers or managing certificates from several issuers.

### Creating a chain

Click **New Chain**. Provide:

- **Name** — required, e.g. "Let's Encrypt R11" or "DigiCert Intermediate 2025"
- **Description** — optional free-text note

Click **Save**. The chain now appears in the Chains table and can be assigned to certificates.

### Adding intermediate certificates

Open a chain by clicking its name. On the Chain Detail page, click **Add Certificate** and provide:

- **Display Name** — a human-readable label for this entry
- **PEM Data** — paste the PEM-encoded certificate
- **Order** — integer; order `1` is closest to the domain certificate, higher numbers ascend toward the root

### Drag-to-reorder

On the Chain Detail page, drag entries up or down to change their order. The order numbers update automatically on save.

### Import Bundle

If your CA provides a bundle file containing multiple certificates in a single PEM, use the **Import Bundle** button on the Chain Detail page. Paste or upload the multi-cert PEM; the app splits it into individual entries, assigns sequential order numbers, and adds them all at once.

### Assigning chains to certificates

When creating a certificate you select which chain to assign. The assignment can also be changed later from the Certificate Detail page. One chain can be shared by many certificates. When you rotate to a new CA, create a new chain, point new certificates at it, and leave existing certificates on the old chain.

### 5.1 Testing with the Local Dev CA

The `dev_ca.py` script creates a two-tier hierarchy (root → intermediate) that mirrors a real CA.

```bash
# One-time: create the root CA and intermediate CA
python dev_ca.py init
```

Output confirms two files are written to `dev-ca/`:

```
root.key / root.crt          ← 10-year self-signed root
intermediate.key / intermediate.crt  ← 5-year intermediate, signed by root
```

**Print chain PEMs for import:**

```bash
python dev_ca.py chain
```

In the app, create a chain under **Chains → New Chain**, then on the Chain Detail page either:

- Click **Import Bundle**, paste or upload the combined output (both PEMs), and let the app split them; or
- Add each certificate individually:
  - **Add Certificate** with Name `Local Dev Intermediate CA`, Order `1`, paste the intermediate PEM
  - **Add Certificate** with Name `Local Dev Root CA`, Order `2`, paste the root PEM

The **Chain Detail** page now shows both entries with their subject, expiry, and CA type.

### 5.2 Production: Real CA Intermediates

When using a CA such as GoDaddy, DigiCert, or Sectigo:

1. Download the intermediate bundle from your CA's support page (usually a `.crt` or `.pem` file containing one or more certificates).
2. In the app, create a new chain under **Chains → New Chain** with a descriptive name.
3. On the Chain Detail page, use **Import Bundle** to paste or upload the full bundle — the app splits it into individual entries automatically. Review the order numbers and adjust if needed.
4. Alternatively, add each certificate separately, assigning order values that reflect the chain from leaf to root:
   - Order `1` — the issuing intermediate (the one that directly signed your domain cert)
   - Order `2` — the next intermediate (if present)
   - Order `3` — the root CA (optional; browsers typically have this built-in)

> **Tip:** GoDaddy typically provides two files — `gd_bundle-g2-g1.crt` (intermediates) and `gd_g2_iis.p7b` (for IIS). Use the `.crt` bundle with **Import Bundle** to add all intermediates in one step.

**Verify chain order** on the Chain Detail page — entries are listed in ascending order. The intermediate that directly signed your domain certificate must be order `1`.

---

## 6. Browse and Search Certificates

**Navigate:** Navbar → **Certificates**

### Sorting

Click any column header to sort by that column. Click the same header again to reverse the sort direction. An arrow icon indicates the active sort column and direction. The default sort is **Created — descending** (newest certificates first).

Sortable columns: **Domain**, **Status**, **Expiry**, **SANs**, **Created**.

### Searching

Type in the search bar above the table to filter rows in real time. The search matches against:

- Domain name
- Status (`active`, `expired`, `pending_signing`)
- Organisation name
- Country
- Email
- Expiry date (YYYY-MM-DD format)
- Created date
- All SAN domains

A counter on the right side of the search bar shows **N of M certificates**, reflecting the number of rows currently visible versus the total.

---

## 7. Create a New Certificate

**Navigate:** Navbar → **Certificates** → **New Certificate**

### Profile selection

If more than one profile exists, a profile dropdown appears at the top of the form. Select the desired profile and click **Apply** to pre-fill the subject fields. Adjust any field as needed before proceeding.

If only one profile exists, its values are applied automatically and no dropdown is shown.

### Fill in the form

| Field | Description |
|---|---|
| **Domain (CN)** | Primary domain, e.g. `www.example.com` |
| **Subject Alternative Names** | One domain per line. The CN is included automatically. |
| **Key Size** | `2048` (standard) or `4096` (higher security) |
| Country / State / City / Org / OU / Email | Pre-filled from the selected profile; edit as needed |
| **Chain** | Select which named chain to bundle with this certificate |

Click **Create Certificate**.

The app:
- Generates an RSA private key (never leaves the server)
- Generates a CSR embedding the CN, SANs, and all subject fields
- Redirects to the **Certificate Detail** page showing status **Pending Signing**

---

## 8. Sign the CSR

On the **Certificate Detail** page, the CSR is displayed in the **Certificate Signing Request** section.

### 8.1 Testing: Sign with dev_ca.py

```bash
# Download the CSR from the Certificate Detail page (Download CSR button)
# Then sign it with the local intermediate CA:
python dev_ca.py sign ~/Downloads/www.example.com.csr
```

The signed certificate PEM is printed to the terminal and saved to `dev-ca/signed/www.example.com.crt`.

```bash
# Custom validity period (default is 365 days):
python dev_ca.py sign ~/Downloads/www.example.com.csr --days 90
```

### 8.2 Production: Submit to a Real CA

1. On the **Certificate Detail** page click **Download CSR** to save the `.csr` file.
2. Log in to your CA's portal (GoDaddy, DigiCert, Sectigo, etc.).
3. Start a new certificate order and paste or upload the CSR when prompted.
4. Complete domain validation (DCV) as required by the CA.
5. Once approved, download the signed certificate — typically delivered as a `.crt` or `.pem` file containing only the end-entity certificate (not the chain).

> **Important:** Download only the **domain certificate**, not the bundle. Intermediate certificates are managed separately in a named chain (Step 3).

---

## 9. Upload the Signed Certificate

**Navigate:** Certificate Detail page → **Upload Signed Certificate** section

1. Open the signed certificate file in a text editor and copy the full PEM block:
   ```
   -----BEGIN CERTIFICATE-----
   MIIDazCCAlOgAwIBAgI...
   -----END CERTIFICATE-----
   ```
2. Paste it into the **Signed Certificate PEM** text area, or use the file upload option.
3. Click **Upload Certificate**.

The app validates the PEM, extracts the expiry date, and updates the status to **Active**. The expiry date appears with a colour-coded indicator:

| Colour | Meaning |
|---|---|
| Green | More than 90 days remaining |
| Yellow | 30–90 days remaining |
| Orange/Red | Fewer than 30 days remaining |
| Red (Expired) | Past expiry date |

The **Downloads** section is now unlocked.

---

## 10. Export Formats

All download options appear in the **Downloads** section of the Certificate Detail page. The chain certificates loaded in Step 3 are automatically included in every bundled format.

### Full Chain PEM

**Button:** Download .pem
**Filename:** `www.example.com-fullchain.pem`

Contains: `private key + signed certificate + all intermediates` concatenated in a single file.

**Use for:** HAProxy (`ssl-certificate`), some load balancers and CDN origin configs that require everything in one file.

---

### Component PEMs (ZIP)

**Button:** Download .zip
**Filename:** `www.example.com-certs.zip`

Extract the archive. Contents:

| File | Use |
|---|---|
| `private_key.pem` | nginx `ssl_certificate_key` / Apache `SSLCertificateKeyFile` |
| `certificate.pem` | End-entity cert only — use for inspection |
| `chain.pem` | Intermediates only — Apache `SSLCACertificateFile` |
| `fullchain.pem` | Cert + intermediates (no key) — nginx `ssl_certificate` / Apache `SSLCertificateFile` (2.4.8+) |
| `certificate.csr` | Original CSR — keep for records |

**nginx example:**
```nginx
ssl_certificate     /etc/nginx/ssl/www.example.com/fullchain.pem;
ssl_certificate_key /etc/nginx/ssl/www.example.com/private_key.pem;
```

**Apache 2.4.8+ example:**
```apache
SSLCertificateFile    /etc/pki/tls/certs/www.example.com/fullchain.pem
SSLCertificateKeyFile /etc/pki/tls/private/www.example.com/private_key.pem
```

**Apache (older, individual files):**
```apache
SSLCertificateFile    /etc/pki/tls/certs/www.example.com/certificate.pem
SSLCertificateKeyFile /etc/pki/tls/private/www.example.com/private_key.pem
SSLCACertificateFile  /etc/pki/tls/certs/www.example.com/chain.pem
```

---

### PKCS#12 / PFX

**Button:** Download .p12
**Field:** Password (optional but strongly recommended)
**Filename:** `www.example.com.p12`

Contains: private key + certificate + chain in a single encrypted file.

**Use for:** Windows IIS, Azure App Service, F5 BIG-IP, Java applications, any tool that imports a PFX file.

Enter a password in the **Password** field before clicking Download. Store the password securely — it is required whenever the `.p12` file is imported.

---

### Java KeyStore (JKS)

**Button:** Download .jks
**Fields:**
- **Store password** (default: `changeit`) — protects the keystore file
- **Alias** (default: `certificate`) — the name for this entry inside the keystore

**Filename:** `www.example.com.jks`

Contains: private key + certificate + chain in Java KeyStore format.

**Use for:** Tomcat, Spring Boot, JBoss/WildFly, Jetty, and any Java application server.

**Tomcat `server.xml` example:**
```xml
<Connector port="443" protocol="org.apache.coyote.http11.Http11NioProtocol"
           SSLEnabled="true"
           keystoreFile="/opt/tomcat/conf/www.example.com.jks"
           keystorePass="changeit"
           keyAlias="certificate" />
```

---

### P7B (Cert Chain Only)

**Button:** Download .p7b
**Filename:** `www.example.com.p7b`

Contains: signed certificate + all intermediates in PKCS#7 DER format. **Does not include the private key.**

**Use for:** Windows Server certificate stores (import via MMC), IIS when importing a certificate with a separately stored private key, some enterprise CA portals.

> Requires `openssl` to be installed on the server running SSL Manager. If `openssl` is not found the button will display an error.

---

## 11. Verification

Use these commands to inspect and verify each format after downloading. Replace filenames with your actual domain.

### 11.1 Component ZIP / PEM files

**Inspect the certificate:**
```bash
openssl x509 -in certificate.pem -text -noout
```
Check: Subject, Issuer, SANs, validity dates.

**Inspect the CSR:**
```bash
openssl req -in certificate.csr -text -noout
```

**Verify the private key matches the certificate** (both commands must produce the same MD5 hash):
```bash
openssl x509 -noout -modulus -in certificate.pem  | md5sum
openssl rsa  -noout -modulus -in private_key.pem  | md5sum
```

**Verify the certificate against the chain:**
```bash
openssl verify -CAfile chain.pem certificate.pem
# Expected output: certificate.pem: OK
```

**Inspect the full chain (no key):**
```bash
openssl crl2pkcs7 -nocrl -certfile fullchain.pem | \
  openssl pkcs7 -print_certs -noout
```
This lists every certificate in the chain with its subject and issuer.

---

### 11.2 Full Chain PEM

**Split and inspect each cert** (the file contains key + cert + intermediates concatenated):
```bash
# Count PEM blocks
grep -c "BEGIN" www.example.com-fullchain.pem

# View cert details (skip past the key block)
openssl x509 -in www.example.com-fullchain.pem -text -noout
```

---

### 11.3 PKCS#12 / PFX

**List contents:**
```bash
openssl pkcs12 -info -in www.example.com.p12 -noout
# Prompts for the import password
```

**Extract and verify the certificate:**
```bash
openssl pkcs12 -in www.example.com.p12 -clcerts -nokeys -out extracted_cert.pem
openssl x509   -in extracted_cert.pem  -text -noout
```

**Extract and verify the private key:**
```bash
openssl pkcs12 -in www.example.com.p12 -nocerts -nodes -out extracted_key.pem
openssl rsa    -in extracted_key.pem   -check
# Expected: RSA key ok
```

**Confirm key matches certificate** (hashes must match):
```bash
openssl x509 -noout -modulus -in extracted_cert.pem | md5sum
openssl rsa  -noout -modulus -in extracted_key.pem  | md5sum
```

---

### 11.4 JKS

Requires the Java `keytool` utility (included with any JDK).

**List keystore contents:**
```bash
keytool -list -v -keystore www.example.com.jks -storepass changeit
```

Look for:
- **Alias name:** `certificate` (or your custom alias)
- **Entry type:** `PrivateKeyEntry`
- **Certificate chain length:** should match the number of certs in your chain (domain cert + intermediates)
- **Subject / Issuer** of each cert in the chain

**Verify the cert chain inside the JKS:**
```bash
keytool -list -v -keystore www.example.com.jks -storepass changeit \
  | grep -E "Owner:|Issuer:|Valid from:|until:"
```

---

### 11.5 P7B

**List all certificates in the bundle:**
```bash
openssl pkcs7 -inform DER -in www.example.com.p7b -print_certs -noout
```

**Convert to PEM for further inspection:**
```bash
openssl pkcs7 -inform DER -in www.example.com.p7b -print_certs -out bundle.pem
openssl x509  -in bundle.pem -text -noout
```

**Import into Windows** (GUI):
1. Double-click the `.p7b` file → Certificate Import Wizard
2. Store location: **Local Machine** → **Personal** or **Trusted Root** as appropriate

---

## 12. User Management

User management is available to **superadmin** accounts only.

**Navigate:** Navbar → **Users**

### Add a user

1. Click **Add User**
2. Fill in username, email, password, confirm password, and role
3. Click **Create User**

### Edit a user

Click the pencil icon next to any user. You can change:
- Username and email
- Role (`superadmin` or `user`)
- Active status (deactivating prevents login without deleting the account)

Password changes are handled in the separate **Change Password** section on the same form — leave the password fields blank to keep the current password.

### Delete a user

Click the trash icon next to any user (you cannot delete your own account).

### Superadmin protection

The application enforces that at least one active superadmin always exists. The following actions are blocked when only one active superadmin remains:

- Deleting the last superadmin
- Changing the last superadmin's role to `user`
- Deactivating the last superadmin's account

To transfer superadmin responsibilities: promote another user to `superadmin` first, then demote or deactivate the original account.
