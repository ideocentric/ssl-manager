# SSL Manager — End-to-End Workflow

This document walks through the complete certificate lifecycle from first login through to a fully verified, deployment-ready certificate bundle. All UI paths and CLI commands are included.

---

## Table of Contents

1. [First-Run Setup](#1-first-run-setup)
2. [Configure Organization Defaults](#2-configure-organization-defaults)
3. [Set Up the Certificate Chain](#3-set-up-the-certificate-chain)
   - [Testing: Local Dev CA](#31-testing-with-the-local-dev-ca)
   - [Production: Real CA Intermediates](#32-production-real-ca-intermediates)
4. [Create a New Certificate](#4-create-a-new-certificate)
5. [Sign the CSR](#5-sign-the-csr)
   - [Testing: Sign with dev_ca.py](#51-testing-sign-with-dev_capy)
   - [Production: Submit to a Real CA](#52-production-submit-to-a-real-ca)
6. [Upload the Signed Certificate](#6-upload-the-signed-certificate)
7. [Export Formats](#7-export-formats)
8. [Verification](#8-verification)
   - [Component ZIP / PEM files](#81-component-zip--pem-files)
   - [Full Chain PEM](#82-full-chain-pem)
   - [PKCS#12 / PFX](#83-pkcs12--pfx)
   - [JKS](#84-jks)
   - [P7B](#85-p7b)
9. [User Management](#9-user-management)

---

## 1. First-Run Setup

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

## 2. Configure Organization Defaults

Settings are applied as defaults whenever a new certificate is created. Configure these once before creating any certificates.

**Navigate:** Navbar → **Settings**

| Field | Description | Example |
|---|---|---|
| Key Size | RSA key length in bits | `2048` or `4096` |
| Country | Two-letter ISO country code | `US` |
| State | State or province | `California` |
| City | Locality | `San Francisco` |
| Organization | Legal org name | `Acme Corp` |
| Org Unit | Department | `IT` |
| Email | Contact email embedded in the CSR | `ssl@acme.com` |

Click **Save Settings**. These values pre-fill the new certificate form; you can override them per certificate.

---

## 3. Set Up the Certificate Chain

Chain certificates (intermediates and root) must be loaded before you export any bundled format. They are stored organisation-wide and automatically included in every certificate export.

**Navigate:** Navbar → **Chain Certificates** → **Add Chain Certificate**

### 3.1 Testing with the Local Dev CA

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

**Add the Intermediate CA (order 1):**

```bash
python dev_ca.py chain --intermediate
```

Copy the printed PEM. In the app:

- **Name:** `Local Dev Intermediate CA`
- **Order:** `1`
- **PEM Data:** paste the intermediate PEM
- Click **Save**

**Add the Root CA (order 2):**

```bash
python dev_ca.py chain --root
```

Copy the printed PEM. In the app:

- **Name:** `Local Dev Root CA`
- **Order:** `2`
- **PEM Data:** paste the root PEM
- Click **Save**

The **Chain Certificates** list now shows both entries with their subject, expiry, and whether each is a root or intermediate.

### 3.2 Production: Real CA Intermediates

When using a CA such as GoDaddy, DigiCert, or Sectigo:

1. Download the intermediate bundle from your CA's support page (usually a `.crt` or `.pem` file containing one or more certificates).
2. If the bundle contains multiple certificates concatenated together, split them into individual PEM blocks (each starts with `-----BEGIN CERTIFICATE-----`).
3. Add each certificate separately under **Chain Certificates**, assigning order values that reflect the chain from leaf to root:
   - Order `1` — the issuing intermediate (the one that directly signed your domain cert)
   - Order `2` — the next intermediate (if present)
   - Order `3` — the root CA (optional; browsers typically have this built-in)

> **Tip:** GoDaddy typically provides two files — `gd_bundle-g2-g1.crt` (intermediates) and `gd_g2_iis.p7b` (for IIS). Use the `.crt` bundle, split it if needed, and add each cert in chain order.

**Verify chain order** on the Chain Certificates page — entries are listed in ascending order. The intermediate that directly signed your domain certificate must be order `1`.

---

## 4. Create a New Certificate

**Navigate:** Navbar → **Certificates** → **New Certificate**

Fill in the form:

| Field | Description |
|---|---|
| **Domain (CN)** | Primary domain, e.g. `www.example.com` |
| **Subject Alternative Names** | One domain per line. The CN is included automatically. |
| **Key Size** | `2048` (standard) or `4096` (higher security) |
| Country / State / City / Org / OU / Email | Pre-filled from Settings; edit as needed |

Click **Create Certificate**.

The app:
- Generates an RSA private key (never leaves the server)
- Generates a CSR embedding the CN, SANs, and all subject fields
- Redirects to the **Certificate Detail** page showing status **Pending Signing**

---

## 5. Sign the CSR

On the **Certificate Detail** page, the CSR is displayed in the **Certificate Signing Request** section.

### 5.1 Testing: Sign with dev_ca.py

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

### 5.2 Production: Submit to a Real CA

1. On the **Certificate Detail** page click **Download CSR** to save the `.csr` file.
2. Log in to your CA's portal (GoDaddy, DigiCert, Sectigo, etc.).
3. Start a new certificate order and paste or upload the CSR when prompted.
4. Complete domain validation (DCV) as required by the CA.
5. Once approved, download the signed certificate — typically delivered as a `.crt` or `.pem` file containing only the end-entity certificate (not the chain).

> **Important:** Download only the **domain certificate**, not the bundle. Intermediate certificates are managed separately in Step 3.

---

## 6. Upload the Signed Certificate

**Navigate:** Certificate Detail page → **Upload Signed Certificate** section

1. Open the signed certificate file in a text editor and copy the full PEM block:
   ```
   -----BEGIN CERTIFICATE-----
   MIIDazCCAlOgAwIBAgI...
   -----END CERTIFICATE-----
   ```
2. Paste it into the **Signed Certificate PEM** text area.
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

## 7. Export Formats

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

## 8. Verification

Use these commands to inspect and verify each format after downloading. Replace filenames with your actual domain.

### 8.1 Component ZIP / PEM files

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

### 8.2 Full Chain PEM

**Split and inspect each cert** (the file contains key + cert + intermediates concatenated):
```bash
# Count PEM blocks
grep -c "BEGIN" www.example.com-fullchain.pem

# View cert details (skip past the key block)
openssl x509 -in www.example.com-fullchain.pem -text -noout
```

---

### 8.3 PKCS#12 / PFX

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

### 8.4 JKS

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

### 8.5 P7B

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

## 9. User Management

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
