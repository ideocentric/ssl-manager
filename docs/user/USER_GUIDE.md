# SSL Manager — User Guide

SSL Manager is a web application for managing the full lifecycle of SSL/TLS certificates — from generating a private key and Certificate Signing Request (CSR) through to storing the signed certificate and downloading it in the format required by your server.

This guide covers everything an end user needs: connecting to the application, setting up your environment, and managing certificates day-to-day.

---

## Table of Contents

1. [Connecting to SSL Manager](#1-connecting-to-ssl-manager)
   - [macOS and Linux](#11-macos-and-linux)
   - [Windows — OpenSSH (Windows 10/11)](#12-windows--openssh-windows-1011)
   - [Windows — PuTTY](#13-windows--putty)
   - [Persistent SSH Config (macOS / Linux)](#14-persistent-ssh-config-macos--linux)
   - [Keeping the Tunnel Open](#15-keeping-the-tunnel-open)
2. [Logging In](#2-logging-in)
3. [Dashboard Overview](#3-dashboard-overview)
4. [Certificate Profiles](#4-certificate-profiles)
   - [Create a Profile](#41-create-a-profile)
   - [Set the Default Profile](#42-set-the-default-profile)
   - [Edit or Delete a Profile](#43-edit-or-delete-a-profile)
5. [Certificate Chains](#5-certificate-chains)
   - [Create a Chain](#51-create-a-chain)
   - [Add Intermediate Certificates](#52-add-intermediate-certificates)
   - [Import a Bundle](#53-import-a-bundle)
6. [Certificate Authorities (Internal CA)](#6-certificate-authorities-internal-ca)
   - [Create a CA](#61-create-a-ca)
   - [Sign a Pending Certificate](#62-sign-a-pending-certificate)
   - [Download the CA Certificate](#63-download-the-ca-certificate)
   - [Delete a CA](#64-delete-a-ca)
7. [Certificate Lifecycle](#7-certificate-lifecycle)
   - [Create a New Certificate](#71-create-a-new-certificate)
   - [Download and Submit the CSR](#72-download-and-submit-the-csr)
   - [Upload the Signed Certificate](#73-upload-the-signed-certificate)
   - [Import an External CSR](#74-import-an-external-csr)
8. [Browsing and Finding Certificates](#8-browsing-and-finding-certificates)
9. [Downloading Certificates](#9-downloading-certificates)
10. [Renewing a Certificate](#10-renewing-a-certificate)
11. [User Management](#11-user-management)
12. [Audit Log](#12-audit-log)

---

## 1. Connecting to SSL Manager

SSL Manager is designed to be accessible only from the server it runs on. To reach it from your computer you use **SSH port forwarding**, which creates an encrypted tunnel through your existing SSH connection. No extra firewall ports need to be opened on the server.

> **What this means in practice:** you open a terminal, run one SSH command, then open your browser to `http://localhost:5001`. The browser talks to the server securely through the SSH tunnel.

### 1.1 macOS and Linux

Open a terminal and run:

```bash
ssh -L 5001:127.0.0.1:5001 youruser@your-server
```

Replace `youruser` with your server username and `your-server` with the server's hostname or IP address. If the server uses a non-standard SSH port, add `-p PORT`:

```bash
ssh -L 5001:127.0.0.1:5001 -p 2222 youruser@your-server
```

While this terminal session remains open, browse to:

```
http://localhost:5001
```

### 1.2 Windows — OpenSSH (Windows 10/11)

Windows 10 and 11 include OpenSSH. Open **Command Prompt** or **PowerShell** and run:

```
ssh -L 5001:127.0.0.1:5001 youruser@your-server
```

Then open your browser to `http://localhost:5001`.

### 1.3 Windows — PuTTY

1. Open PuTTY and enter your server's hostname under **Session**.
2. In the left panel navigate to **Connection → SSH → Tunnels**.
3. Fill in:
   - **Source port:** `5001`
   - **Destination:** `127.0.0.1:5001`
   - Select **Local**
4. Click **Add**. You will see `L5001  127.0.0.1:5001` in the forwarded ports list.
5. Go back to **Session**, save the session if you like, then click **Open**.

While the PuTTY session is connected, browse to `http://localhost:5001`.

### 1.4 Persistent SSH Config (macOS / Linux)

To avoid typing the full command every time, add an entry to `~/.ssh/config`:

```
Host ssl-manager
    HostName     your-server
    User         youruser
    LocalForward 5001 127.0.0.1:5001
```

After saving the file you can connect with just:

```bash
ssh ssl-manager
```

Then open `http://localhost:5001`. The `Host` label (`ssl-manager`) can be anything you like.

### 1.5 Keeping the Tunnel Open

The tunnel is active for as long as the SSH session is open. If you close the terminal or the session times out, refresh the SSH connection and reload the browser tab.

To keep a session alive longer, add to `~/.ssh/config`:

```
Host ssl-manager
    ...
    ServerAliveInterval 60
    ServerAliveCountMax 10
```

This sends a keepalive packet every 60 seconds, keeping idle sessions open for up to 10 minutes of inactivity.

---

## 2. Logging In

Navigate to `http://localhost:5001` in your browser while the SSH tunnel is active.

- **First visit ever:** you are redirected to the **Setup** page to create the initial administrator account. Fill in a username, email, and password and click **Create Admin Account**. You are logged in automatically.
- **All subsequent visits:** you are presented with the login form. Enter your username and password.

If your session expires you are returned to the login page automatically.

---

## 3. Dashboard Overview

After logging in you land on the **Certificates** page. The navbar at the top provides access to all sections:

| Nav item | Purpose |
|---|---|
| **SSL Manager** (logo) | Return to the certificates list from anywhere |
| **Certificates** | List, search, sort, and manage all certificates |
| **Chains** | Manage named sets of intermediate CA certificates |
| **CAs** | Manage internal Certificate Authorities and sign pending certificates |
| **Profiles** | Manage certificate subject templates (org name, country, key size, etc.) |
| **Users** | Add, edit, or remove users *(superadmin only)* |
| **Audit Log** | View a history of all actions taken in the app *(superadmin only)* |
| **Logout** | End your session |

---

## 4. Certificate Profiles

A **profile** is a reusable template for the subject fields that appear in every CSR — your organisation name, country, key size, and so on. Instead of filling in these fields from scratch each time you create a certificate, you pick a profile and the form is pre-filled for you.

You can have as many profiles as you need. For example:
- `Acme Corp — US` for US-based certificates
- `Acme EU GmbH` for European subsidiary certificates
- `Internal Services` with a different org unit

### 4.1 Create a Profile

1. Navigate to **Profiles** in the navbar.
2. Click **New Profile**.
3. Fill in:

| Field | Description | Example |
|---|---|---|
| **Profile Name** | A short descriptive label for this profile | `Acme Corp — US` |
| **Key Size** | RSA key length: `2048` (standard) or `4096` (stronger) | `2048` |
| **Country** | Two-letter ISO country code | `US` |
| **State / Province** | State or province | `California` |
| **City / Locality** | City | `San Francisco` |
| **Organization Name** | Your organisation's legal name | `Acme Corp` |
| **Organizational Unit** | Department or team | `IT` |
| **Email Address** | Contact email embedded in the CSR | `ssl@acme.com` |

4. Click **Save Profile**.

### 4.2 Set the Default Profile

The profile marked **default** (green badge) is used automatically when only one profile exists, or pre-selected when creating a new certificate with multiple profiles.

To change the default:

1. Go to **Profiles**.
2. Click **Set Default** next to the profile you want to promote.

Only one profile can be the default at a time. The previous default is unset automatically.

### 4.3 Edit or Delete a Profile

- **Edit:** click the **Edit** button next to a profile, update the fields, and click **Save Profile**.
- **Delete:** click **Delete** and confirm. You cannot delete the last remaining profile.

> Changing or deleting a profile does not affect certificates that were already created — each certificate stores a permanent copy of the subject fields at the time it was generated.

---

## 5. Certificate Chains

A **chain** is a named collection of the intermediate (and optionally root) CA certificates that connect your domain certificate back to a trusted root. You must set up at least one chain before you can generate full bundled download formats.

Common scenarios for multiple chains:
- You use different Certificate Authorities for different certificate types.
- Your CA rotated their intermediate certificate — you need the old chain for existing certs and the new chain for new ones.

### 5.1 Create a Chain

1. Navigate to **Chains** in the navbar.
2. Click **New Chain**.
3. Enter a **Name** (e.g. `DigiCert 2024`) and an optional **Description**.
4. Click **Save**.

You are taken to the **Chain Detail** page where you add the individual CA certificates.

### 5.2 Add Intermediate Certificates

From the **Chain Detail** page, click **Add Certificate**. Fill in:

| Field | Description |
|---|---|
| **Display Name** | A label for this entry, e.g. `DigiCert TLS RSA SHA256 2020 CA1` |
| **Order** | Position in the chain. `1` = the intermediate that directly signed your domain cert; higher numbers go toward the root |
| **PEM Data** | The certificate in PEM format, including the `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` lines |

Click **Save**. Repeat for each certificate in the chain (typically an intermediate and a root).

Use the **▲ / ▼** chevron buttons on each row to reorder entries on the Chain Detail page.

### 5.3 Import a Bundle

If your CA provides a single file containing multiple certificates concatenated together (common with `.crt`, `.pem`, or `.ca-bundle` files), use **Import Bundle** instead of adding them one by one:

1. On the **Chain Detail** page, click **Import Bundle**.
2. Paste the full PEM contents or upload the file — the app splits it into individual certificates automatically.
3. Review the detected certificates and click **Import**.

Each certificate is added as a separate entry in the chain, ordered from the first PEM block to the last.

---

## 6. Certificate Authorities (Internal CA)

SSL Manager includes a built-in Certificate Authority module. An internal CA lets you sign certificates entirely within SSL Manager — no external CA portal required. This is useful for:

- Internal services and development environments that don't require a publicly-trusted certificate.
- Network equipment such as Cisco ISE, firewalls, and load balancers that generate their own CSRs and need a signed certificate returned to them.
- Lab and staging environments where you control the full trust chain.

Each CA is a self-signed root CA. You can create multiple CAs — for example one per environment (dev, staging, prod) or one per team.

### 6.1 Create a CA

1. Navigate to **CAs** in the navbar.
2. Click **New CA**.
3. Fill in the form:

| Field | Description | Default |
|---|---|---|
| **CA Name** | A short descriptive label, also used as the Common Name | — |
| **Description** | Optional free-text note | — |
| **Validity Period** | How long the CA certificate remains valid | 10 years |
| **Key Size** | RSA key length: `2048` or `4096` | 4096 |
| **Country** | Two-letter ISO country code | From profile |
| **State / Province** | State or province | From profile |
| **City / Locality** | City | From profile |
| **Organization Name** | Organisation's legal name | From profile |
| **Organizational Unit** | Department or team | From profile |
| **Email Address** | Contact email embedded in the CA certificate | From profile |

4. Click **Create CA**.

The application generates an RSA private key (which never leaves the server) and a self-signed CA certificate. You are taken to the **CA Detail** page.

> **Key security note:** The CA private key is stored on the server alongside certificate private keys. Treat it with the same sensitivity as any other private key material. See the [backup note in the installation guide](../admin/INSTALL.md) for recommendations on securing backup archives.

### 6.2 Sign a Pending Certificate

Any certificate with status **Pending Signing** can be signed by an internal CA — whether it was created using **New Certificate** or imported using **Import CSR**.

**From the CA Detail page:**

1. Navigate to **CAs** and click the CA name.
2. The **Pending Certificates** table lists all certificates awaiting a signature.
3. For each certificate, set the **Validity (days)** field (default: 365).
4. Click **Sign** for the certificate you want to sign.

The certificate status changes to **Active** and the expiry date is set automatically.

**From the Certificate Detail page:**

If you are already viewing a pending certificate, a **Sign with Internal CA** card appears on the Certificate Detail page:

1. Select the CA to use from the dropdown.
2. Set the validity period in days.
3. Click **Sign Certificate**.

### 6.3 Download the CA Certificate

To configure a device or browser to trust certificates signed by your internal CA, you need to install the CA certificate as a trusted root.

1. Navigate to **CAs** and find the CA in the list.
2. Click **Download Cert** to download the CA certificate as a PEM file.

Or from the **CA Detail** page, the CA certificate is displayed in PEM format and can be copied or downloaded from there.

Install this PEM file as a trusted root CA on any machine or device that needs to trust certificates signed by it.

### 6.4 Delete a CA

Deleting a CA removes its private key and certificate from SSL Manager. **Certificates already signed by the CA remain in the system and are not affected**, but you will no longer be able to sign new certificates with it.

1. Navigate to **CAs** and click the CA name.
2. Scroll to the **Danger Zone** section at the bottom of the CA Detail page.
3. Click **Delete CA** and confirm.

---

## 7. Certificate Lifecycle

### 7.1 Create a New Certificate

1. From the **Certificates** page, click **New Certificate**.
2. If you have multiple profiles, a **profile dropdown** appears at the top. Select the profile that matches this certificate's organisation and click **Apply** to fill the subject fields. You can edit any field after applying.
3. Fill in the form:

| Field | Description |
|---|---|
| **Common Name (Domain)** | The primary domain this certificate covers, e.g. `www.example.com` or `*.example.com` |
| **Subject Alternative Names** | Additional domains — one per line. The CN is included automatically. Leave blank if only one domain is needed. |
| **Key Size** | Pre-filled from the profile. Change only if you need a different size for this certificate. |
| **Country / State / City / Org / OU / Email** | Pre-filled from the profile. Edit as needed for this specific certificate. |
| **Assign Chain** | Select the certificate chain that will be used when building download bundles. Can be changed later. |

4. Click **Generate RSA Key & CSR**.

The application generates a new RSA private key (which never leaves the server) and a Certificate Signing Request. You are taken to the **Certificate Detail** page. The status shows **Pending Signing**.

### 7.2 Download and Submit the CSR

The CSR is what you send to your Certificate Authority (CA) to request a signed certificate.

1. On the **Certificate Detail** page, click **Download CSR**.
2. Log in to your CA's portal (e.g. DigiCert, Sectigo, GoDaddy, Let's Encrypt with a manual workflow), **or** sign the certificate using an internal CA (see [Section 6.2](#62-sign-a-pending-certificate)).
3. Start a new certificate order and paste or upload the `.csr` file when the CA asks for it.
4. Complete any domain validation (DCV) steps required by the CA (email, DNS record, or file upload).
5. Once the CA approves and issues the certificate, download it. You want the **domain certificate only** — not the bundle that includes intermediates. The file is usually a `.crt` or `.pem` file.

> **Keep the original certificate record open.** The private key is stored server-side and is already paired with this CSR. You must upload the signed certificate back to the same certificate record.

### 7.3 Upload the Signed Certificate

1. Return to the **Certificate Detail** page for your certificate.
2. In the **Signed Certificate** section, either:
   - Click **Choose File** and select the `.crt`/`.pem` file downloaded from your CA, **or**
   - Open the file in a text editor, copy the entire PEM block (including the `-----BEGIN CERTIFICATE-----` header and `-----END CERTIFICATE-----` footer), and paste it into the text area.
3. Click **Save Certificate**.

The application validates the PEM and extracts the expiry date. The status changes to **Active** and the expiry date appears with a colour indicator:

| Colour | Meaning |
|---|---|
| Green | More than 90 days remaining |
| Yellow | 30–90 days remaining |
| Red | Fewer than 30 days remaining or already expired |

All download formats are now available.

### 7.4 Import an External CSR

Some systems — network appliances, load balancers, identity platforms such as Cisco ISE — generate their own private key and CSR internally and export only the CSR for signing. In this case you do not have access to the private key, but you still need a signed certificate returned to the device.

Use **Import CSR** for this workflow:

1. On the **Certificates** page, click **Import CSR**.
2. Either paste the CSR PEM block (including the `-----BEGIN CERTIFICATE REQUEST-----` header and footer) into the text area, or upload the `.csr` file directly.
3. Optionally assign a certificate chain.
4. Click **Import CSR**.

SSL Manager parses the CSR, extracts the Common Name and Subject Alternative Names, and creates a certificate record with status **Pending Signing**. The private key is **not** stored — it remains on the originating device.

**Signing an imported CSR:**

The imported certificate can be signed in the same way as any other pending certificate:
- Use an internal CA (see [Section 6.2](#62-sign-a-pending-certificate)).
- Or download the CSR and submit it to an external CA, then upload the signed certificate back.

**Download restrictions for imported CSRs:**

Because the private key is not held by SSL Manager, formats that require it are unavailable:

| Format | Available? |
|---|---|
| Certificate PEM | Yes |
| DER | Yes |
| Full Chain PEM | No (requires private key) |
| Component ZIP | No (requires private key) |
| PKCS#12 / PFX | No (requires private key) |
| Java KeyStore (JKS) | No (requires private key) |
| P7B | No (requires private key) |

Download the **Certificate PEM** and install it on the originating device following that device's certificate import procedure.

---

## 8. Browsing and Finding Certificates

The **Certificates** page lists all certificates with their domain, status, expiry, SANs count, and creation date.

### Sorting

Click any column header to sort by that column. Click again to reverse the sort direction. An arrow icon indicates the active sort column. The default sort is **Created** (newest first).

### Searching

Type in the **search bar** above the table to filter certificates in real time. The search checks:

- Domain name
- Status (`active`, `expired`, `pending signing`)
- Organisation name
- Country code
- Email address
- Expiry date (in `YYYY-MM-DD` format)
- Creation date
- SAN domains

The counter on the right of the search bar shows how many certificates match (e.g. `3 of 12 certificates`). Clear the search box to show all certificates again.

**Examples:**
- Type `expired` to see all expired certificates at a glance.
- Type `example.com` to find all certificates covering that domain.
- Type `2025-` to list certificates expiring or created in 2025.
- Type `acme` to find all certificates tied to that organisation.

### Rows per page

Use the **10 / 20 / 50 / All** button group (top-right of the toolbar) to control how many certificates are shown at once. The default is 20. When more rows exist than the selected page size, a page navigation bar appears below the table.

---

## 9. Downloading Certificates

Once a signed certificate has been uploaded, the **Downloads** section on the **Certificate Detail** page offers several formats. Choose the format that matches your server or platform.

### Full Chain PEM

**Button:** Download .pem
**File:** `domain-fullchain.pem`

Contains the private key, signed certificate, and all intermediate certificates in a single file. Use this for **HAProxy**, some CDN origin configurations, and any tool that requires everything in one PEM file.

### Component ZIP

**Button:** Download .zip
**File:** `domain-certs.zip`

A ZIP archive containing individual files for maximum flexibility:

| File | Use |
|---|---|
| `private_key.pem` | nginx `ssl_certificate_key`, Apache `SSLCertificateKeyFile` |
| `certificate.pem` | The domain certificate on its own |
| `chain.pem` | Intermediate certificates only — Apache `SSLCACertificateFile` |
| `fullchain.pem` | Domain certificate + intermediates (no key) — nginx `ssl_certificate`, Apache `SSLCertificateFile` |
| `certificate.csr` | The original CSR — keep for your records |

### PKCS#12 / PFX

**Button:** Download .p12
**File:** `domain.p12`

A password-protected bundle containing the private key, certificate, and chain in a single encrypted file.

1. Enter a password in the **Password** field before clicking Download.
2. Store the password securely — it is required every time the `.p12` file is imported.

Use for: **Windows IIS**, Azure App Service, F5 BIG-IP, and any platform that imports a PFX file.

### Java KeyStore (JKS)

**Button:** Download .jks
**Fields:** Store password (default: `changeit`), Alias (default: `certificate`)
**File:** `domain.jks`

Use for: **Tomcat**, Spring Boot, JBoss/WildFly, Jetty, and any Java application server.

### P7B (Chain Bundle, No Private Key)

**Button:** Download .p7b
**File:** `domain.p7b`

Contains the signed certificate and all intermediate certificates. Does **not** include the private key.

Use for: **Windows Server** (MMC certificate store), IIS when the private key is already present, some enterprise CA portals.

### DER (Binary Certificate)

**Button:** Download .der
**File:** `domain.der`

The domain certificate in binary DER encoding. Does not include the private key or chain.

Use for: Java `keytool` imports, some embedded devices, and systems that require a binary certificate file.

---

## 10. Renewing a Certificate

Certificates typically need to be renewed annually. SSL Manager's renew/rekey workflow generates a fresh private key and CSR while keeping your existing certificate active until you are ready to replace it.

1. On the **Certificate Detail** page, click **Renew / Rekey**.
2. The form pre-fills with the existing domain, SANs, subject fields, and chain assignment. Edit any field that has changed (e.g. updated organisation name or a new SAN).
3. Click **Generate RSA Key & CSR**.

A new certificate record is created with status **Pending Signing**. Your original certificate remains **Active** and continues to serve traffic.

4. Follow the same steps as a new certificate: download the CSR, submit it to your CA, upload the returned signed certificate.
5. Once the new certificate is verified and deployed, return to the **Certificates** page and delete the old record.

> **Tip:** Start renewals at least 30 days before expiry. The expiry badge changes from green to yellow at 90 days and red at 30 days as a visual reminder.

---

## 11. User Management

User management is available to **superadmin** accounts only. Navigate to **Users** in the navbar.

### Roles

| Role | Capabilities |
|---|---|
| `superadmin` | Everything a user can do, plus manage users and view the audit log |
| `user` | Create and manage certificates, chains, and profiles; download all formats |

### Add a User

1. Click **Add User**.
2. Fill in username, email, password, confirm password, and role.
3. Click **Create User**.

### Edit a User

Click the pencil icon next to a user. You can update:
- Username and email
- Role (`superadmin` or `user`)
- Active status — deactivating a user prevents login without deleting the account

To change a password, fill in the **New Password** and **Confirm Password** fields. Leave them blank to keep the current password.

### Delete a User

Click the trash icon next to a user. You cannot delete your own account.

### Superadmin Protection

At least one active superadmin must always exist. The following are blocked when only one active superadmin remains:
- Deleting the last superadmin
- Changing the last superadmin's role to `user`
- Deactivating the last superadmin's account

To transfer superadmin responsibilities, promote a second user to `superadmin` first, then make changes to the original account.

---

---

## 12. Audit Log

The **Audit Log** is available to **superadmin** accounts only. Navigate to **Audit Log** in the navbar.

Every action taken in the application is recorded — logins, certificate creation, signing, downloads, user changes, and automated system events such as backups.

### Searching

Type in the search bar to filter log entries in real time across all columns (user, action, resource, result, and detail). Click the **✕** button or clear the search box to reset.

### Sorting

Click any underlined column header to sort by that column. Click again to reverse the direction.

### Rows per page

Use the **10 / 20 / 50 / All** button group to control how many entries are shown per page. The default is 20. Page navigation appears below the table when there are more entries than the current page size.

### Result badges

| Badge | Meaning |
|---|---|
| `success` | The action completed without errors |
| `failure` | The action failed (detail column gives the reason) |
| Other | Informational status specific to the action type |

---

*For installation, deployment, and system administration see [README.md](../../README.md). For detailed CLI verification commands and CA-specific notes see [WORKFLOW.md](../developer/WORKFLOW.md).*