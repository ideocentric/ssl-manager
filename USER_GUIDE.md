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
6. [Certificate Lifecycle](#6-certificate-lifecycle)
   - [Create a New Certificate](#61-create-a-new-certificate)
   - [Download and Submit the CSR](#62-download-and-submit-the-csr)
   - [Upload the Signed Certificate](#63-upload-the-signed-certificate)
7. [Browsing and Finding Certificates](#7-browsing-and-finding-certificates)
8. [Downloading Certificates](#8-downloading-certificates)
9. [Renewing a Certificate](#9-renewing-a-certificate)
10. [User Management](#10-user-management)

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

You can **drag and drop** entries on the Chain Detail page to reorder them if needed.

### 5.3 Import a Bundle

If your CA provides a single file containing multiple certificates concatenated together (common with `.crt`, `.pem`, or `.ca-bundle` files), use **Import Bundle** instead of adding them one by one:

1. On the **Chain Detail** page, click **Import Bundle**.
2. Paste the full PEM contents or upload the file — the app splits it into individual certificates automatically.
3. Review the detected certificates and click **Import**.

Each certificate is added as a separate entry in the chain, ordered from the first PEM block to the last.

---

## 6. Certificate Lifecycle

### 6.1 Create a New Certificate

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

### 6.2 Download and Submit the CSR

The CSR is what you send to your Certificate Authority (CA) to request a signed certificate.

1. On the **Certificate Detail** page, click **Download CSR**.
2. Log in to your CA's portal (e.g. DigiCert, Sectigo, GoDaddy, Let's Encrypt with a manual workflow).
3. Start a new certificate order and paste or upload the `.csr` file when the CA asks for it.
4. Complete any domain validation (DCV) steps required by the CA (email, DNS record, or file upload).
5. Once the CA approves and issues the certificate, download it. You want the **domain certificate only** — not the bundle that includes intermediates. The file is usually a `.crt` or `.pem` file.

> **Keep the original certificate record open.** The private key is stored server-side and is already paired with this CSR. You must upload the signed certificate back to the same certificate record.

### 6.3 Upload the Signed Certificate

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

---

## 7. Browsing and Finding Certificates

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

---

## 8. Downloading Certificates

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

## 9. Renewing a Certificate

Certificates typically need to be renewed annually. SSL Manager's renew/rekey workflow generates a fresh private key and CSR while keeping your existing certificate active until you are ready to replace it.

1. On the **Certificate Detail** page, click **Renew / Rekey**.
2. The form pre-fills with the existing domain, SANs, subject fields, and chain assignment. Edit any field that has changed (e.g. updated organisation name or a new SAN).
3. Click **Generate RSA Key & CSR**.

A new certificate record is created with status **Pending Signing**. Your original certificate remains **Active** and continues to serve traffic.

4. Follow the same steps as a new certificate: download the CSR, submit it to your CA, upload the returned signed certificate.
5. Once the new certificate is verified and deployed, return to the **Certificates** page and delete the old record.

> **Tip:** Start renewals at least 30 days before expiry. The expiry badge changes from green to yellow at 90 days and red at 30 days as a visual reminder.

---

## 10. User Management

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

*For installation, deployment, and system administration see [README.md](README.md). For detailed CLI verification commands and CA-specific notes see [WORKFLOW.md](WORKFLOW.md).*
