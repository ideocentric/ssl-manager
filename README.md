# SSL Manager

A Flask-based web application for managing SSL certificate lifecycle — from RSA key and CSR generation through to signed certificate storage and multi-format bundle downloads.

## Features

- User authentication with first-run setup wizard
- Two roles: **superadmin** (manage users) and **user** (manage certificates)
- At least one superadmin is always enforced — the last superadmin cannot be removed or demoted
- Configure organization-wide defaults (key size, country, state, org name, etc.)
- Generate RSA private keys (2048 or 4096-bit) and CSRs per domain
- Support for Subject Alternative Names (SANs)
- Manage intermediate and root certificate chain
- Upload signed certificates returned by your CA
- Color-coded expiration tracking (green → yellow → orange → red)
- Download certificates in multiple formats:
  - **Full Chain PEM** — private key + signed cert + intermediates in one file
  - **Component PEMs (ZIP)** — individual PEM files ready for Apache2 / nginx deployment (see below)
  - **PKCS#12 / PFX** — password-protected bundle (`.p12`)
  - **JKS** — Java KeyStore with configurable password and alias (`.jks`)
  - **P7B** — certificate chain bundle, no private key (`.p7b`, requires `openssl` in PATH)

### Component ZIP contents

| File                | Contents                                      | Deployment use                                                    |
|---------------------|-----------------------------------------------|-------------------------------------------------------------------|
| `private_key.pem`   | RSA private key                               | nginx `ssl_certificate_key` / Apache `SSLCertificateKeyFile`      |
| `certificate.pem`   | Signed certificate only                       | Inspection / verification                                         |
| `chain.pem`         | Intermediates concatenated (no cert, no key)  | Apache `SSLCACertificateFile`, or copy files to `/etc/pki/certs/` |
| `fullchain.pem`     | Signed cert + intermediates (no private key)  | nginx `ssl_certificate` / Apache `SSLCertificateFile` (2.4.8+)    |
| `certificate.csr`   | Original CSR                                  | Records                                                           |

> The **Full Chain PEM** single-file download (`domain-fullchain.pem`) includes the private key as well and is intended for tools that require everything in one file (e.g. HAProxy, some load balancers).

---

## Authentication

### First run

The first time you open the app you will be redirected to `/setup`. Fill in a username, email, and password to create the initial **superadmin** account. All subsequent visits require login.

### Roles

| Role | Capabilities |
|---|---|
| `superadmin` | Everything a user can do, plus: add/edit/delete users, change roles |
| `user` | Create and manage certificates, download all formats, manage chain certs and settings |

### User management

Superadmins access the **Users** page from the navbar. From there you can:

- Add new users and assign their role
- Edit an existing user's username, email, role, or active status
- Reset a user's password
- Delete a user

**Safeguard:** the last active superadmin cannot be deleted, demoted to `user`, or deactivated. There must always be at least one superadmin.

---

## Certificate Workflow

1. **Settings** → configure org defaults (key size, country, org name, etc.)
2. **Chain Certificates** → add your intermediate and root CA certs, set their chain order
3. **New Certificate** → enter a domain (and optional SANs); the app generates an RSA key and CSR automatically
4. Download the `.csr` file and submit it to your Certificate Authority
5. Once the CA returns a signed cert, paste the PEM into the **Upload** section
6. All download formats become available immediately

For a full step-by-step walkthrough — including CA setup, CSR signing, importing intermediates, all export formats, and verification commands — see **[WORKFLOW.md](WORKFLOW.md)**.

---

## Installing on Ubuntu

`install.sh` installs SSL Manager as a production systemd service on Ubuntu 20.04 or later.

### What the installer does

- Installs system packages (`python3`, `openssl`, `gcc`, `nginx`)
- Creates a dedicated `ssl-manager` service account
- Copies app files to `/opt/ssl-manager`
- Creates a Python venv and installs all dependencies (including `gunicorn`)
- Writes an environment config file to `/etc/ssl-manager/env`
- Installs and starts a `systemd` service (runs gunicorn, auto-restarts on failure)
- Optionally configures nginx as a reverse proxy

### Install

```bash
git clone https://github.com/your-org/ssl-manager.git
cd ssl-manager
sudo bash install.sh
```

The installer is interactive and will prompt for:

| Prompt | Default | Notes |
|---|---|---|
| Listen port | `5000` | gunicorn binds to `127.0.0.1:<port>` |
| Worker processes | `2` | gunicorn workers; increase for higher load |
| Secret key | auto-generated | Used to sign Flask sessions |
| nginx reverse proxy | yes | Exposes the app on port 80 |
| Server name / domain | `_` | nginx `server_name`; use your actual domain or `_` to catch all |

### Post-install

Once the service is running, open the app URL in a browser. You will be directed to the **first-run setup page** to create your superadmin account. Additional users can then be added from the **Users** page inside the app.

```bash
# Service management
sudo systemctl status ssl-manager
sudo systemctl restart ssl-manager
sudo journalctl -u ssl-manager -f          # live logs

# Edit config (port, secret key, database path)
sudo nano /etc/ssl-manager/env
sudo systemctl restart ssl-manager
```

Files installed:

| Path | Purpose |
|---|---|
| `/opt/ssl-manager/` | Application code and venv |
| `/var/lib/ssl-manager/ssl_manager.db` | SQLite database (persists across upgrades) |
| `/etc/ssl-manager/env` | Environment config (secret key, DB path, port) |
| `/etc/systemd/system/ssl-manager.service` | systemd unit |
| `/etc/nginx/sites-available/ssl-manager` | nginx reverse proxy config (if enabled) |

### Upgrade

After pulling new code, re-run with `--upgrade`. App files and dependencies are updated; the database and config file are left untouched.

```bash
git pull
sudo bash install.sh --upgrade
```

### Uninstall

```bash
sudo bash install.sh --uninstall
```

Prompts before removing the database and service user. The database at `/var/lib/ssl-manager` is preserved by default.

---

## Running Locally

### Prerequisites

- Python 3.10+
- `openssl` in your PATH (for P7B downloads)

### Setup

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

The app starts at **http://localhost:5000**

---

## Docker

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/) (included with Docker Desktop)

### Start

```bash
docker compose up -d
```

Builds the image on first run. The app will be available at **http://localhost:5001**

### Stop

```bash
docker compose down
```

The SQLite database is stored in a named Docker volume (`ssl-manager-db`) and persists between restarts.

### View Logs

```bash
docker compose logs -f
```

### Rebuild After Code Changes

```bash
docker compose up --build -d
```

### Reset (Wipe Database)

```bash
docker compose down -v
```

The `-v` flag removes the named volume, deleting all certificates and settings.

### Run on a Different Port

Edit `docker-compose.yml` and change the left side of the port mapping:

```yaml
ports:
  - "8080:5000"   # app will be at http://localhost:8080
```

### Set a Custom Secret Key

The `SECRET_KEY` environment variable is used to sign Flask sessions. Set it in `docker-compose.yml`:

```yaml
environment:
  - SECRET_KEY=your-strong-secret-here
```

---

## Local Development CA

`dev_ca.py` is a helper script for end-to-end UI testing. It creates a two-tier CA hierarchy that mirrors a real-world CA (e.g. GoDaddy) — a self-signed **root CA** issues an **intermediate CA**, and the intermediate signs domain certificates. This lets you exercise every download format, including the full chain assembly, without a real Certificate Authority.

```
Root CA  →  Intermediate CA  →  Domain certificate
```

Files created in `dev-ca/`:

| File                  | Purpose                              |
|-----------------------|--------------------------------------|
| `root.key`            | Root CA private key (keep secret)    |
| `root.crt`            | Root CA certificate (self-signed)    |
| `intermediate.key`    | Intermediate CA private key          |
| `intermediate.crt`    | Intermediate CA cert (signed by root)|
| `signed/<domain>.crt` | Domain certs signed by intermediate  |

### One-time setup

```bash
# 1. Create the root CA and intermediate CA
python dev_ca.py init
```

Then add both CA certs to ssl-manager under **Chain Certificates → Add** (run once):

```bash
# Intermediate CA — add first, set order: 1
python dev_ca.py chain --intermediate

# Root CA — add second, set order: 2
python dev_ca.py chain --root
```

Paste each printed PEM into a separate Chain Certificate entry.

### Per-certificate workflow

```bash
# 1. In ssl-manager: Certificates → New → fill in the domain → Save
# 2. On the certificate detail page, download the .csr file
# 3. Sign it with the intermediate CA
python dev_ca.py sign ~/Downloads/example.com.csr

# 4. Copy the printed PEM and paste it into
#    Certificates → [your domain] → Upload Signed Certificate
# 5. All download formats are now available on the detail page
```

The signed certificate is also saved to `dev-ca/signed/<domain>.crt` for reference.

### Other commands

```bash
# Show subject, issuer, and validity dates for both CAs
python dev_ca.py info

# Print both chain PEMs together (with instructions)
python dev_ca.py chain

# Sign with a custom validity period (default is 365 days)
python dev_ca.py sign example.com.csr --days 90

# Regenerate both CAs (overwrites all existing CA files)
python dev_ca.py init --force
```

> **Note:** The `dev-ca/` directory is gitignored. Keep `dev-ca/root.key` and `dev-ca/intermediate.key` out of version control.

---

## Project Structure

```
ssl-manager/
├── app.py                  # Flask app — routes, models, crypto helpers
├── dev_ca.py               # Local dev CA for signing test CSRs
├── install.sh              # Ubuntu production installer
├── test_app.py             # pytest test suite
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── templates/
    ├── base.html               # Bootstrap 5 layout, navbar, flash messages
    ├── login.html              # Login page
    ├── setup.html              # First-run admin account setup
    ├── users.html              # User management (superadmin only)
    ├── user_form.html          # Add / edit user
    ├── certificates.html       # Certificate list with expiry badges
    ├── cert_new.html           # New certificate form
    ├── cert_detail.html        # Detail, upload, and download page
    ├── settings.html           # Org defaults
    ├── intermediates.html      # Chain certificate management
    └── intermediate_form.html
```

## Dependencies

| Package            | Purpose                                    |
|--------------------|--------------------------------------------|
| Flask              | Web framework                              |
| Flask-SQLAlchemy   | ORM / SQLite persistence                   |
| Flask-Login        | Session-based authentication               |
| cryptography       | RSA key gen, CSR, x509 parsing, PKCS#12    |
| pyjks              | Java KeyStore (JKS) creation               |
| gunicorn           | Production WSGI server                     |
| openssl (system)   | P7B/PKCS#7 bundle generation               |
