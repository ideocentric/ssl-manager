# SSL Manager

A Flask-based web application for managing SSL certificate lifecycle — from RSA key and CSR generation through to signed certificate storage and multi-format bundle downloads.

## Features

- User authentication with first-run setup wizard
- Two roles: **superadmin** (manage users) and **user** (manage certificates)
- At least one superadmin is always enforced — the last superadmin cannot be removed or demoted
- **Named certificate profiles** — create multiple profiles (Name, key size, country, org name, etc.) and apply them as templates when generating new certificates; a default profile is pre-selected automatically
- Generate RSA private keys (2048 or 4096-bit) and CSRs per domain
- Support for Subject Alternative Names (SANs)
- **Named certificate chains** — manage multiple independent intermediate/root CA sets, each with drag-to-reorder support; assign each chain to the certificates that use it (useful when transitioning between CA providers or intermediate generations)
- **Bundle import** — upload or paste a multi-cert PEM bundle (e.g. a CA-provided `.crt` file) to auto-populate a chain in one step
- **Certificate list sort and search** — click column headers to sort by Domain, Status, Expiry, SANs, or Created; type in the search bar to filter in real time across domain, status, org name, country, email, dates, and SAN domains
- Upload signed certificates returned by your CA — via file upload or paste
- **Renew / Rekey** — pre-populate a new CSR from an existing certificate to streamline annual renewals
- Color-coded expiration tracking (green → yellow → red) on both certificate and chain detail views
- Download certificates in multiple formats:
  - **Full Chain PEM** — private key + signed cert + intermediates in one file
  - **Component PEMs (ZIP)** — individual PEM files ready for Apache / nginx deployment
  - **PKCS#12 / PFX** — password-protected bundle (`.p12`)
  - **JKS** — Java KeyStore with configurable password and alias (`.jks`)
  - **P7B** — certificate chain bundle, no private key (`.p7b`, requires `openssl` in PATH)
  - **DER** — binary-encoded certificate (`.der`, no key, no chain)

### Component ZIP contents

| File | Contents | Deployment use |
|---|---|---|
| `private_key.pem` | RSA private key | nginx `ssl_certificate_key` / Apache `SSLCertificateKeyFile` |
| `certificate.pem` | Signed certificate only | Inspection / verification |
| `chain.pem` | Intermediates concatenated (no cert, no key) | Apache `SSLCACertificateFile` |
| `fullchain.pem` | Signed cert + intermediates (no private key) | nginx `ssl_certificate` / Apache `SSLCertificateFile` (2.4.8+) |
| `certificate.csr` | Original CSR | Records |

> The **Full Chain PEM** single-file download (`domain-fullchain.pem`) includes the private key as well and is intended for tools that require everything in one file (e.g. HAProxy, some load balancers).

---

## Authentication

### First run

The first time you open the app you will be redirected to `/setup`. Fill in a username, email, and password to create the initial **superadmin** account. All subsequent visits require login.

### Roles

| Role | Capabilities |
|---|---|
| `superadmin` | Everything a user can do, plus: add/edit/delete users, change roles |
| `user` | Create and manage certificates, download all formats, manage chains and profiles |

### User management

Superadmins access the **Users** page from the navbar. From there you can:

- Add new users and assign their role
- Edit an existing user's username, email, role, or active status
- Reset a user's password
- Delete a user

**Safeguard:** the last active superadmin cannot be deleted, demoted to `user`, or deactivated.

---

## Certificate Workflow

1. **Profiles** → create one or more named profiles with your org defaults (key size, country, org name, etc.); mark one as the default
2. **Chains** → create one or more named chains; add your intermediate and root CA certs to each, or use **Import Bundle** to import a multi-cert PEM file in one step; drag entries to set their order
3. **New Certificate** → enter a domain (and optional SANs); select a profile to pre-fill subject fields; assign a chain; the app generates an RSA key and CSR automatically
4. Download the `.csr` file and submit it to your Certificate Authority
5. Once the CA returns a signed cert, upload the file or paste the PEM into the **Signed Certificate** section on the certificate detail page
6. All download formats become available immediately

### Annual renewal / rekey

1. On the certificate detail page, click **Renew / Rekey** — the form pre-fills with the existing domain, SANs, org fields, and chain assignment
2. A brand-new RSA key and CSR are generated; the existing certificate stays active
3. Submit the new CSR to your CA, upload the returned cert to the new certificate record
4. Once verified, delete the old certificate

For a full step-by-step walkthrough — including CA setup, CSR signing, importing intermediates, all export formats, and verification commands — see **[WORKFLOW.md](WORKFLOW.md)**.

---

## Installing on Ubuntu

`install.sh` installs SSL Manager as a production systemd service on Ubuntu 20.04 or later.

### Deployment architecture

```
Browser  ←→  SSH tunnel (encrypted, auth-gated)
                 ↓
           nginx  (127.0.0.1:<PORT> — loopback only)
                 ↓  Unix socket  /run/ssl-manager/ssl-manager.sock
           gunicorn  (ssl-manager user, no login shell)
                 ↓
           Flask app  (/opt/ssl-manager, root:ssl-manager, mode 750)
                 ↓
           SQLite DB  (/var/lib/ssl-manager, ssl-manager only, mode 700)
```

nginx listens **only on the loopback interface** (`127.0.0.1`). No port is reachable from the network. Remote access is provided entirely through SSH port forwarding, meaning a valid SSH session is required before a single HTTP byte can reach the application.

### What the installer does

- Installs system packages (`python3`, `openssl`, `gcc`, `nginx`)
- Creates a dedicated `ssl-manager` system account (no login shell, no home directory)
- Adds `www-data` (the nginx user) to the `ssl-manager` group so it can reach the Unix socket — no other process has access
- Creates all directories with enforced ownership and permissions (see table below)
- Copies app files to `/opt/ssl-manager`
- Creates a Python venv and installs all dependencies (including `gunicorn`)
- Generates a cryptographically random `SECRET_KEY` and writes it to `/etc/ssl-manager/env` (readable only by root and the service user)
- Installs a hardened `systemd` service unit (auto-restarts on failure; see [Systemd hardening](#systemd-hardening))
- Installs and enables a `systemd` timer (`ssl-manager-backup.timer`) that runs `backup.sh` daily at 02:00, retaining 7 days of compressed, integrity-checked backups in `/var/backups/ssl-manager/`
- Configures nginx as a reverse proxy with rate limiting and direct static file serving

### Install

```bash
git clone https://github.com/your-org/ssl-manager.git
cd ssl-manager
sudo bash install.sh
```

The installer prompts for:

| Prompt | Default | Notes |
|---|---|---|
| nginx listen port | `5001` | nginx binds to `127.0.0.1:<port>` — loopback only |
| Gunicorn workers | `2` | Increase for higher concurrent load |
| Secret key | auto-generated | 256-bit random hex; used to sign Flask sessions |

### Remote access via SSH port forwarding

Because nginx listens on loopback only, the application is not directly reachable from another machine. Use SSH port forwarding to create an encrypted tunnel:

```bash
# On your local machine — forward local port 5001 to the server's loopback
ssh -L 5001:127.0.0.1:5001 user@your-server

# Then open in your browser
http://localhost:5001
```

The tunnel is active for the duration of the SSH session. You can also add it to your SSH config for convenience:

```
# ~/.ssh/config
Host ssl-manager
    HostName your-server
    User your-user
    LocalForward 5001 127.0.0.1:5001
```

Then simply `ssh ssl-manager` and browse to `http://localhost:5001`.

### Post-install

After install, open `http://localhost:5001` (via the tunnel or on the server itself) and complete the **first-run setup** to create your superadmin account.

```bash
# Service management
sudo systemctl status ssl-manager
sudo systemctl restart ssl-manager
sudo journalctl -u ssl-manager -f          # live application logs

# Edit config (secret key, database path)
sudo nano /etc/ssl-manager/env
sudo systemctl restart ssl-manager

# Application logs
sudo tail -f /var/log/ssl-manager/error.log
sudo tail -f /var/log/ssl-manager/access.log

# nginx logs
sudo tail -f /var/log/nginx/ssl-manager-access.log
sudo tail -f /var/log/nginx/ssl-manager-error.log

# Backup timer
sudo systemctl status ssl-manager-backup.timer   # next scheduled run
sudo systemctl list-timers ssl-manager-backup.timer
sudo systemctl start ssl-manager-backup.service  # run a backup immediately

# Manual backup with custom retention
sudo bash /opt/ssl-manager/backup.sh --days 30 --dest /mnt/nas/ssl-backups
```

### File layout

| Path | Owner | Mode | Purpose |
|---|---|---|---|
| `/opt/ssl-manager/` | `root:ssl-manager` | `750` | Application code and venv |
| `/var/lib/ssl-manager/` | `ssl-manager:ssl-manager` | `700` | SQLite database — service user only |
| `/var/log/ssl-manager/` | `ssl-manager:ssl-manager` | `750` | gunicorn access and error logs |
| `/etc/ssl-manager/env` | `root:ssl-manager` | `640` | Environment config (SECRET_KEY, DATABASE_URL) |
| `/run/ssl-manager/ssl-manager.sock` | `ssl-manager:ssl-manager` | `660` | Unix socket between nginx and gunicorn |
| `/etc/systemd/system/ssl-manager.service` | `root` | `644` | systemd service unit |
| `/etc/systemd/system/ssl-manager-backup.service` | `root` | `644` | backup job unit (oneshot) |
| `/etc/systemd/system/ssl-manager-backup.timer` | `root` | `644` | backup timer (daily at 02:00) |
| `/var/backups/ssl-manager/` | `root` | `700` | compressed database backups (7-day retention) |
| `/etc/nginx/sites-available/ssl-manager` | `root` | `644` | nginx reverse proxy config |

### Systemd hardening

The service unit applies the following restrictions to the gunicorn process:

| Directive | Effect |
|---|---|
| `NoNewPrivileges=true` | Process cannot gain additional privileges via setuid or capabilities |
| `PrivateTmp=true` | Isolated `/tmp` — temporary files are not visible to other processes |
| `ProtectSystem=strict` | `/` and `/usr` mounted read-only; only the data and log directories are writable |
| `ProtectHome=true` | No access to `/home` or `/root` |
| `PrivateDevices=true` | Restricted device node access |
| `CapabilityBoundingSet=` | All Linux capabilities dropped |
| `SystemCallFilter=@system-service` | Only system calls needed by a typical service are permitted |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` | Only Unix sockets and IP networking |
| `LockPersonality=true` | Cannot change the execution domain |
| `RestrictRealtime=true` | Cannot acquire real-time scheduling |
| `RestrictSUIDSGID=true` | Cannot set-UID/set-GID bits |

### Host hardening

The steps below are strongly recommended after running the installer. None are automated by `install.sh` because they affect system-wide services (SSH, firewall) and incorrect configuration can lock you out of the server. Review each step before applying.

#### UFW firewall

SSL Manager's nginx instance binds to `127.0.0.1` only, so its port must **not** be opened in the firewall. Only SSH needs to be reachable from the network.

```bash
# Install ufw if not already present
sudo apt-get install -y ufw

# Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH — change 22 to your actual SSH port if non-standard
sudo ufw allow 22/tcp comment 'SSH'

# Rate-limit SSH to slow brute-force attempts (max 6 connections per 30 s per IP)
sudo ufw limit 22/tcp

# Enable the firewall (confirm with 'y' when prompted)
sudo ufw enable

# Verify — nginx port (e.g. 5001) must NOT appear here
sudo ufw status verbose
```

> **Note:** If you use a non-standard SSH port, replace `22` above with your port before enabling UFW to avoid locking yourself out.

#### fail2ban — SSH brute-force protection

```bash
sudo apt-get install -y fail2ban

# Create a local override (never edit the packaged jail.conf directly)
sudo tee /etc/fail2ban/jail.d/ssh-local.conf > /dev/null <<'EOF'
[sshd]
enabled  = true
port     = ssh
maxretry = 5
findtime = 10m
bantime  = 1h
EOF

sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd   # confirm the jail is active
```

Increase `bantime` (e.g. `24h` or `-1` for permanent) for a more restrictive posture.

#### SSH daemon hardening

Edit `/etc/ssh/sshd_config` (or drop a file in `/etc/ssh/sshd_config.d/`) and set:

```
# Disable password authentication — key-based auth only
PasswordAuthentication no
KbdInteractiveAuthentication no

# Prevent direct root login over SSH
PermitRootLogin no

# Only allow specific users to log in (replace 'youruser' with your actual username)
AllowUsers youruser

# Disable unused authentication methods
UsePAM yes
X11Forwarding no
```

Reload after editing:

```bash
# Test configuration before reloading — fix any errors reported here first
sudo sshd -t
sudo systemctl reload ssh
```

> **Important:** Open a second SSH session to verify access before closing your current one.

#### Automatic security updates

```bash
sudo apt-get install -y unattended-upgrades

# Enable and configure
sudo dpkg-reconfigure -plow unattended-upgrades

# Optionally configure automatic reboots for kernel updates
# Edit /etc/apt/apt.conf.d/50unattended-upgrades and set:
#   Unattended-Upgrade::Automatic-Reboot "true";
#   Unattended-Upgrade::Automatic-Reboot-Time "03:00";
```

#### Kernel and sysctl hardening

Add to `/etc/sysctl.d/99-hardening.conf`:

```
# Ignore ICMP redirects (prevent routing table poisoning)
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Do not send ICMP redirects
net.ipv4.conf.all.send_redirects = 0

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable SYN flood protection
net.ipv4.tcp_syncookies = 1

# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Restrict dmesg to root
kernel.dmesg_restrict = 1

# Prevent core dumps from exposing memory
fs.suid_dumpable = 0
```

Apply immediately:

```bash
sudo sysctl --system
```

### Upgrade

Pull new code and re-run with `--upgrade`. Application files and Python dependencies are updated; the database and config are left untouched.

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

## Security

The application implements multiple layers of defence:

### Input validation (server-side)
- Domain names and SANs validated against RFC hostname format (including wildcard support)
- Country codes enforced as exactly two letters
- Email addresses validated with regex
- Usernames restricted to letters, numbers, underscores, and hyphens
- All text fields trimmed and length-capped before storage
- Key size whitelisted to 2048 or 4096
- File uploads capped at 1 MB (`MAX_CONTENT_LENGTH`)
- PEM data validated by the `cryptography` library before storage

### CSRF protection
Every state-changing form includes a server-generated session token. Requests without a valid token are rejected before any application logic runs. The AJAX reorder endpoint uses the `X-CSRFToken` request header.

### HTTP security headers
Applied to every response:

| Header | Value |
|---|---|
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `X-XSS-Protection` | `1; mode=block` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Content-Security-Policy` | Scripts and styles restricted to `self` and `cdn.jsdelivr.net`; `frame-ancestors 'none'` |

### Template escaping
Jinja2 auto-escaping is enabled for all templates. No `| safe` filters are used on user-supplied data.

### Database access
All queries use the SQLAlchemy ORM with parameterised bindings. The one raw SQL statement (schema migration) operates only on a whitelisted set of hardcoded `(table, column)` pairs.

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

The app starts at **http://localhost:5001**

---

## Docker

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/) (included with Docker Desktop)

### Start

```bash
docker compose up -d
```

Builds the image on first run. The app will be available at **http://localhost:5001**.

### Stop

```bash
docker compose down
```

The SQLite database is stored in a named Docker volume (`ssl-manager-db`) and persists between restarts.

### View logs

```bash
docker compose logs -f
```

### Rebuild after code changes

```bash
docker compose up --build -d
```

### Reset (wipe database)

```bash
docker compose down -v
```

The `-v` flag removes the named volume, deleting all certificates and settings.

### Set a custom secret key

The `SECRET_KEY` environment variable signs Flask sessions. Set it in `docker-compose.yml`:

```yaml
environment:
  - SECRET_KEY=your-strong-secret-here
```

---

## Local Development CA

`dev_ca.py` is a helper script for end-to-end UI testing. It creates a two-tier CA hierarchy that mirrors a real-world CA — a self-signed **root CA** issues an **intermediate CA**, and the intermediate signs domain certificates. This lets you exercise every download format, including the full chain assembly, without a real Certificate Authority.

```
Root CA  →  Intermediate CA  →  Domain certificate
```

Files created in `dev-ca/`:

| File | Purpose |
|---|---|
| `root.key` | Root CA private key (keep secret) |
| `root.crt` | Root CA certificate (self-signed) |
| `intermediate.key` | Intermediate CA private key |
| `intermediate.crt` | Intermediate CA cert (signed by root) |
| `signed/<domain>.crt` | Domain certs signed by intermediate |

### One-time setup

```bash
# 1. Create the root CA and intermediate CA
python dev_ca.py init
```

Then in the app, create a chain under **Chains → New Chain**, then add both CA certs to it (run once):

```bash
# Print both chain PEMs with instructions
python dev_ca.py chain
```

Paste each printed PEM into a separate entry on the chain detail page, or save them to a `.crt` file and use **Import Bundle** to add both at once.

### Per-certificate workflow

```bash
# 1. In ssl-manager: Certificates → New → fill in the domain → Save
# 2. On the certificate detail page, download the .csr file
# 3. Sign it with the intermediate CA
python dev_ca.py sign ~/Downloads/example.com.csr

# 4. Upload the returned PEM on the certificate detail page
#    (Signed Certificate → upload file or paste PEM → Save Certificate)
# 5. All download formats are now available
```

The signed certificate is also saved to `dev-ca/signed/<domain>.crt` for reference.

### Other commands

```bash
# Show subject, issuer, and validity dates for both CAs
python dev_ca.py info

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
    ├── login.html
    ├── setup.html              # First-run admin account setup
    ├── users.html              # User list (superadmin only)
    ├── user_form.html          # Add / edit user
    ├── certificates.html       # Certificate list with sort, search, and expiry badges
    ├── cert_new.html           # New certificate / renew form
    ├── cert_detail.html        # Detail, signed cert upload, and downloads
    ├── profiles.html           # Profile list
    ├── profile_form.html       # Create / edit profile
    ├── chains.html             # Named chain list
    ├── chain_form.html         # Create / edit chain
    ├── chain_detail.html       # Chain intermediates with drag-to-reorder
    ├── chain_import.html       # Bulk PEM bundle import
    └── intermediate_form.html  # Add / edit individual chain certificate
```

> `/settings` redirects to `/profiles` for backwards-compatible bookmarks.

## Dependencies

| Package | Purpose |
|---|---|
| Flask | Web framework |
| Flask-SQLAlchemy | ORM / SQLite persistence |
| Flask-Login | Session-based authentication |
| cryptography | RSA key gen, CSR, x509 parsing, PKCS#12, DER |
| pyjks | Java KeyStore (JKS) creation |
| gunicorn | Production WSGI server |
| openssl (system) | P7B/PKCS#7 bundle generation |
