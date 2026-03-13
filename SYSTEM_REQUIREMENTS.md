# SSL Manager — System Requirements

## Table of Contents

1. [Operating System](#1-operating-system)
2. [Minimum Hardware](#2-minimum-hardware)
   - [Sizing Rationale](#21-sizing-rationale)
   - [When to Upsize](#22-when-to-upsize)
3. [System Packages](#3-system-packages)
   - [Installed by the Installer](#31-installed-by-the-installer)
   - [Recommended Hardening Packages](#32-recommended-hardening-packages)
4. [Python Packages](#4-python-packages)
5. [Network Requirements](#5-network-requirements)
6. [File System Layout](#6-file-system-layout)

---

## 1. Operating System

| Requirement | Value |
|---|---|
| **Supported OS** | Ubuntu 24.04 LTS (Noble Numbat) — recommended |
| **Also supported** | Ubuntu 22.04 LTS (Jammy Jellyfish), Ubuntu 20.04 LTS (Focal Fossa) |
| **Architecture** | x86_64 (amd64) |
| **Install type** | Server (minimal) or standard server image |

Ubuntu 24.04 LTS is the recommended target. The installer (`install.sh`) detects the OS and enforces Ubuntu 20.04 or later.

---

## 2. Minimum Hardware

The following sizing targets installations with up to **1,000 certificate records** and **2–3 concurrent users** accessing via SSH tunnel.

| Resource | Minimum | Recommended |
|---|---|---|
| **CPU** | 1 vCPU | 2 vCPU |
| **RAM** | 1 GB | 2 GB |
| **Disk** | 10 GB SSD | 20 GB SSD |
| **Network** | Any | Any |

### 2.1 Sizing Rationale

The table below shows the expected steady-state memory footprint of all running components:

| Component | Memory | Notes |
|---|---|---|
| Ubuntu 24.04 minimal OS | 200–300 MB | systemd, journald, base services |
| nginx (2 workers) | 10–20 MB | Loopback reverse proxy + static file serving |
| gunicorn (2 workers) | 100–160 MB | Each Python worker loads Flask, SQLAlchemy, and the cryptography library (~50–80 MB each) |
| SQLite | 5–10 MB | Page cache; under 1,000 records the database remains small |
| fail2ban | 30–50 MB | Python-based log watcher; resident in memory at all times |
| sshd (2–3 active tunnels) | 15–30 MB | ~5–10 MB per active SSH tunnel session |
| **Total steady-state** | **~360–570 MB** | |

**1 GB RAM** runs all components comfortably with 40–60% headroom under normal load.

**CPU** is nearly idle between requests. The two operations that briefly spike CPU are:

- **RSA key generation** — RSA-2048 takes 50–200 ms per key; RSA-4096 takes 500 ms–2 s on a single vCPU. Each generation occupies one gunicorn worker for its duration.
- **Certificate format export** (PKCS#12, JKS, P7B) — subprocess calls to `openssl` and `keytool`, each completing in under 1 second.

With 2 gunicorn workers, one worker can generate a key while another concurrently serves a page request.

**Disk** usage for 1,000 certificates:

| Item | Size |
|---|---|
| Ubuntu OS + installed packages | 3–5 GB |
| Python virtual environment + app files | 150–200 MB |
| SQLite database (1,000 certs × ~8 KB PEM data) | 20–50 MB |
| 7-day backup retention (PEM text compresses ~75% with gzip) | 20–50 MB |
| nginx + gunicorn logs (1 year, light usage) | 100–300 MB |
| **Total** | **~4–6 GB** |

A **10 GB** disk is sufficient; **20 GB** provides comfortable headroom for log accumulation and OS updates.

### 2.2 When to Upsize

| Scenario | Recommendation |
|---|---|
| fail2ban configured with aggressive regex scanning against large nginx log files | 2 GB RAM |
| Server runs other services alongside SSL Manager | 2 GB RAM |
| Users frequently generate RSA-4096 keys concurrently (3 simultaneous users can briefly queue behind 2 workers) | 2 vCPU |
| Backup retention extended significantly beyond 7 days | Larger disk |
| Certificate records exceed ~10,000 | Review disk and RAM; SQLite remains performant well past this point |

**Representative instance tiers** matching the minimum and recommended specifications:

| Provider | Tier | Spec | Est. Cost | Notes |
|---|---|---|---|---|
| Hetzner | CX11 | 2 vCPU / 2 GB / 20 GB SSD | ~€4/month | Best value; storage included |
| DigitalOcean | Basic Droplet | 1 vCPU / 1 GB / 25 GB SSD | ~$6/month | Storage included |
| Linode/Akamai | Nanode | 1 vCPU / 1 GB / 25 GB SSD | ~$5/month | Storage included |
| Vultr | Cloud Compute | 1 vCPU / 1 GB / 25 GB SSD | ~$6/month | Storage included |
| AWS | t4g.micro (minimum) | 2 vCPU / 1 GB | ~$6/month | Add ~$1.60/month for 20 GB gp3 EBS; ARM (Graviton2); Ubuntu 24.04 supported |
| AWS | t4g.small (recommended) | 2 vCPU / 2 GB | ~$12/month | Add ~$1.60/month for 20 GB gp3 EBS; ARM (Graviton2); eligible for Savings Plans |
| Azure | B1s (minimum) | 1 vCPU / 1 GB | ~$8/month | 4 GB managed OS disk included; Standard HDD additional |
| Azure | B1ms (recommended) | 1 vCPU / 2 GB | ~$15/month | 4 GB managed OS disk included; add Standard SSD for data |

> **AWS pricing notes:** EC2 compute and EBS storage are billed separately. A 20 GB gp3 EBS volume adds approximately $1.60/month. New AWS accounts receive 750 hours/month of t2.micro or t3.micro (x86) On-Demand usage free for 12 months under the Free Tier. Prices shown are On-Demand Linux rates for us-east-1; Reserved Instances (1-year, no upfront) reduce compute cost by approximately 30–40%.
>
> **Azure pricing notes:** Azure VM pricing includes a small managed OS disk but application data and backups should use a separate managed disk. Prices shown are Pay-As-You-Go Linux rates for East US. Azure Reserved VM Instances (1-year) reduce cost by approximately 30–40%. The B-series (burstable) is appropriate for this workload as CPU usage is low between certificate operations.
>
> **All prices are estimates** based on public list pricing at time of writing and will vary by region, commitment term, and provider promotions. Verify current pricing on each provider's pricing page before provisioning.

Hetzner CX11 offers the best value for this workload — 2 vCPU and 2 GB RAM with storage included at the lowest monthly cost. AWS and Azure become more competitive when an organisation already has existing cloud credits, reserved capacity, or consolidated billing agreements.

---

## 3. System Packages

### 3.1 Installed by the Installer

The packages below are **not present in a default Ubuntu 24.04 LTS server install** and are installed automatically by `install.sh`:

| Package | Version | Purpose |
|---|---|---|
| `nginx` | Latest LTS | Reverse proxy; listens on `127.0.0.1` only; serves static files directly and forwards dynamic requests to gunicorn via Unix socket |
| `python3-pip` | Latest | pip package manager used to install the Python virtual environment dependencies |
| `python3-venv` | Latest | Creates the isolated Python virtual environment at `/opt/ssl-manager/venv` |
| `python3-dev` | Latest | C header files required to compile the `cryptography` package's native extensions |
| `gcc` | Latest | C compiler required to build the `cryptography` package during `pip install` |
| `sqlite3` | Latest | SQLite CLI tool; used by `backup.sh` for WAL checkpointing, the `.backup` command, and post-backup integrity checks |

> **Note:** `python3` and `openssl` are present in a default Ubuntu 24.04 LTS server install and are listed here for completeness only — the installer includes them in the `apt-get install` call as an explicit dependency declaration.

| Package | Included in Ubuntu 24.04 default | Role in SSL Manager |
|---|---|---|
| `python3` | Yes (3.12) | Runtime for the Flask application |
| `openssl` | Yes | CSR generation, P7B export, certificate inspection |

### 3.2 Recommended Hardening Packages

The following packages are **not installed by `install.sh`** because they affect system-wide services and require manual review before enabling. They are documented in the README under **Host hardening**.

| Package | Ubuntu 24.04 Default | Purpose |
|---|---|---|
| `ufw` | Included, inactive | Host firewall; restrict inbound traffic to SSH (22) only — all other ports blocked |
| `fail2ban` | Not included | Monitors nginx and sshd logs; automatically bans IPs that repeatedly fail authentication |
| `unattended-upgrades` | Included, inactive | Automatically installs security updates; configured to apply patches without manual intervention |

**Optional — JKS export format:**

| Package | Ubuntu 24.04 Default | Purpose |
|---|---|---|
| `default-jdk-headless` | Not included | Provides `keytool`, which is required to generate Java KeyStore (`.jks`) files. If not installed, the JKS download button returns an error. All other export formats continue to work. |

Install with:
```bash
sudo apt-get install -y default-jdk-headless
```

---

## 4. Python Packages

All Python dependencies are installed into an isolated virtual environment at `/opt/ssl-manager/venv` and are **not installed system-wide**. The `pip install` step runs during `install.sh` and again during `--upgrade`.

| Package | Version | Purpose |
|---|---|---|
| `Flask` | 3.1.3 | Web framework — routing, templating, session management |
| `Flask-SQLAlchemy` | 3.1.1 | SQLAlchemy ORM integration for Flask; manages the SQLite connection pool |
| `Flask-Login` | 0.6.3 | User session management, login/logout, `current_user` context, `@login_required` decorator |
| `cryptography` | 46.0.5 | RSA key generation, CSR construction, certificate parsing, PKCS#12 export; uses OpenSSL bindings |
| `pyjks` | 20.0.0 | Java KeyStore (JKS) file generation for the `.jks` download format |
| `gunicorn` | 23.0.0 | Production WSGI server; runs the Flask app as multiple worker processes behind the nginx Unix socket |

---

## 5. Network Requirements

SSL Manager is designed to be **unreachable from the network** by default. No inbound port other than SSH needs to be open.

| Interface | Port | Protocol | Direction | Purpose |
|---|---|---|---|---|
| All interfaces | 22 | TCP | Inbound | SSH — required for tunnel access and server administration |
| `127.0.0.1` | 5001 (configurable) | TCP | Loopback only | nginx listener; not exposed to the network |
| `/run/ssl-manager/ssl-manager.sock` | — | Unix socket | Internal | nginx → gunicorn communication |

**Remote access** is provided exclusively via SSH port forwarding:

```bash
ssh -L 5001:127.0.0.1:5001 user@your-server
```

No HTTP/HTTPS ports are opened to the network. A firewall rule allowing only port 22 inbound is sufficient.

---

## 6. File System Layout

All paths created by `install.sh`:

| Path | Owner | Mode | Purpose |
|---|---|---|---|
| `/opt/ssl-manager/` | `root:ssl-manager` | `750` | Application code, templates, static files, Python venv |
| `/opt/ssl-manager/venv/` | `root:ssl-manager` | `750` | Isolated Python virtual environment |
| `/opt/ssl-manager/backup.sh` | `root:ssl-manager` | `750` | Database backup script |
| `/var/lib/ssl-manager/` | `ssl-manager:ssl-manager` | `700` | SQLite database — accessible only by the service user |
| `/var/lib/ssl-manager/ssl_manager.db` | `ssl-manager:ssl-manager` | `600` | Live SQLite database (WAL mode) |
| `/var/log/ssl-manager/` | `ssl-manager:ssl-manager` | `750` | gunicorn access and error logs |
| `/var/backups/ssl-manager/` | `root:root` | `700` | Compressed database backups (7-day retention by default) |
| `/etc/ssl-manager/` | `root:ssl-manager` | `750` | Application configuration directory |
| `/etc/ssl-manager/env` | `root:ssl-manager` | `640` | Environment file — `SECRET_KEY`, `DATABASE_URL` |
| `/run/ssl-manager/ssl-manager.sock` | `ssl-manager:ssl-manager` | `660` | Unix socket between nginx and gunicorn (recreated at each service start) |
| `/etc/systemd/system/ssl-manager.service` | `root` | `644` | gunicorn systemd service unit |
| `/etc/systemd/system/ssl-manager-backup.service` | `root` | `644` | Backup job systemd unit (Type=oneshot) |
| `/etc/systemd/system/ssl-manager-backup.timer` | `root` | `644` | Backup timer unit (daily at 02:00, Persistent=true) |
| `/etc/nginx/sites-available/ssl-manager` | `root` | `644` | nginx reverse proxy configuration |
| `/etc/nginx/conf.d/ssl-manager-ratelimit.conf` | `root` | `644` | nginx rate-limit zone definition (10 req/s per IP) |
