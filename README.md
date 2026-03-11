# SSL Manager

A Flask-based web application for managing SSL certificate lifecycle — from RSA key and CSR generation through to signed certificate storage and multi-format bundle downloads.

## Features

- Configure organization-wide defaults (key size, country, state, org name, etc.)
- Generate RSA private keys (2048 or 4096-bit) and CSRs per domain
- Support for Subject Alternative Names (SANs)
- Manage intermediate and root certificate chain
- Upload signed certificates returned by your CA
- Color-coded expiration tracking (green → yellow → orange → red)
- Download certificates in multiple formats:
  - **Full Chain PEM** — private key + signed cert + intermediates in one file
  - **Component PEMs (ZIP)** — individual PEM files plus a combined fullchain
  - **PKCS#12 / PFX** — password-protected bundle (`.p12`)
  - **JKS** — Java KeyStore with configurable password and alias (`.jks`)
  - **P7B** — certificate chain bundle, no private key (`.p7b`, requires `openssl` in PATH)

---

## Certificate Workflow

1. **Settings** → configure org defaults (key size, country, org name, etc.)
2. **Chain Certificates** → add your intermediate and root CA certs, set their chain order
3. **New Certificate** → enter a domain (and optional SANs); the app generates an RSA key and CSR automatically
4. Download the `.csr` file and submit it to your Certificate Authority
5. Once the CA returns a signed cert, paste the PEM into the **Upload** section
6. All download formats become available immediately

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

`dev_ca.py` is a helper script for end-to-end UI testing. It creates a local root CA and signs CSRs so you can exercise every download format without a real Certificate Authority.

### One-time setup

```bash
# Create the local CA (writes dev-ca/ca.key and dev-ca/ca.crt)
python dev_ca.py init

# Add the CA cert to ssl-manager as a Chain Certificate
# Copy the printed PEM and paste it into Chain Certificates → Add
python dev_ca.py chain
```

### Per-certificate workflow

```bash
# 1. In ssl-manager: Certificates → New → fill in the domain → Save
# 2. On the certificate detail page, download the .csr file
# 3. Sign it with the local CA
python dev_ca.py sign ~/Downloads/example.com.csr

# 4. Copy the printed PEM and paste it into
#    Certificates → [your domain] → Upload Signed Certificate
# 5. All download formats are now available on the detail page
```

### Other commands

```bash
# Show CA subject, serial, and validity dates
python dev_ca.py info

# Sign with a custom validity period (default is 365 days)
python dev_ca.py sign example.com.csr --days 90

# Regenerate the CA (overwrites existing key and cert)
python dev_ca.py init --force
```

> **Note:** The `dev-ca/` directory is gitignored. Keep `dev-ca/ca.key` out of version control.

---

## Project Structure

```
ssl-manager/
├── app.py                  # Flask app — routes, models, crypto helpers
├── dev_ca.py               # Local dev CA for signing test CSRs
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── templates/
    ├── base.html           # Bootstrap 5 layout, navbar, flash messages
    ├── certificates.html   # Certificate list with expiry badges
    ├── cert_new.html       # New certificate form
    ├── cert_detail.html    # Detail, upload, and download page
    ├── settings.html       # Org defaults
    ├── intermediates.html  # Chain certificate management
    └── intermediate_form.html
```

## Dependencies

| Package | Purpose |
|---|---|
| Flask | Web framework |
| Flask-SQLAlchemy | ORM / SQLite persistence |
| cryptography | RSA key gen, CSR, x509 parsing, PKCS#12 |
| pyjks | Java KeyStore (JKS) creation |
| openssl (system) | P7B/PKCS#7 bundle generation |
