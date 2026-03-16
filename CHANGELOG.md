# Changelog

All notable changes to SSL Manager are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
SSL Manager uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-03-16

Initial production release.

### Certificate Management

- Generate RSA private keys (2048 or 4096-bit) and Certificate Signing Requests entirely server-side — private keys never leave the server
- Upload signed certificates returned from any external CA; expiry date extracted automatically
- Import external CSRs from network appliances, identity platforms (Cisco ISE, F5, Palo Alto), and any device that generates its own private key
- Renew / rekey existing certificates — preserves the active certificate until the new one is ready
- Certificate status tracking: **Active**, **Pending Signing**, **Expired**
- Expiry indicator with colour-coded urgency (>90 days / 30–90 days / <30 days / expired)

### Download Formats

- **Full Chain PEM** — private key + certificate + intermediates in a single file (HAProxy, CDN origins)
- **Component ZIP** — individual `private_key.pem`, `certificate.pem`, `chain.pem`, `fullchain.pem`, `certificate.csr` (nginx, Apache)
- **PKCS#12 / PFX** — password-protected bundle (Windows IIS, Azure App Service, F5 BIG-IP)
- **Java KeyStore (JKS)** — configurable store password and alias (Tomcat, Spring Boot, Jetty)
- **P7B** — certificate + chain without private key (Windows MMC, IIS)
- **DER** — binary certificate encoding (embedded devices, Java `keytool`)
- Import-only certificates (no stored private key) restricted to Certificate PEM and DER formats

### Certificate Chains

- Named, ordered collections of intermediate and root CA certificates bundled into every download format
- Add certificates individually or import a multi-certificate PEM bundle in one step
- Reorder entries with up/down controls; order persists immediately
- One chain can be shared across multiple certificates; chain assignment can be changed after creation

### Certificate Profiles

- Reusable templates for Distinguished Name (DN) subject fields (country, state, city, organisation, OU, email, key size)
- Multiple profiles supported — one profile carries the **default** badge and is pre-selected at certificate creation time
- Profile values are a snapshot at creation time; editing a profile does not affect existing certificates

### Internal Certificate Authority

- Create self-signed root CAs entirely within the application
- Sign any pending certificate directly from the CA Detail page or from the Certificate Detail page
- Configurable validity period per signing operation
- Download the CA certificate PEM for installation as a trusted root on client devices
- Multiple independent CAs supported (per-environment, per-team)

### User Interface

- Bootstrap 5.3 dark theme with a custom green-teal palette (DM Sans body font, DM Mono for code values)
- All create and edit interactions presented as modal dialogs — no full-page navigation for common operations
- Client-side search, sort, and pagination (10 / 20 / 50 / All rows) on the Certificates, Profiles, and Users tables
- Server-side search, sort, and pagination (10 / 20 / 50 / All rows) on the Audit Log
- Custom `badge-status` pill system for consistent status indicators across all pages

### User Management

- Role-based access control: **superadmin** (full access) and **user** (certificate and chain management)
- Add, edit, deactivate, and delete user accounts
- Password changes handled independently from account detail edits
- Superadmin protection: the application blocks any action that would leave zero active superadmin accounts
- First-run setup creates the initial superadmin account on first visit with no existing users

### Security

- Session-based authentication with configurable secret key
- CSRF protection on all state-changing forms
- Content Security Policy (CSP) headers on all responses
- Passwords stored as bcrypt hashes
- 403 / 404 error pages consistent with application styling

### Audit Log

- Every user action and automated system event recorded with timestamp, username, IP address, action, resource, result, and detail
- Searchable across all columns; sortable by timestamp, user, action, resource, and result
- Automated backup events logged as `system` user entries

### Backup

- Shell script (`backup.sh`) checkpoints the SQLite WAL and creates a compressed archive
- Docker Compose test overlay (`docker-compose.test.yml`) runs the backup service on a configurable schedule
- Backup retention configurable in days; older archives pruned automatically

### Infrastructure & Deployment

- Docker Compose configuration for local development and production
- Designer seed environment (`docker-compose.design.yml`) pre-populates the database with representative data covering every UI state
- AWS deployment via Terraform (`docs/admin/DEPLOY-AWS.md`)
- Azure deployment via Terraform (`docs/admin/DEPLOY-AZURE.md`)
- nginx reverse proxy configuration included

### Developer Tooling

- pytest suite covering crypto helpers, model properties, and route integration tests
- `dev_ca.py` script creates a two-tier local CA hierarchy (root → intermediate) for development signing
- In-memory SQLite test database with per-test truncation and re-seed

---

[1.0.0]: https://github.com/ideocentric/ssl-manager/releases/tag/v1.0.0
