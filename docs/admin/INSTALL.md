<!--
  This guide is built into docs/user/../admin/../ (relative path kept for cross-links).
  PDF artifact: built by docs/generate_pdf.py as part of SSL_Manager_Admin_Guide.pdf.
  See docs/generate_pdf.py for the full procedure.
-->
# SSL Manager — Installation Guide

## Deployment Options

| Method | Best for |
|---|---|
| [Bare Metal / Ubuntu Server](#bare-metal--ubuntu-server) | Physical hardware, on-premises VMs, self-managed VPS |
| [RHEL / Rocky Linux / AlmaLinux](#rhel--rocky-linux--almalinux) | Red Hat-based enterprise or on-premises environments |
| [AWS (EC2)](#aws-ec2) | Existing AWS accounts, consolidated billing, Graviton cost savings |
| [Azure (VM)](#azure-vm) | Existing Azure accounts, enterprise agreements, Azure credits |
| [Docker (local development)](#docker-local-development) | Development, testing, and feature validation — not for production |

Cloud deployments (AWS and Azure) require Terraform **or** [OpenTofu](https://opentofu.org/) (its open-source fork — the configurations work with either) and the relevant cloud CLI. See [Cloud Deployment Prerequisites](#cloud-deployment-prerequisites) for installation instructions covering macOS, Linux, and Windows — including [SSH key generation](#ssh-key-pair) for all platforms and [server-side user management](#managing-ssh-users-on-the-server).

All production methods share the same runtime stack: nginx → gunicorn → Flask → SQLite, with access via SSH tunnel only. See [REQUIREMENTS.md](REQUIREMENTS.md) for hardware sizing guidance.

---

## Bare Metal / Ubuntu Server

Use this method for physical hardware, on-premises virtual machines, or any VPS where you provision the OS yourself.

### Requirements

- Ubuntu 26.04 LTS, 24.04 LTS (recommended), 22.04 LTS, or 20.04 LTS
- Root or `sudo` access
- Outbound internet access (for `apt-get` and `pip`)
- Minimum: 1 vCPU, 1 GB RAM, 10 GB disk
- Recommended: 1–2 vCPU, 2 GB RAM, 20 GB disk

> **Python version:** The installer uses the distribution's default Python 3 —
> from 3.8 on 20.04 through **3.14 on 26.04** — and all dependencies install as
> prebuilt wheels, so no compiler toolchain is exercised at install time.
> `requirements.txt` selects a compatible `gunicorn` per interpreter via
> environment markers (23.0.0 on Python < 3.10, 26.0.0 on ≥ 3.10), so a single
> file spans every supported release (including RHEL 9's Python 3.9). All
> combinations are validated by the test harness — see
> [Pre-Deployment Testing](#pre-deployment-testing-deploytest).

### 1. Get the code

```bash
git clone https://github.com/your-org/ssl-manager.git
cd ssl-manager
```

Or transfer the files to the server:

```bash
scp -r ssl-manager/ user@your-server:~/ssl-manager
```

### 2. Run the installer

```bash
sudo bash install.sh
```

The installer prompts for three values:

| Prompt | Default | Notes |
|---|---|---|
| nginx listen port | `5001` | nginx binds to `127.0.0.1:<port>` — loopback only, not reachable from the network |
| Gunicorn worker processes | `2` | Increase for higher concurrent load; 2 is sufficient for 2–3 users |
| Secret key | auto-generated | 256-bit random hex used to sign Flask sessions; leave blank to auto-generate |

The installer:

1. Installs system packages (`nginx`, `python3-pip`, `python3-venv`, `gcc`, `python3-dev`)
2. Creates the `ssl-manager` service account (no login shell, no home directory)
3. Creates all directories with enforced ownership and permissions
4. Copies application files to `/opt/ssl-manager/`
5. Creates a Python virtual environment and installs all dependencies
6. Writes the secret key and database URL to `/etc/ssl-manager/env` (on a re-run, an existing `SECRET_KEY` is preserved — never regenerated — because it encrypts stored SMTP/OAuth secrets)
7. Installs and starts the `ssl-manager` systemd service
8. Configures nginx as a reverse proxy with rate limiting
9. Installs and enables the `ssl-manager-backup.timer` for daily database backups

> **sqlite3:** The backup script requires the `sqlite3` CLI. Ubuntu 24.04 minimal server may not include it. If the first scheduled backup fails, install it with `sudo apt-get install -y sqlite3`.

> **Re-running the installer:** Running `sudo bash install.sh` again on a host that already has SSL Manager auto-detects the existing installation and switches to **upgrade mode** — it skips the prompts and preserves your configuration, secret key, and database. See [Upgrading](#upgrading). Use `--reinstall` to force the interactive installer instead.

### 3. Verify the service is running

```bash
sudo systemctl status ssl-manager
sudo systemctl status ssl-manager-backup.timer
```

### 4. Connect via SSH tunnel

From your local machine:

```bash
ssh -L 5001:127.0.0.1:5001 user@your-server
```

Open `http://localhost:5001` in your browser. Complete the first-run setup to create the superadmin account.

For a persistent tunnel, add to `~/.ssh/config`:

```
Host ssl-manager
    HostName your-server
    User your-user
    LocalForward 5001 127.0.0.1:5001
    ServerAliveInterval 60
```

Then `ssh ssl-manager` is all that is needed.

### 5. Recommended post-install hardening

The following steps are not automated because they affect system-wide services. Review each before applying.

**Firewall (UFW):**

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable
sudo ufw status verbose
```

**fail2ban:**

```bash
sudo apt-get install -y fail2ban
sudo systemctl enable --now fail2ban
```

Create `/etc/fail2ban/jail.d/ssl-manager.conf`:

```ini
[sshd]
enabled  = true
port     = ssh
maxretry = 5
bantime  = 1h
findtime = 10m

[nginx-limit-req]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/ssl-manager-error.log
maxretry = 10
bantime  = 1h
```

```bash
sudo systemctl restart fail2ban
```

**Unattended security updates:**

```bash
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

### Service management

```bash
# Status and logs
sudo systemctl status ssl-manager
sudo journalctl -u ssl-manager -f
sudo tail -f /var/log/ssl-manager/error.log

# Restart after config change
sudo nano /etc/ssl-manager/env
sudo systemctl restart ssl-manager

# Backup management
sudo systemctl status ssl-manager-backup.timer
sudo systemctl list-timers ssl-manager-backup.timer
sudo bash /opt/ssl-manager/backup.sh   # run a backup immediately
```

### Upgrading

After pulling or transferring updated code:

```bash
sudo bash install.sh --upgrade
```

Re-running the installer with no flag does the same thing — it auto-detects the existing install and upgrades.

The upgrade backs up the database, then refreshes the application files, Python dependencies, systemd unit, and nginx config from the new code. Your `SECRET_KEY`, database, and existing port/worker settings are **preserved** (the port and worker count are re-derived from the current nginx/systemd config, so there are no prompts). Schema migrations run automatically on the next service start — no manual SQL steps are required. See [Upgrading from Previous Versions](#upgrading-from-previous-versions) for version-specific notes.

### Uninstalling

```bash
sudo bash install.sh --uninstall
```

Removes the service, application files, nginx config, and optionally the database and service user. The database at `/var/lib/ssl-manager/` is not deleted unless explicitly confirmed.

---

## RHEL / Rocky Linux / AlmaLinux

Use this method for RHEL 8/9, Rocky Linux 8/9, AlmaLinux 8/9, or CentOS Stream 9. The RHEL installer (`install-rhel.sh`) handles SELinux configuration and `dnf`-based package management automatically.

### Requirements

- RHEL 9 / Rocky Linux 9 / AlmaLinux 9 (recommended), or 8-series equivalents
- Root or `sudo` access
- Outbound internet access (for `dnf` and `pip`)
- Minimum: 1 vCPU, 1 GB RAM, 10 GB disk
- Recommended: 1–2 vCPU, 2 GB RAM, 20 GB disk
- **Registered RHEL only:** An active Red Hat subscription with the AppStream and BaseOS repositories enabled

### 1. Get the code

```bash
git clone https://github.com/your-org/ssl-manager.git
cd ssl-manager
```

Or transfer the files to the server:

```bash
scp -r ssl-manager/ user@your-server:~/ssl-manager
```

### 2. Run the installer

```bash
sudo bash install-rhel.sh
```

The installer prompts for the same three values as the Ubuntu installer (port, worker count, secret key).

The installer additionally:

1. Enables EPEL (on Rocky/AlmaLinux/CentOS Stream; skipped on registered RHEL)
2. Installs `policycoreutils-python-utils` for SELinux management
3. Configures SELinux to allow nginx to communicate with the gunicorn Unix socket:
   - Sets `httpd_var_run_t` file context on the socket directory
   - Enables `httpd_can_network_connect` boolean
   - Adds the chosen port to the `http_port_t` SELinux port type
4. Writes the nginx config to `/etc/nginx/conf.d/` (RHEL uses `conf.d`; there is no `sites-available`/`sites-enabled`)
5. Uses `nginx` as the nginx user (not `www-data` as on Ubuntu)

> **SELinux note:** If you later change the nginx port after installation, re-run the SELinux port permission manually:
> ```bash
> sudo semanage port -a -t http_port_t -p tcp <new-port>
> sudo systemctl restart nginx
> ```

### 3. Verify the service is running

```bash
sudo systemctl status ssl-manager
sudo systemctl status ssl-manager-backup.timer
```

### 4. Connect via SSH tunnel

Identical to the Ubuntu procedure — from your local machine:

```bash
ssh -L 5001:127.0.0.1:5001 user@your-server
```

Open `http://localhost:5001` and complete the first-run setup.

### 5. Recommended post-install hardening

**Firewall (firewalld):**

```bash
# Allow SSH only — all other inbound ports are blocked by default on RHEL
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --remove-service=cockpit   # optional
sudo firewall-cmd --reload
sudo firewall-cmd --list-all
```

**fail2ban:**

```bash
sudo dnf install -y fail2ban
sudo systemctl enable --now fail2ban
```

Create `/etc/fail2ban/jail.d/ssl-manager.conf` with the same content as the Ubuntu example above, then:

```bash
sudo systemctl restart fail2ban
```

**Automatic security updates (dnf-automatic):**

```bash
sudo dnf install -y dnf-automatic
sudo sed -i 's/^apply_updates = .*/apply_updates = yes/' /etc/dnf/automatic.conf
sudo systemctl enable --now dnf-automatic.timer
```

### Service management

Identical commands to Ubuntu — `systemctl status ssl-manager`, `journalctl -u ssl-manager`, etc.

### Upgrading

```bash
sudo bash install-rhel.sh --upgrade
```

As on Ubuntu, re-running `install-rhel.sh` with no flag auto-detects the existing install and upgrades, preserving your `SECRET_KEY`, database, and port/worker settings (and re-applying the SELinux and nginx configuration). Use `--reinstall` to force the interactive installer. See [Upgrading from Previous Versions](#upgrading-from-previous-versions) for version-specific notes.

### Uninstalling

```bash
sudo bash install-rhel.sh --uninstall
```

---

## Configure Email (Optional)

SSL Manager can send password reset emails via SMTP. This step is optional — the application functions fully without email; only the password reset flow requires it.

### Supported authentication methods

| Method | When to use |
|---|---|
| **Standard SMTP** | Any mail provider reached over SMTP — with username/password (Gmail app password, SendGrid, Amazon SES, Mailgun, your own server) **or** unauthenticated against an internal relay (Authentication Method *None*). STARTTLS or implicit SSL can be enabled on any port. |
| **Microsoft 365 OAuth** | Microsoft 365 / Exchange Online accounts where modern authentication is required |
| **Google OAuth** | Google Workspace accounts using OAuth 2.0 |

### Configure via the web UI

1. Log in as a **superadmin** user.
2. Navigate to **Settings → Email** (`/settings/smtp`).
3. Fill in the fields for your provider:

**Standard SMTP fields:**

| Field | Example |
|---|---|
| SMTP Host | `smtp.sendgrid.net` |
| Port | `587` (STARTTLS) or `465` (SSL) |
| Username | Your SMTP login or API key name |
| Password | Your SMTP password or API key |
| From address | `noreply@yourdomain.com` |
| From name | `SSL Manager` |
| Use TLS / Use SSL | Match your provider's requirement |

> **Unauthenticated, encrypted relay (e.g. port 25 + STARTTLS):** For an internal relay that requires no login but supports TLS, set **Authentication Method** to **None**, set **Port** to your relay's port (commonly `25`), enable **STARTTLS**, and leave Username/Password blank. STARTTLS is not tied to a specific port — it upgrades the connection to TLS on whatever port you configure.

**Microsoft 365 OAuth:**

1. Register an application in [Azure Active Directory](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps).
2. Add the redirect URI: `http://localhost:5001/settings/smtp/oauth/microsoft/callback`
3. Grant the `Mail.Send` permission (delegated).
4. In the SSL Manager SMTP settings, select **Microsoft 365 OAuth**, enter the **Client ID**, **Client Secret**, and **Tenant ID**, then click **Connect** to complete the OAuth flow.

**Google OAuth:**

1. Create an OAuth 2.0 Client ID in [Google Cloud Console](https://console.cloud.google.com/).
2. Add the redirect URI: `http://localhost:5001/settings/smtp/oauth/google/callback`
3. Enable the **Gmail API** in your project.
4. In the SSL Manager SMTP settings, select **Google OAuth**, enter the **Client ID** and **Client Secret**, then click **Connect**.

### Test email delivery

After saving your settings, click **Send Test Email** on the SMTP settings page. A test message will be sent to your own account (the logged-in superadmin's email address). Check the audit log if the test fails — delivery errors are recorded there.

### Network requirements

Ensure outbound TCP is permitted on the port your provider uses:

```bash
# Ubuntu (UFW)
sudo ufw allow out 587/tcp   # STARTTLS
sudo ufw allow out 465/tcp   # SSL (if used instead)

# RHEL (firewalld)
sudo firewall-cmd --permanent --add-port=587/tcp
sudo firewall-cmd --reload
```

### Recovering email after a SECRET_KEY change

The SMTP password and all OAuth tokens are encrypted with a key derived from
`SECRET_KEY`. If `SECRET_KEY` is ever changed — for example, an older installer
re-run regenerated it instead of preserving the existing key — those stored
secrets can no longer be decrypted and email fails **silently**: the
configuration still appears enabled, but authentication uses an empty secret.

`remediate_secret_key.py` detects and cleans up this situation. It is read-only
by default:

```bash
# Report which stored secrets can no longer be decrypted (no changes):
sudo -u ssl-manager /opt/ssl-manager/venv/bin/python \
    /opt/ssl-manager/remediate_secret_key.py

# Clear the dead secrets and disable SMTP, then re-enter them in the web UI
# (Settings → SMTP) and re-enable:
sudo -u ssl-manager /opt/ssl-manager/venv/bin/python \
    /opt/ssl-manager/remediate_secret_key.py --apply

# If you still have the PREVIOUS key, recover the secrets instead of clearing
# them (decrypt with the old key, re-encrypt under the current one):
sudo -u ssl-manager /opt/ssl-manager/venv/bin/python \
    /opt/ssl-manager/remediate_secret_key.py --old-secret-key <previous-key> --apply
```

> Certificate and CA private keys are **not** affected — they are stored without
> `SECRET_KEY`-based encryption and survive a key change. Note that `backup.sh`
> backs up the database only, not `/etc/ssl-manager/env`, so a rotated key is not
> recoverable from a backup; keep a copy of `SECRET_KEY` if you need portability.

---

## Cloud Deployment Prerequisites

The AWS and Azure deployments both use Terraform — or, equivalently, [OpenTofu](https://opentofu.org/), its open-source fork. Install **one** of the two (plus the relevant cloud CLI) on your local machine before proceeding. The SSL Manager configurations in `deploy/aws/` and `deploy/azure/` are identical for both tools.

### Terraform

**macOS**
```bash
brew tap hashicorp/tap
brew install hashicorp/tap/terraform
terraform version   # confirm install
```

**Linux (Ubuntu / Debian)**
```bash
sudo apt-get install -y gnupg software-properties-common
wget -O- https://apt.releases.hashicorp.com/gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
  https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt-get update && sudo apt-get install -y terraform
terraform version   # confirm install
```

**Linux (RHEL / Fedora / Amazon Linux)**
```bash
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
sudo yum install -y terraform
terraform version   # confirm install
```

**Windows**

Option A — winget (Windows 10/11, recommended):
```powershell
winget install HashiCorp.Terraform
terraform version   # confirm install
```

Option B — Chocolatey:
```powershell
choco install terraform
terraform version   # confirm install
```

Option C — Manual: download the `.zip` from [developer.hashicorp.com/terraform/downloads](https://developer.hashicorp.com/terraform/downloads), extract `terraform.exe`, and add its folder to your `PATH`.

### OpenTofu (drop-in alternative to Terraform)

[OpenTofu](https://opentofu.org/) is an open-source, Linux Foundation fork of Terraform. The SSL Manager configurations work with it unchanged — same HCL, same `terraform.tfvars`, same state files. Install OpenTofu **instead of** Terraform if you prefer it; everywhere the deployment guides say `terraform <command>`, substitute `tofu <command>` (e.g. `tofu init`, `tofu plan`, `tofu apply`, `tofu destroy`). You do not need both tools.

**macOS**
```bash
brew install opentofu
tofu --version   # confirm install
```

**Linux (Debian / Ubuntu / RHEL / Fedora)**
```bash
# Official installer — auto-detects the distribution and configures the package repo
curl --proto '=https' --tlsv1.2 -fsSL https://get.opentofu.org/install-opentofu.sh -o install-opentofu.sh
chmod +x install-opentofu.sh
./install-opentofu.sh --install-method deb      # use 'rpm' on RHEL / Fedora
rm -f install-opentofu.sh
tofu --version   # confirm install
```

**Windows**

Option A — winget (Windows 10/11, recommended):
```powershell
winget install --exact --id=OpenTofu.Tofu
tofu --version   # confirm install
```

Option B — Chocolatey:
```powershell
choco install opentofu
tofu --version   # confirm install
```

---

### AWS CLI (required for AWS deployments only)

**macOS**
```bash
brew install awscli
aws --version   # confirm install
```

**Linux**
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o awscliv2.zip
unzip awscliv2.zip
sudo ./aws/install
aws --version   # confirm install
```

For ARM (Graviton) systems replace `x86_64` with `aarch64` in the URL.

**Windows**

Option A — winget:
```powershell
winget install Amazon.AWSCLI
aws --version   # confirm install
```

Option B — MSI installer: download and run [AWSCLIV2.msi](https://awscli.amazonaws.com/AWSCLIV2.msi) from AWS, then confirm with `aws --version` in a new terminal.

---

### Azure CLI (required for Azure deployments only)

**macOS**
```bash
brew install azure-cli
az version   # confirm install
```

**Linux (Ubuntu / Debian)**
```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az version   # confirm install
```

**Linux (RHEL / Fedora / Amazon Linux)**
```bash
sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
sudo dnf install -y azure-cli
az version   # confirm install
```

**Windows**

Option A — winget:
```powershell
winget install Microsoft.AzureCLI
az version   # confirm install
```

Option B — MSI installer: download and run the installer from [aka.ms/installazurecliwindows](https://aka.ms/installazurecliwindows), then confirm with `az version` in a new terminal.

---

### SSH key pair

Every user who needs to connect to the server requires an SSH key pair. Generate one on the machine you will connect from, then provide the public key to the server administrator (or paste it into `terraform.tfvars` for Terraform deployments).

#### macOS

OpenSSH is included with macOS. Open **Terminal** and check whether a key already exists:

```bash
ls -la ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.pub 2>/dev/null
```

**If a key already exists** and you are comfortable reusing it for SSL Manager, skip to the "View / copy" step below.

**If no key exists**, or you prefer a dedicated key for this server, generate one:

```bash
# Default name — use if you have no existing key
ssh-keygen -t ed25519 -C "your-name-ssl-manager"

# Named key — use if you want to keep this separate from existing keys
ssh-keygen -t ed25519 -C "your-name-ssl-manager" -f ~/.ssh/id_ed25519_ssl_manager
```

Set a passphrase when prompted — this protects the private key if your machine is compromised.

```bash
# View the public key (share this — never the private key)
cat ~/.ssh/id_ed25519.pub           # default key
cat ~/.ssh/id_ed25519_ssl_manager.pub  # named key

# Copy the public key to the clipboard
pbcopy < ~/.ssh/id_ed25519.pub
pbcopy < ~/.ssh/id_ed25519_ssl_manager.pub  # named key
```

Keys are stored in `~/.ssh/`:

| File | Description |
|---|---|
| `~/.ssh/id_ed25519` | Private key — keep this secret, never share it |
| `~/.ssh/id_ed25519.pub` | Public key — safe to share; goes on the server |

**Connecting with a named key** — use the `-i` flag to specify which private key to use:

```bash
ssh -i ~/.ssh/id_ed25519_ssl_manager user@<server-ip>

# With tunnel
ssh -i ~/.ssh/id_ed25519_ssl_manager -L 5001:127.0.0.1:5001 user@<server-ip>
```

To avoid typing `-i` every time, add an entry to `~/.ssh/config`:

```
Host ssl-manager
    HostName <server-ip>
    User <username>
    IdentityFile ~/.ssh/id_ed25519_ssl_manager
    LocalForward 5001 127.0.0.1:5001
    ServerAliveInterval 60
```

Then connect with just `ssh ssl-manager`.

#### Linux

OpenSSH is included on most distributions. If it is missing:

```bash
sudo apt-get install -y openssh-client   # Ubuntu / Debian
sudo dnf install -y openssh             # Fedora / RHEL
```

Check whether a key already exists:

```bash
ls -la ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.pub 2>/dev/null
```

**If no key exists**, or you want a dedicated key:

```bash
# Default name
ssh-keygen -t ed25519 -C "your-name-ssl-manager"

# Named key — keeps this separate from existing keys
ssh-keygen -t ed25519 -C "your-name-ssl-manager" -f ~/.ssh/id_ed25519_ssl_manager
```

Set a passphrase when prompted.

```bash
# View the public key
cat ~/.ssh/id_ed25519.pub
cat ~/.ssh/id_ed25519_ssl_manager.pub   # named key

# Copy to clipboard (install xclip first if needed)
xclip -selection clipboard < ~/.ssh/id_ed25519.pub          # X11
wl-copy < ~/.ssh/id_ed25519.pub                             # Wayland
```

**Connecting with a named key:**

```bash
ssh -i ~/.ssh/id_ed25519_ssl_manager user@<server-ip>

# With tunnel
ssh -i ~/.ssh/id_ed25519_ssl_manager -L 5001:127.0.0.1:5001 user@<server-ip>
```

Or add to `~/.ssh/config`:

```
Host ssl-manager
    HostName <server-ip>
    User <username>
    IdentityFile ~/.ssh/id_ed25519_ssl_manager
    LocalForward 5001 127.0.0.1:5001
    ServerAliveInterval 60
```

#### Windows

**Option A — OpenSSH (recommended, built into Windows 10/11)**

Open **PowerShell** or **Windows Terminal** and check whether a key already exists:

```powershell
Test-Path $env:USERPROFILE\.ssh\id_ed25519
```

A result of `True` means a key exists. You can reuse it, or generate a named key to keep SSL Manager separate.

**If no key exists**, or you want a dedicated key:

```powershell
# Default name
ssh-keygen -t ed25519 -C "your-name-ssl-manager"

# Named key
ssh-keygen -t ed25519 -C "your-name-ssl-manager" -f "$env:USERPROFILE\.ssh\id_ed25519_ssl_manager"
```

Set a passphrase when prompted. Keys are written to `C:\Users\<you>\.ssh\`.

```powershell
# View the public key
type $env:USERPROFILE\.ssh\id_ed25519.pub
type $env:USERPROFILE\.ssh\id_ed25519_ssl_manager.pub   # named key

# Copy the public key to the clipboard
Get-Content $env:USERPROFILE\.ssh\id_ed25519.pub | Set-Clipboard
```

**Connecting with a named key:**

```powershell
ssh -i $env:USERPROFILE\.ssh\id_ed25519_ssl_manager user@<server-ip>
ssh -i $env:USERPROFILE\.ssh\id_ed25519_ssl_manager -L 5001:127.0.0.1:5001 user@<server-ip>
```

Or add to `C:\Users\<you>\.ssh\config`:

```
Host ssl-manager
    HostName <server-ip>
    User <username>
    IdentityFile C:\Users\<you>\.ssh\id_ed25519_ssl_manager
    LocalForward 5001 127.0.0.1:5001
    ServerAliveInterval 60
```

**Option B — Git Bash**

If you have [Git for Windows](https://git-scm.com/download/win) installed, open **Git Bash** and follow the Linux instructions above. Keys are stored in `~/.ssh/` within Git Bash, which maps to `C:\Users\<you>\.ssh\`.

**Option C — PuTTYgen (PuTTY users)**

If you use PuTTY for SSH sessions:

1. Open **PuTTYgen** (included with PuTTY)
2. Check whether an existing `.ppk` file exists — if so, load and reuse it via **File → Load private key**
3. To create a new key: select **EdDSA** and click **Generate**, then move the mouse to generate entropy
4. Set a **Key passphrase**
5. Click **Save private key** — save the `.ppk` file (e.g. `ssl-manager.ppk`)
6. Copy the text in the **Public key for pasting into OpenSSH authorized_keys** box

To specify the key in a PuTTY session: go to **Connection → SSH → Auth → Credentials** and set the **Private key file** to your `.ppk`.

> The `.ppk` format is PuTTY-specific. When asked for your public key, provide the text from the "Public key for pasting into OpenSSH" box, not the `.ppk` file itself.

### Find your current public IP

You will need your public IP address to populate `allowed_ssh_ips` in `terraform.tfvars`.

```bash
# macOS / Linux
curl -s https://checkip.amazonaws.com

# Windows (PowerShell)
(Invoke-WebRequest -Uri "https://checkip.amazonaws.com").Content.Trim()
```

---

## AWS (EC2)

SSL Manager can be deployed to AWS using the Terraform configuration in `deploy/aws/`. It provisions a hardened EC2 instance (Ubuntu 24.04 LTS) with an encrypted EBS root volume and a security group that restricts SSH access to specified IP addresses only.

**Full instructions:** [DEPLOY-AWS.md](DEPLOY-AWS.md)

### Summary of steps

```bash
# 1. Install prerequisites — see "Cloud Deployment Prerequisites" above

# 2. Authenticate
aws configure
aws sts get-caller-identity     # confirm the correct account

# 3. Configure
cd deploy/aws
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars: set admin_ssh_public_key and allowed_ssh_ips

# 4. Deploy
terraform init
terraform plan
terraform apply

# 5. Install SSL Manager on the provisioned instance
ssh ubuntu@<public_ip_from_output>
# Then follow the bare metal steps above from "Get the code"
```

### What Terraform provisions

| Resource | Detail |
|---|---|
| VPC, subnet, internet gateway | Isolated network with public routing |
| Security group | SSH (port 22) from `allowed_ssh_ips` only; all other inbound blocked |
| EC2 instance | `t3.small` (2 vCPU / 2 GB), Ubuntu 24.04 LTS |
| EBS root volume | 30 GB gp3, encrypted with AWS-managed key |
| Elastic IP | Static public IP, persists through reboots |

### Adding SSH IPs later

```hcl
# terraform.tfvars
allowed_ssh_ips = [
  "203.0.113.10/32",   # existing
  "198.51.100.5/32",   # new IP
]
```

```bash
terraform apply   # updates the security group in seconds, no restart needed
```

---

## Azure (VM)

SSL Manager can be deployed to Azure using the Terraform configuration in `deploy/azure/`. It provisions a hardened Linux VM (Ubuntu 24.04 LTS) with hypervisor-level disk encryption and a Network Security Group that restricts SSH access to specified IP addresses only.

**Full instructions:** [DEPLOY-AZURE.md](DEPLOY-AZURE.md)

### Summary of steps

```bash
# 1. Install prerequisites — see "Cloud Deployment Prerequisites" above

# 2. Authenticate
az login
az account show                    # confirm the correct subscription

# 3. Register the EncryptionAtHost feature (one-time per subscription)
az feature register --name EncryptionAtHost --namespace Microsoft.Compute
az feature show    --name EncryptionAtHost --namespace Microsoft.Compute \
  --query "properties.state" -o tsv
# Wait until output is "Registered" (5–10 minutes)
az provider register --namespace Microsoft.Compute

# 4. Configure
cd deploy/azure
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars: set admin_ssh_public_key and allowed_ssh_ips

# 5. Deploy
terraform init
terraform plan
terraform apply

# 6. Install SSL Manager on the provisioned VM
ssh sslmgr@<public_ip_from_output>
# Then follow the bare metal steps above from "Get the code"
```

### What Terraform provisions

| Resource | Detail |
|---|---|
| Resource group, VNet, subnet | Isolated network |
| Network Security Group | SSH (port 22) from `allowed_ssh_ips` only; all other inbound blocked |
| VM | `Standard_B1ms` (1 vCPU / 2 GB), Ubuntu 24.04 LTS |
| OS disk | 30 GB Premium SSD, encrypted at host |
| Static public IP | Standard SKU, persists through reboots |

### Adding SSH IPs later

```hcl
# terraform.tfvars
allowed_ssh_ips = [
  "203.0.113.10/32",   # existing
  "198.51.100.5/32",   # new IP
]
```

```bash
terraform apply   # updates the NSG rule in seconds, no restart needed
```

---

## Docker (Local Development)

Docker is provided for local development and testing only. It runs the Flask application directly without nginx, gunicorn, systemd, or the hardening applied by `install.sh`. **Do not use Docker in production.**

### App only

```bash
docker compose up --build
```

The app is available at `http://localhost:5001`.

### App + backup test service

Adds a `backup-test` container that runs `backup.sh` 10 seconds after startup, then every hour. Use this to verify backup execution and audit log entries without waiting for the systemd timer.

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml up --build
```

Watch backup output:

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml logs -f backup-test
```

### App + design seed data

Populates the database with representative seed data (certificates, chains, CAs, users) for UI development and screenshot generation:

```bash
docker compose -f docker-compose.yml -f docker-compose.design.yml up --build
```

Seed credentials: `designer / design123` (superadmin), `alice / design123` (user). See `seed_design.py` for the full dataset.

Full developer workflow documentation, including the complete Docker command reference, is in [WORKFLOW.md — Section 1](../developer/WORKFLOW.md#1-docker-development-environment).

---

## Pre-Deployment Testing (deploy/test/)

For maintainers: `deploy/test/` is a Docker-based harness that validates the
installers against every supported OS and CPU architecture in disposable
containers — before any real server is touched. It is **not** required to deploy
SSL Manager; use it when changing dependencies, the installers, or qualifying a
new OS release.

### Requirements

- Docker (Desktop or Engine) with the daemon running
- For cross-architecture runs on a single host, the QEMU/binfmt emulators:
  ```bash
  docker run --privileged --rm tonistiigi/binfmt --install amd64,arm64
  ```

### Two layers of checks

| Script | What it proves |
|---|---|
| `run-matrix.sh` | **Dependency + app layer.** In a clean container per OS/arch: installs the same apt packages as `install.sh`, builds the venv, runs `pip install -r requirements.txt` (asserting wheels resolve — no source builds), runs the full `pytest` suite, and boots gunicorn to serve a live request. |
| `install-matrix.sh` | **Full installer, end-to-end.** Boots a systemd-enabled container, runs `install.sh` non-interactively, then `verify-install.sh` asserts the service + timers are active, the socket and file permissions are correct, and a request through nginx → gunicorn returns a valid HTTP response. |

Supporting files: `Dockerfile.systemd` (Ubuntu systemd image), `Dockerfile.systemd-rhel` (AlmaLinux 9 image for `install-rhel.sh`), `preflight.sh` (the in-container dependency check), and `verify-install.sh` (the OS-agnostic post-install assertions).

### Running

```bash
# Dependency + app matrix across Ubuntu 24.04/26.04, amd64 + arm64 (default)
bash deploy/test/run-matrix.sh

# Full install.sh matrix (systemd containers)
bash deploy/test/install-matrix.sh

# Narrow the matrix with env vars
IMAGES="ubuntu:26.04" PLATFORMS="linux/arm64" bash deploy/test/install-matrix.sh

# install-rhel.sh on AlmaLinux 9 (Python 3.9 — the supported floor)
docker build --build-arg BASE=almalinux:9 -t ssl-mgr-rhel \
  -f deploy/test/Dockerfile.systemd-rhel deploy/test
# then run it with systemd (see the Dockerfile header for the exact flags) and
# execute install-rhel.sh + deploy/test/verify-install.sh inside the container.
```

### Known container/emulation limitations

These are artifacts of testing in containers and do **not** affect real servers:

- **systemd sandboxing is not fully reproducible in a container.** The unit's
  hardening directives (`ProtectSystem`, `PrivateDevices`, `SystemCallFilter`, …)
  are validated on the **native** architecture; under QEMU emulation a service
  start can fail with `status=226/NAMESPACE` because the emulation layer cannot
  set up the required mount namespaces (notably Ubuntu 26.04 / systemd 259 under
  `linux/amd64` emulation on an arm64 host). Run the install matrix on the native
  arch and rely on `run-matrix.sh` for the other.
- **Rocky Linux 9's minimal arm64 image** ships broken DNF *module* metadata,
  which breaks `dnf install nginx`; the RHEL harness uses **AlmaLinux 9** instead
  (both are accepted by `install-rhel.sh`).

---

## Managing SSH Users on the Server

This section applies to all deployment methods. Perform these steps as the initial admin user after connecting to the server for the first time.

### Creating a user account

```bash
# Create a standard user (no sudo)
sudo adduser alice

# Create a user with sudo access
sudo adduser bob
sudo usermod -aG sudo bob      # Ubuntu
sudo usermod -aG wheel bob     # RHEL-family
```

`adduser` / `useradd` is interactive — it prompts for a password. The password is used only for `sudo` prompts on the server itself; SSH login uses keys.

> **Tip:** For users who only need SSH tunnel access to the SSL Manager web UI and will never run commands on the server, a standard account without sudo is sufficient.

### Adding a user's SSH public key

Each user generates their key pair on their own machine and sends their **public key** to the administrator.

**As the admin, placing a key for another user:**

```bash
sudo mkdir -p /home/alice/.ssh
sudo chmod 700 /home/alice/.ssh
echo "ssh-ed25519 AAAAC3Nz...rest-of-key... alice-laptop" \
  | sudo tee -a /home/alice/.ssh/authorized_keys
sudo chmod 600 /home/alice/.ssh/authorized_keys
sudo chown -R alice:alice /home/alice/.ssh
```

### Adding multiple keys for one user

Each line in `authorized_keys` is one public key. A user can have keys for multiple devices:

```bash
sudo tee -a /home/alice/.ssh/authorized_keys <<'EOF'
ssh-ed25519 AAAAC3Nz...key-one... alice-laptop
ssh-ed25519 AAAAC3Nz...key-two... alice-home-desktop
EOF
sudo chmod 600 /home/alice/.ssh/authorized_keys
```

### Disabling password authentication (recommended)

Once all users have working key-based login, disable password authentication:

```bash
sudo nano /etc/ssh/sshd_config
```

Set or confirm:

```
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AuthorizedKeysFile .ssh/authorized_keys
```

```bash
sudo sshd -t          # test config before applying
sudo systemctl reload ssh
```

> **Important:** Do not close your current session until you have confirmed key-based login works in a new terminal window.

### Revoking access

To remove a user's access, delete their line in `authorized_keys`:

```bash
sudo nano /home/alice/.ssh/authorized_keys
# Delete the line containing the key to revoke
```

To remove the user entirely:

```bash
sudo deluser --remove-home alice      # Ubuntu
sudo userdel --remove alice           # RHEL-family
```

---

## Upgrading from Previous Versions

The `--upgrade` flag handles all routine upgrades: it backs up the database, then refreshes the application files, Python dependencies, systemd unit, and nginx config. Your `SECRET_KEY`, database, and port/worker settings are preserved. Re-running the installer with no flag auto-detects the existing install and does the same thing. **Schema changes are applied automatically** on the next service start — no manual SQL steps are ever required.

```bash
sudo bash install.sh --upgrade          # Ubuntu
sudo bash install-rhel.sh --upgrade     # RHEL-family
```

### Version history and migration notes

#### v1.1.0 — 2026-06-28 — Expiry notifications, platform support, installer & chain-PEM hygiene

No manual steps required on upgrade (one optional cleanup for older installs — see *Chain PEM hygiene* below).

**New features:**
- **Expiry notification emails** — an optional daily digest (superadmin → Settings → Notifications) emails a colour-coded list of certificates, CAs, and intermediates expiring within a configurable threshold. Delivered by the new `ssl-manager-notify.timer`.
- **Ubuntu 26.04 LTS / Python 3.14 support** — `requirements.txt` selects a compatible `gunicorn` per interpreter via environment markers, so a single dependency set spans RHEL 9's Python 3.9 through Ubuntu 26.04's Python 3.14. Validated on Ubuntu 24.04/26.04 and AlmaLinux 9, amd64 and arm64.
- **OpenTofu supported** — the AWS and Azure Terraform configurations work unchanged with [OpenTofu](https://opentofu.org/); substitute `tofu` for `terraform`. See [Cloud Deployment Prerequisites](#cloud-deployment-prerequisites).

**Reliability fixes:**
- **Worker-boot race fixed** — concurrent gunicorn workers no longer race on schema initialization at startup. Previously a boot could fail with `table ... already exists` (service `status=3`, "Worker failed to boot"); schema bootstrap is now serialized with an exclusive lock.
- **Installer auto-upgrade** — re-running `install.sh` / `install-rhel.sh` on an existing host now detects the installation and upgrades instead of starting a fresh interactive install. A new `--reinstall` flag forces the interactive installer.
- **`SECRET_KEY` preserved on re-run** — the installer no longer regenerates the key on an existing install. Previously this could rotate the key and make stored SMTP/OAuth secrets undecryptable.
- **Installer hardening** — secret generation no longer assumes `python3` exists before the package step, and the Ubuntu installer enables and reload-or-restarts nginx rather than assuming it is already running (robust on lean/container/cloud-init bases).

**Chain PEM hygiene:**
- **Intermediate PEM rendering fixed** — the chain edit modal previously showed PEM with literal `&#10;` instead of line breaks (a display-only double-escape; stored data was unaffected).
- **Line endings normalized on import** — pasting a bundle into a text area submits it with CRLF (standard browser behaviour), which was stored verbatim and surfaced as stray characters in exported `fullchain.pem`. Imports now store LF.
- **Optional cleanup for older installs** — if a chain was imported before this release, normalize the stored rows in place with the bundled tool (dry-run first):
  ```bash
  /opt/ssl-manager/venv/bin/python /opt/ssl-manager/remediate_chain_entities.py          # report
  /opt/ssl-manager/venv/bin/python /opt/ssl-manager/remediate_chain_entities.py --apply  # fix
  ```

**Schema migrations (automatic):**
- `notification_config` — new table created to store expiry-notification settings.

#### v1.0.0 — 2026-03-16 — Initial release

The first tagged release. On a fresh install all schema is created automatically — no manual steps. Capabilities included:

- **Certificate lifecycle** — generate key + CSR, upload signed certificates, renew / rekey, import external CSRs, and intermediate certificate management.
- **Internal Certificate Authority** — create self-signed root CAs and sign pending certificates; reusable certificate profiles; named certificate chains shareable across certificates.
- **Email & accounts** — password reset by email; SMTP with Microsoft 365 and Google OAuth; automatic session invalidation on password change; 15-minute idle timeout for unauthenticated sessions.
- **Smart import** — smart P12/PFX import with a live File Analysis preview; keypair (private key + certificate/bundle, including P7B) import; role-based smart bundle upload that splits and deduplicates intermediates.
- **Operations** — role-based user accounts, audit log, and a daily backup timer.
- **Security** — bundled `cryptography` 46.0.7 (addresses CVE-2025-61727).

---

## Choosing Between AWS and Azure

| Consideration | AWS | Azure |
|---|---|---|
| **Disk encryption setup** | None — `encrypted = true` works immediately | One-time `az feature register` per subscription required |
| **Cheapest option** | t4g.small (ARM Graviton2) ~$12/month + ~$1.60 EBS | B1ms ~$15/month |
| **Minimum viable** | t4g.micro ~$6/month + EBS | B1s ~$8/month |
| **Static IP billing** | EIP free when attached; ~$0.005/hr when unattached | Included in VM cost |
| **Existing account** | Prefer if you have AWS credits or consolidated billing | Prefer if you have Azure credits or EA |
| **Admin username** | `ubuntu` (fixed by AMI) | Configurable (default: `sslmgr`) |

See [REQUIREMENTS.md](REQUIREMENTS.md) for full hardware sizing rationale and a complete provider comparison table.