# SSL Manager — Installation Guide

## Deployment Options

| Method | Best for |
|---|---|
| [Bare metal / Ubuntu server](#bare-metal--ubuntu-server) | Physical hardware, on-premises VMs, self-managed VPS |
| [AWS (EC2)](#aws-ec2) | Existing AWS accounts, consolidated billing, Graviton cost savings |
| [Azure (VM)](#azure-vm) | Existing Azure accounts, enterprise agreements, Azure credits |
| [Docker (local development)](#docker-local-development) | Development, testing, and feature validation — not for production |

Cloud deployments (AWS and Azure) require Terraform and the relevant cloud CLI. See [Cloud Deployment Prerequisites](#cloud-deployment-prerequisites) for installation instructions covering macOS, Linux, and Windows — including [SSH key generation](#ssh-key-pair) for all platforms and [server-side user management](#managing-ssh-users-on-the-server).

All production methods (bare metal, AWS, Azure) share the same runtime stack: nginx → gunicorn → Flask → SQLite, with access via SSH tunnel only. See [REQUIREMENTS.md](REQUIREMENTS.md) for hardware sizing guidance.

---

## Bare Metal / Ubuntu Server

Use this method for physical hardware, on-premises virtual machines, or any VPS where you provision the OS yourself.

### Requirements

- Ubuntu 24.04 LTS (recommended), 22.04 LTS, or 20.04 LTS
- Root or `sudo` access
- Outbound internet access (for `apt-get` and `pip`)
- Minimum: 1 vCPU, 1 GB RAM, 10 GB disk
- Recommended: 1–2 vCPU, 2 GB RAM, 20 GB disk

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

1. Installs system packages (`nginx`, `sqlite3`, `python3-pip`, `python3-venv`, `gcc`, `python3-dev`)
2. Creates the `ssl-manager` service account (no login shell, no home directory)
3. Creates all directories with enforced ownership and permissions
4. Copies application files to `/opt/ssl-manager/`
5. Creates a Python virtual environment and installs all dependencies
6. Writes the secret key and database URL to `/etc/ssl-manager/env`
7. Installs and starts the `ssl-manager` systemd service
8. Configures nginx as a reverse proxy with rate limiting
9. Installs and enables the `ssl-manager-backup.timer` for daily database backups

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

See [README.md — Host hardening](../../README.md#host-hardening) for the complete hardening checklist including SSH configuration and sysctl settings.

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

The upgrade script backs up the database, copies updated application files, reinstalls Python dependencies, and restarts the service.

### Uninstalling

```bash
sudo bash install.sh --uninstall
```

Removes the service, application files, nginx config, and optionally the database and service user. The database at `/var/lib/ssl-manager/` is not deleted unless explicitly confirmed.

---

## Cloud Deployment Prerequisites

The AWS and Azure deployments both use Terraform. Install the required tools on your local machine before proceeding.

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

Every user who needs to connect to the server — including the administrator deploying via Terraform — requires an SSH key pair. Generate one on the machine you will connect from, then provide the public key to the server administrator (or paste it into `terraform.tfvars` for Terraform deployments).

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

**If a key already exists** and you are comfortable reusing it, skip to the "View / copy" step below.

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
xclip -selection clipboard < ~/.ssh/id_ed25519_ssl_manager.pub   # named key, X11
```

**Connecting with a named key:**

```bash
ssh -i ~/.ssh/id_ed25519_ssl_manager user@<server-ip>

# With tunnel
ssh -i ~/.ssh/id_ed25519_ssl_manager -L 5001:127.0.0.1:5001 user@<server-ip>
```

Or add to `~/.ssh/config` to avoid specifying `-i` on every connection:

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
Get-Content $env:USERPROFILE\.ssh\id_ed25519_ssl_manager.pub | Set-Clipboard  # named key
```

**Connecting with a named key:**

```powershell
ssh -i $env:USERPROFILE\.ssh\id_ed25519_ssl_manager user@<server-ip>

# With tunnel
ssh -i $env:USERPROFILE\.ssh\id_ed25519_ssl_manager -L 5001:127.0.0.1:5001 user@<server-ip>
```

Or add to `C:\Users\<you>\.ssh\config` (create the file if it does not exist):

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
2. Check whether an existing `.ppk` file exists in your documents — if so, you can load and reuse it via **File → Load private key**
3. To create a new key: select **EdDSA** and click **Generate**, then move the mouse over the blank area to generate entropy
4. Set a **Key passphrase**
5. Click **Save private key** — save the `.ppk` file with a descriptive name (e.g. `ssl-manager.ppk`)
6. Copy the text in the **Public key for pasting into OpenSSH authorized_keys** box — this is what goes on the server

To specify the key in a PuTTY session: open the session, go to **Connection → SSH → Auth → Credentials**, and set the **Private key file** to your `.ppk` file.

> The `.ppk` format is PuTTY-specific. When the server administrator asks for your public key, give them the text from the "Public key for pasting into OpenSSH" box, not the `.ppk` file itself.

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
| OS disk | 30 GB Premium SSD, encrypted at host (covers OS disk, temp disk, and caches) |
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

Trigger an immediate backup:

```bash
docker compose -f docker-compose.yml -f docker-compose.test.yml \
  exec backup-test bash /app/backup.sh \
    --db /app/instance/ssl_manager.db \
    --dest /var/backups/ssl-manager \
    --days 7
```

Full developer workflow documentation, including the complete Docker command reference, is in [WORKFLOW.md — Section 1](WORKFLOW.md#1-docker-development-environment).

---

## Managing SSH Users on the Server

This section applies to all deployment methods (bare metal, AWS, Azure). Perform these steps as the initial admin user after connecting to the server for the first time.

### Creating a user account

```bash
# Create a standard user (no sudo)
sudo adduser alice

# Create a user with sudo access
sudo adduser bob
sudo usermod -aG sudo bob
```

`adduser` is interactive — it prompts for a password and optional profile fields. The password is used only for `sudo` prompts on the server itself; SSH login will use the key exclusively.

> **Tip:** For users who only need SSH tunnel access to the SSL Manager web UI and will never run commands on the server, a standard account without sudo is sufficient.

### Adding a user's SSH public key

Each user generates their key pair on their own machine (see [SSH key pair](#ssh-key-pair) above) and sends their **public key** (the `.pub` file contents) to the administrator. The administrator then places it on the server.

**Method A — as the admin, placing a key for another user**

```bash
# Switch to the target user's home directory
sudo mkdir -p /home/alice/.ssh
sudo chmod 700 /home/alice/.ssh

# Paste or write the user's public key into authorized_keys
# Replace the echo line with the actual key the user sent you
echo "ssh-ed25519 AAAAC3Nz...rest-of-key... alice-laptop" \
  | sudo tee -a /home/alice/.ssh/authorized_keys

# Lock down permissions — SSH will refuse keys if these are wrong
sudo chmod 600 /home/alice/.ssh/authorized_keys
sudo chown -R alice:alice /home/alice/.ssh
```

**Method B — the user adds their own key after first login**

If you grant the user temporary password-based SSH access to set up their own key:

```bash
# Run this as the user (alice) after logging in with a password
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo "ssh-ed25519 AAAAC3Nz...rest-of-key... alice-laptop" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Once the key is in place, test that key-based login works before disabling password authentication.

### Adding multiple keys for one user

Each line in `authorized_keys` is one public key. A user can have keys for multiple devices:

```bash
sudo tee -a /home/alice/.ssh/authorized_keys <<'EOF'
ssh-ed25519 AAAAC3Nz...key-one... alice-laptop
ssh-ed25519 AAAAC3Nz...key-two... alice-home-desktop
EOF
sudo chmod 600 /home/alice/.ssh/authorized_keys
```

### Verifying permissions

Incorrect permissions on `.ssh` or `authorized_keys` silently prevent key-based login. Verify with:

```bash
sudo ls -la /home/alice/.ssh/
# Expected:
#   drwx------  alice alice  .ssh/               (700)
#   -rw-------  alice alice  authorized_keys     (600)
```

### Testing the connection

Have the user test their key before closing any existing sessions:

```bash
# From the user's local machine
ssh alice@<server-ip>

# Or via tunnel for SSL Manager access
ssh -L 5001:127.0.0.1:5001 alice@<server-ip>
```

### Disabling password authentication (recommended)

Once all users have working key-based login, disable password authentication to prevent brute-force attacks:

```bash
sudo nano /etc/ssh/sshd_config
```

Set or confirm the following lines:

```
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AuthorizedKeysFile .ssh/authorized_keys
```

Apply the change:

```bash
sudo sshd -t          # test the config for syntax errors before reloading
sudo systemctl reload ssh
```

> **Important:** Do not close your current session until you have confirmed that key-based login works in a new terminal window. A misconfigured `sshd_config` can lock you out of the server.

### Revoking access

To remove a user's access, delete or comment out their line in `authorized_keys`:

```bash
sudo nano /home/alice/.ssh/authorized_keys
# Delete the line containing the key to revoke
```

To remove the user entirely:

```bash
sudo deluser --remove-home alice
```

This deletes the home directory and `authorized_keys` file, immediately terminating all future SSH access for that user.

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