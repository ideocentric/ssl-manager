# SSL Manager — Azure Deployment

Terraform configuration that provisions a hardened Azure VM running SSL Manager.

## What is created

| Resource | Details |
|---|---|
| Resource Group | Contains all SSL Manager resources |
| Virtual Network + Subnet | Isolated network (`10.0.0.0/16` / `10.0.1.0/24`) |
| Network Security Group | SSH (port 22) allowed from `allowed_ssh_ips` only; all other inbound blocked |
| Static Public IP | Standard SKU — address persists through VM restarts |
| Network Interface | NSG applied at both NIC and subnet level (defence in depth) |
| Linux VM | Ubuntu 24.04 LTS, `Standard_B1ms` (1 vCPU / 2 GB RAM) |
| OS Disk | 30 GB Premium SSD, encrypted at host |

### Disk encryption

`encryption_at_host_enabled = true` encrypts all data written by the VM at the hypervisor level — OS disk, temporary disk, and their caches — using Azure platform-managed keys. This requires a one-time subscription feature registration (see Prerequisites below).

This approach covers everything written to disk by the SSL Manager application: the SQLite database, log files, backup archives, and private key material.

### NSG IP management

All permitted SSH source addresses are stored in the `allowed_ssh_ips` Terraform variable. To add or remove an IP:

1. Edit `terraform.tfvars` — add or remove entries from `allowed_ssh_ips`
2. Run `terraform apply`

The NSG rule updates in place in seconds; no VM restart is required.

---

## Prerequisites

### 1. Tools

| Tool | Install |
|---|---|
| [Terraform](https://developer.hashicorp.com/terraform/downloads) | `brew install terraform` / [hashicorp.com](https://developer.hashicorp.com/terraform/downloads) |
| [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) | `brew install azure-cli` / [Microsoft docs](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) |

### 2. Azure login

```bash
az login
az account show   # confirm the correct subscription is active
```

To switch subscriptions:

```bash
az account set --subscription "<subscription-id-or-name>"
```

### 3. Register the EncryptionAtHost feature

This is a one-time step per subscription. It takes 5–10 minutes.

```bash
az feature register --name EncryptionAtHost --namespace Microsoft.Compute

# Poll until state is "Registered"
az feature show --name EncryptionAtHost --namespace Microsoft.Compute \
  --query "properties.state" -o tsv

az provider register --namespace Microsoft.Compute
```

### 4. SSH key pair

If you do not already have an SSH key pair:

```bash
ssh-keygen -t ed25519 -C "ssl-manager-azure"
# Keys written to ~/.ssh/id_ed25519 and ~/.ssh/id_ed25519.pub
```

---

## Deploy

### 1. Configure variables

```bash
cd deploy/azure
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` and set at minimum:

- `admin_ssh_public_key` — contents of `~/.ssh/id_ed25519.pub`
- `allowed_ssh_ips` — your current public IP (find it with `curl -s https://checkip.amazonaws.com`)

### 2. Initialise and apply

```bash
terraform init
terraform plan    # review what will be created
terraform apply   # type 'yes' to confirm
```

`terraform apply` completes in approximately 2–4 minutes. On success, the outputs section displays:

```
Outputs:

allowed_ssh_ips            = ["203.0.113.10/32"]
encryption_at_host_enabled = true
public_ip_address          = "20.x.x.x"
resource_group_name        = "ssl-manager-rg"
ssh_command                = "ssh sslmgr@20.x.x.x"
ssh_tunnel_command         = "ssh -L 5001:127.0.0.1:5001 sslmgr@20.x.x.x"
vm_name                    = "ssl-manager-vm"
```

### 3. Connect and install SSL Manager

```bash
# Connect to the VM
ssh sslmgr@<public_ip_address>

# On the VM — update packages
sudo apt-get update && sudo apt-get upgrade -y

# Clone the repository (or copy files via scp)
git clone https://github.com/your-org/ssl-manager.git
cd ssl-manager

# Run the installer
sudo bash install.sh
```

Follow the interactive installer prompts (port, Gunicorn workers, secret key). When complete, the SSL Manager service is running and the daily backup timer is enabled.

### 4. Open the web UI via SSH tunnel

From your **local machine**:

```bash
ssh -L 5001:127.0.0.1:5001 sslmgr@<public_ip_address>
```

Then open `http://localhost:5001` in your browser and complete first-run setup.

For persistent tunnel configuration, add to `~/.ssh/config`:

```
Host ssl-manager
    HostName <public_ip_address>
    User sslmgr
    IdentityFile ~/.ssh/id_ed25519
    LocalForward 5001 127.0.0.1:5001
    ServerAliveInterval 60
```

Then simply `ssh ssl-manager`.

---

## Adding SSH IPs

Edit `terraform.tfvars`:

```hcl
allowed_ssh_ips = [
  "203.0.113.10/32",   # Office
  "198.51.100.5/32",   # New IP to add
]
```

Apply:

```bash
terraform apply
```

The NSG rule updates in seconds. No VM restart needed.

---

## Verify disk encryption

After the VM is running:

```bash
az vm show \
  --resource-group ssl-manager-rg \
  --name ssl-manager-vm \
  --query "securityProfile.encryptionAtHost" \
  --output tsv
# Expected output: true
```

---

## Upgrade SSL Manager

After pulling new code, upload it to the VM and run the upgrade:

```bash
# From your local machine — copy updated files
scp -r app.py templates/ static/ backup.sh requirements.txt \
    ssl-manager-backup.service ssl-manager-backup.timer \
    sslmgr@<public_ip>:/tmp/ssl-manager-update/

# On the VM
sudo cp /tmp/ssl-manager-update/* /opt/ssl-manager/
sudo bash /opt/ssl-manager/install.sh --upgrade
```

---

## Tear down

```bash
terraform destroy
```

This removes all resources in the resource group. The SQLite database is on the VM's OS disk and will be deleted. Take a manual backup first:

```bash
ssh sslmgr@<public_ip> \
  "sudo bash /opt/ssl-manager/backup.sh --dest /tmp/ssl-final-backup && \
   sudo ls -lh /tmp/ssl-final-backup/"

# Copy the backup archive locally before destroying
scp "sslmgr@<public_ip>:/tmp/ssl-final-backup/*.db.gz" .
```
