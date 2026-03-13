# SSL Manager — AWS Deployment

Terraform configuration that provisions a hardened AWS EC2 instance running SSL Manager.

## What is created

| Resource | Details |
|---|---|
| VPC | Isolated network (`10.0.0.0/16`) with DNS enabled |
| Internet Gateway | Provides outbound internet access (for apt, pip, OS updates) |
| Subnet | Public subnet (`10.0.1.0/24`) in `<region>a` |
| Route Table | Default route → Internet Gateway |
| Security Group | SSH (port 22) allowed from `allowed_ssh_ips` only; all other inbound blocked by default |
| Key Pair | SSH public key registered in EC2 |
| EC2 Instance | Ubuntu 24.04 LTS, `t3.small` (2 vCPU / 2 GB RAM) |
| Root EBS Volume | 30 GB gp3, encrypted with AWS-managed key |
| Elastic IP | Static public IP; persists through stop/start and reboots |

### EBS encryption

`encrypted = true` on the root EBS volume encrypts all data at rest using the AWS-managed key (`alias/aws/ebs`) at no additional cost. This requires no prerequisite registration and is applied immediately at provisioning time, covering the SQLite database, log files, backup archives, and private key material.

To use a Customer Managed Key (CMK) from AWS KMS instead, uncomment and set `kms_key_id` in the `root_block_device` block in `main.tf`.

### Security Group IP management

All permitted SSH source addresses are stored in the `allowed_ssh_ips` Terraform variable. Each IP gets its own ingress rule (AWS best practice). To add or remove an IP:

1. Edit `terraform.tfvars` — add or remove entries from `allowed_ssh_ips`
2. Run `terraform apply`

The security group rules update in place in seconds; no instance restart is required.

---

## Prerequisites

### 1. Tools

| Tool | Install |
|---|---|
| [Terraform](https://developer.hashicorp.com/terraform/downloads) | `brew install terraform` / [hashicorp.com](https://developer.hashicorp.com/terraform/downloads) |
| [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html) | `brew install awscli` / [AWS docs](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html) |

### 2. AWS credentials

Configure credentials for the account and region you want to deploy into:

```bash
aws configure
# Prompts for: AWS Access Key ID, Secret Access Key, region, output format
```

Or for SSO / assumed roles:

```bash
aws sso login --profile your-profile
export AWS_PROFILE=your-profile
```

Confirm the correct account is active:

```bash
aws sts get-caller-identity
```

### 3. SSH key pair

If you do not already have an SSH key pair:

```bash
ssh-keygen -t ed25519 -C "ssl-manager-aws"
# Keys written to ~/.ssh/id_ed25519 and ~/.ssh/id_ed25519.pub
```

---

## Deploy

### 1. Configure variables

```bash
cd deploy/aws
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

`terraform apply` completes in approximately 1–3 minutes. On success, the outputs section displays:

```
Outputs:

allowed_ssh_ips   = ["203.0.113.10/32"]
ami_id            = "ami-0xxxxxxxxxxxxxxxx"
ami_name          = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-20240423"
ebs_encrypted     = true
instance_id       = "i-0xxxxxxxxxxxxxxxx"
public_ip_address = "54.x.x.x"
region            = "us-east-1"
ssh_command       = "ssh ubuntu@54.x.x.x"
ssh_tunnel_command = "ssh -L 5001:127.0.0.1:5001 ubuntu@54.x.x.x"
```

### 3. Connect and install SSL Manager

```bash
# Connect to the instance
ssh ubuntu@<public_ip_address>

# On the instance — update packages
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
ssh -L 5001:127.0.0.1:5001 ubuntu@<public_ip_address>
```

Then open `http://localhost:5001` in your browser and complete first-run setup.

For a persistent tunnel configuration, add to `~/.ssh/config`:

```
Host ssl-manager
    HostName <public_ip_address>
    User ubuntu
    IdentityFile ~/.ssh/id_ed25519
    LocalForward 5001 127.0.0.1:5001
    ServerAliveInterval 60
```

Then simply `ssh ssl-manager`.

---

## Using a Graviton (ARM) instance

Graviton2 instances (`t4g`) offer approximately 20% lower cost for equivalent performance. To switch:

1. In `terraform.tfvars`, set:
   ```hcl
   instance_type = "t4g.small"
   ami_arch      = "arm64"
   ```
2. Run `terraform apply`

The AMI data source selects the correct Ubuntu 24.04 ARM image automatically. All SSL Manager dependencies support ARM — the `cryptography` package includes ARM native extensions.

> **Note:** Switching between `x86_64` and `arm64` replaces the EC2 instance. Take a manual backup before switching architecture.

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

The security group rules update in seconds. No instance restart needed.

---

## Verify EBS encryption

After the instance is running:

```bash
aws ec2 describe-volumes \
  --filters "Name=attachment.instance-id,Values=$(terraform output -raw instance_id)" \
  --query "Volumes[*].{ID:VolumeId,Encrypted:Encrypted,KmsKeyId:KmsKeyId}" \
  --output table
# Encrypted column should show True
```

Or from the instance itself:

```bash
# Each block device should show "crypto_LUKS" or similar
lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT
```

---

## Upgrade SSL Manager

After pulling new code, copy it to the instance and run the upgrade:

```bash
# From your local machine — copy updated files
scp -r app.py templates/ static/ backup.sh requirements.txt \
    ssl-manager-backup.service ssl-manager-backup.timer \
    ubuntu@<public_ip>:/tmp/ssl-manager-update/

# On the instance
sudo cp /tmp/ssl-manager-update/* /opt/ssl-manager/
sudo bash /opt/ssl-manager/install.sh --upgrade
```

---

## Tear down

```bash
terraform destroy
```

This terminates the EC2 instance and releases the Elastic IP. The EBS volume is deleted (`delete_on_termination = true`). Take a manual backup first:

```bash
ssh ubuntu@<public_ip> \
  "sudo bash /opt/ssl-manager/backup.sh --dest /tmp/ssl-final-backup && \
   sudo ls -lh /tmp/ssl-final-backup/"

# Copy the backup archive locally before destroying
scp "ubuntu@<public_ip>:/tmp/ssl-final-backup/*.db.gz" .
```

> **Elastic IP note:** An unassociated Elastic IP is billed at ~$0.005/hour. `terraform destroy` releases it, stopping the charge.
