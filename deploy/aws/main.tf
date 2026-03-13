terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Uncomment and configure to store state in S3 (recommended for teams):
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "ssl-manager/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-state-lock"
  # }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = var.tags
  }
}

# ---------------------------------------------------------------------------
# Ubuntu 24.04 LTS AMI (Canonical)
#
# The data source resolves the correct AMI ID for the chosen region and
# architecture automatically. To verify the resolved AMI:
#   terraform plan  (shown in the plan output)
#   aws ec2 describe-images --image-ids <ami-id> --region <region>
# ---------------------------------------------------------------------------
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical's official AWS account

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-${var.ami_arch}-server-*"]
  }

  filter {
    name   = "architecture"
    values = [var.ami_arch]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

# ---------------------------------------------------------------------------
# VPC and networking
# ---------------------------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.prefix}-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${var.prefix}-igw" }
}

resource "aws_subnet" "main" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false # We use an Elastic IP instead

  tags = { Name = "${var.prefix}-subnet" }
}

resource "aws_route_table" "main" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.prefix}-rt" }
}

resource "aws_route_table_association" "main" {
  subnet_id      = aws_subnet.main.id
  route_table_id = aws_route_table.main.id
}

# ---------------------------------------------------------------------------
# Security Group
#
# AllowSSH   — port 22 inbound from var.allowed_ssh_ips only.
#              To add more IPs: append to allowed_ssh_ips in terraform.tfvars
#              and run 'terraform apply' — the rule updates in place.
#
# AllowAllOutbound — unrestricted outbound so apt-get, pip, and the app can
#                    reach the internet. Restrict further if required.
#
# All other inbound traffic is implicitly denied (AWS default behaviour).
# ---------------------------------------------------------------------------
resource "aws_security_group" "main" {
  name        = "${var.prefix}-sg"
  description = "SSL Manager — SSH from approved IPs only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${var.prefix}-sg" }
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.main.id
  description       = "SSH access restricted to approved IPs. Managed by Terraform — edit allowed_ssh_ips in terraform.tfvars."
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22

  # One rule with a list of CIDRs — adding an IP is a one-line tfvars edit + apply
  for_each   = toset(var.allowed_ssh_ips)
  cidr_ipv4  = each.value
}

resource "aws_vpc_security_group_egress_rule" "all_outbound" {
  security_group_id = aws_security_group.main.id
  description       = "Allow all outbound traffic"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# ---------------------------------------------------------------------------
# SSH Key Pair
# ---------------------------------------------------------------------------
resource "aws_key_pair" "main" {
  key_name   = "${var.prefix}-key"
  public_key = var.admin_ssh_public_key

  tags = { Name = "${var.prefix}-key" }
}

# ---------------------------------------------------------------------------
# EC2 Instance
# ---------------------------------------------------------------------------
resource "aws_instance" "main" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.main.key_name
  subnet_id              = aws_subnet.main.id
  vpc_security_group_ids = [aws_security_group.main.id]

  # Do not assign a public IP automatically — traffic routes through the EIP
  associate_public_ip_address = false

  # Set the system timezone on first boot via cloud-init.
  # This ensures backup filenames, log timestamps, and the systemd timer all
  # use the same local time. Changing this value after provisioning requires
  # running 'sudo timedatectl set-timezone <tz>' on the instance manually,
  # as user_data only executes on the first boot.
  user_data = base64encode(<<-EOF
    #cloud-config
    timezone: ${var.timezone}
  EOF
  )

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_size_gb
    iops        = 3000  # gp3 baseline; no extra charge at this level
    throughput  = 125   # MB/s gp3 baseline

    # ---------------------------------------------------------------------------
    # EBS encryption
    #
    # encrypted = true encrypts the root volume using the AWS-managed key
    # (alias/aws/ebs) at no additional cost. No prerequisite registration
    # is required — encryption is applied immediately at provisioning time.
    #
    # The encryption covers all data written to the volume by the OS, including
    # the SQLite database, log files, backup archives, and private key material.
    #
    # To use a Customer Managed Key (CMK) instead, uncomment and set kms_key_id:
    #   kms_key_id = "arn:aws:kms:<region>:<account-id>:key/<key-id>"
    # ---------------------------------------------------------------------------
    encrypted = true

    delete_on_termination = true

    tags = { Name = "${var.prefix}-osdisk" }
  }

  tags = { Name = "${var.prefix}-vm" }

  # Prevent accidental destruction of the running instance.
  # To destroy: first run 'terraform apply' with this block removed, then 'terraform destroy'.
  lifecycle {
    prevent_destroy = false # Set to true in production after initial provisioning
  }
}

# ---------------------------------------------------------------------------
# Elastic IP (static public IP)
#
# The EIP persists through instance stop/start and reboots.
# It is billed at ~$0.005/hour only when NOT associated with a running instance.
# ---------------------------------------------------------------------------
resource "aws_eip" "main" {
  domain = "vpc"
  tags   = { Name = "${var.prefix}-eip" }
}

resource "aws_eip_association" "main" {
  instance_id   = aws_instance.main.id
  allocation_id = aws_eip.main.id
}
