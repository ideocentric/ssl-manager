variable "prefix" {
  description = "Short name prefix applied to every resource. Keep it lowercase with hyphens."
  type        = string
  default     = "ssl-manager"
}

variable "region" {
  description = "AWS region. Run 'aws ec2 describe-regions --output table' for valid values."
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = <<-EOT
    EC2 instance type.
      t3.small  (2 vCPU / 2 GB) — recommended, x86_64
      t3.micro  (2 vCPU / 1 GB) — minimum, x86_64
      t4g.small (2 vCPU / 2 GB) — recommended, ARM Graviton2 (~20% cheaper)
      t4g.micro (2 vCPU / 1 GB) — minimum, ARM Graviton2

    If using a t4g instance type, also change ami_arch to "arm64".
  EOT
  type        = string
  default     = "t3.small"
}

variable "ami_arch" {
  description = "AMI CPU architecture. Use 'x86_64' for t3/t2 instances, 'arm64' for t4g instances."
  type        = string
  default     = "x86_64"

  validation {
    condition     = contains(["x86_64", "arm64"], var.ami_arch)
    error_message = "ami_arch must be 'x86_64' or 'arm64'."
  }
}

variable "admin_username" {
  description = <<-EOT
    Linux admin username. Ubuntu AMIs on AWS create the 'ubuntu' user automatically
    and inject the SSH key into that account. Changing this requires a cloud-init
    user_data script — leave as 'ubuntu' unless you have a specific requirement.
  EOT
  type        = string
  default     = "ubuntu"
}

variable "admin_ssh_public_key" {
  description = "Contents of the SSH public key used to authenticate to the instance (e.g. the contents of ~/.ssh/id_ed25519.pub)."
  type        = string
  sensitive   = true
}

variable "allowed_ssh_ips" {
  description = <<-EOT
    List of IP addresses or CIDR ranges permitted to reach port 22.
    Use /32 for individual IPs. To add more IPs later, append to this list
    and run 'terraform apply' — the security group rule updates in place.

    Example:
      allowed_ssh_ips = ["203.0.113.10/32", "198.51.100.0/24"]
  EOT
  type        = list(string)

  validation {
    condition     = length(var.allowed_ssh_ips) > 0
    error_message = "At least one IP or CIDR must be specified for allowed_ssh_ips."
  }
}

variable "root_volume_size_gb" {
  description = "Root EBS volume size in GB. 30 GB is sufficient for <1000 certificates + 7-day backups."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags applied to every resource in the deployment."
  type        = map(string)
  default = {
    Project     = "ssl-manager"
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
