variable "prefix" {
  description = "Short name prefix applied to every resource. Keep it lowercase alphanumeric."
  type        = string
  default     = "ssl-manager"
}

variable "resource_group_name" {
  description = "Name of the Azure resource group to create."
  type        = string
  default     = "ssl-manager-rg"
}

variable "location" {
  description = "Azure region. Run 'az account list-locations -o table' for valid values."
  type        = string
  default     = "eastus"
}

variable "vm_size" {
  description = <<-EOT
    Azure VM SKU.
      Standard_B1ms (1 vCPU / 2 GB) — recommended default
      Standard_B1s  (1 vCPU / 1 GB) — minimum
      Standard_B2s  (2 vCPU / 4 GB) — recommended for CA-heavy deployments

    Note: The CA module generates RSA-4096 keys on demand. B1ms completes
    this in ~2-4 seconds on a burstable core, well within the 120-second
    gunicorn worker timeout. B2s reduces generation time to ~1-2 seconds.
  EOT
  type        = string
  default     = "Standard_B1ms"
}

variable "admin_username" {
  description = "Linux admin username created on the VM. Root login is disabled by default."
  type        = string
  default     = "sslmgr"
}

variable "admin_ssh_public_key" {
  description = "Contents of the SSH public key used to authenticate to the VM (e.g. the contents of ~/.ssh/id_ed25519.pub)."
  type        = string
  sensitive   = true
}

variable "allowed_ssh_ips" {
  description = <<-EOT
    List of IP addresses or CIDR ranges permitted to reach port 22.
    Use /32 for individual IPs. To add more IPs later, append to this list
    and run 'terraform apply' — the NSG rule updates in place.

    Example:
      allowed_ssh_ips = ["203.0.113.10/32", "198.51.100.0/24"]
  EOT
  type        = list(string)

  validation {
    condition     = length(var.allowed_ssh_ips) > 0
    error_message = "At least one IP or CIDR must be specified for allowed_ssh_ips."
  }
}

variable "os_disk_size_gb" {
  description = "OS disk size in GB. 30 GB is sufficient for <1000 certificates and CAs; increase if log retention will be long."
  type        = number
  default     = 30
}

variable "timezone" {
  description = <<-EOT
    System timezone for the server. Controls log timestamps, backup filenames,
    and the systemd timer fire time. Must be a valid tz database name.
    Run 'timedatectl list-timezones' on any Ubuntu system for the full list.
    Examples: "America/New_York", "America/Chicago", "America/Denver",
              "America/Los_Angeles", "Europe/London", "Asia/Tokyo", "UTC"
  EOT
  type    = string
  default = "UTC"
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
