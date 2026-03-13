terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.110"
    }
  }

  # Uncomment and configure to store state in Azure Blob Storage (recommended for teams):
  # backend "azurerm" {
  #   resource_group_name  = "terraform-state-rg"
  #   storage_account_name = "tfstatexxxxxxxx"
  #   container_name       = "tfstate"
  #   key                  = "ssl-manager.terraform.tfstate"
  # }
}

provider "azurerm" {
  features {}
}

# ---------------------------------------------------------------------------
# Resource Group
# ---------------------------------------------------------------------------
resource "azurerm_resource_group" "main" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------
resource "azurerm_virtual_network" "main" {
  name                = "${var.prefix}-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = var.tags
}

resource "azurerm_subnet" "main" {
  name                 = "${var.prefix}-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}

# ---------------------------------------------------------------------------
# Network Security Group
#
# AllowSSH   — allows port 22 inbound from the IPs in var.allowed_ssh_ips.
#              To add more IPs later: append to allowed_ssh_ips in
#              terraform.tfvars and run 'terraform apply'.
#
# Azure's built-in default rules handle everything else:
#   - Priority 65000: AllowVnetInBound  (VNet-internal traffic allowed)
#   - Priority 65001: AllowAzureLoadBalancerInBound
#   - Priority 65500: DenyAllInBound    (all other internet traffic blocked)
# ---------------------------------------------------------------------------
resource "azurerm_network_security_group" "main" {
  name                = "${var.prefix}-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = var.tags

  security_rule {
    name                       = "AllowSSH"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefixes    = var.allowed_ssh_ips
    destination_address_prefix = "*"
    description                = "SSH access restricted to approved IPs. Managed by Terraform — edit allowed_ssh_ips in terraform.tfvars."
  }
}

# Apply NSG to the subnet (covers all NICs in the subnet)
resource "azurerm_subnet_network_security_group_association" "main" {
  subnet_id                 = azurerm_subnet.main.id
  network_security_group_id = azurerm_network_security_group.main.id
}

# Apply NSG to the NIC as well (defence in depth)
resource "azurerm_network_interface_security_group_association" "main" {
  network_interface_id      = azurerm_network_interface.main.id
  network_security_group_id = azurerm_network_security_group.main.id
}

# ---------------------------------------------------------------------------
# Public IP
# ---------------------------------------------------------------------------
resource "azurerm_public_ip" "main" {
  name                = "${var.prefix}-pip"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

# ---------------------------------------------------------------------------
# Network Interface
# ---------------------------------------------------------------------------
resource "azurerm_network_interface" "main" {
  name                = "${var.prefix}-nic"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = var.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.main.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.main.id
  }
}

# ---------------------------------------------------------------------------
# Virtual Machine
# ---------------------------------------------------------------------------
resource "azurerm_linux_virtual_machine" "main" {
  name                = "${var.prefix}-vm"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  size                = var.vm_size
  admin_username      = var.admin_username
  tags                = var.tags

  network_interface_ids = [azurerm_network_interface.main.id]

  # SSH key authentication only — password login disabled
  disable_password_authentication = true

  # Set the system timezone on first boot via cloud-init.
  # This ensures backup filenames, log timestamps, and the systemd timer all
  # use the same local time. Changing this value after provisioning requires
  # running 'sudo timedatectl set-timezone <tz>' on the VM manually,
  # as custom_data only executes on the first boot.
  custom_data = base64encode(<<-EOF
    #cloud-config
    timezone: ${var.timezone}
  EOF
  )

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  # ---------------------------------------------------------------------------
  # Disk encryption
  #
  # encryption_at_host_enabled encrypts the OS disk, temporary disk, and their
  # read/write caches at the hypervisor level using platform-managed keys.
  # This covers all data written by the VM, including the SQLite database, logs,
  # and backup archives stored on the OS disk.
  #
  # PREREQUISITE — register the feature on your subscription once before the
  # first 'terraform apply':
  #
  #   az feature register --name EncryptionAtHost --namespace Microsoft.Compute
  #   az feature show    --name EncryptionAtHost --namespace Microsoft.Compute
  #     (wait until "state": "Registered" — usually 5-10 minutes)
  #   az provider register --namespace Microsoft.Compute
  #
  # To verify on a running VM:
  #   az vm show -g <resource_group> -n <vm_name> \
  #     --query "securityProfile.encryptionAtHost"
  # ---------------------------------------------------------------------------
  encryption_at_host_enabled = true

  os_disk {
    name                 = "${var.prefix}-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_size_gb         = var.os_disk_size_gb
  }

  # Ubuntu 24.04 LTS (Noble Numbat) — Canonical's official Azure image.
  # To list available Ubuntu 24.04 images in your region:
  #   az vm image list --publisher Canonical --offer ubuntu-24_04-lts \
  #     --location <region> --all -o table
  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }
}
