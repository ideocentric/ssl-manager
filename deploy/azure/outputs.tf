output "public_ip_address" {
  description = "Public IP address of the SSL Manager VM."
  value       = azurerm_public_ip.main.ip_address
}

output "ssh_command" {
  description = "SSH command to connect to the VM."
  value       = "ssh ${var.admin_username}@${azurerm_public_ip.main.ip_address}"
}

output "ssh_tunnel_command" {
  description = "SSH tunnel command for accessing the SSL Manager web UI (adjust local port as needed)."
  value       = "ssh -L 5001:127.0.0.1:5001 ${var.admin_username}@${azurerm_public_ip.main.ip_address}"
}

output "resource_group_name" {
  description = "Name of the Azure resource group containing all SSL Manager resources."
  value       = azurerm_resource_group.main.name
}

output "vm_name" {
  description = "Name of the virtual machine."
  value       = azurerm_linux_virtual_machine.main.name
}

output "allowed_ssh_ips" {
  description = "IP addresses currently permitted SSH access via the NSG."
  value       = var.allowed_ssh_ips
}

output "encryption_at_host_enabled" {
  description = "Confirms that hypervisor-level disk encryption is active."
  value       = azurerm_linux_virtual_machine.main.encryption_at_host_enabled
}
