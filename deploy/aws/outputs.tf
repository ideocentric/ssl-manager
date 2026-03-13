output "public_ip_address" {
  description = "Elastic IP address of the SSL Manager instance."
  value       = aws_eip.main.public_ip
}

output "ssh_command" {
  description = "SSH command to connect to the instance."
  value       = "ssh ${var.admin_username}@${aws_eip.main.public_ip}"
}

output "ssh_tunnel_command" {
  description = "SSH tunnel command for accessing the SSL Manager web UI (adjust local port as needed)."
  value       = "ssh -L 5001:127.0.0.1:5001 ${var.admin_username}@${aws_eip.main.public_ip}"
}

output "instance_id" {
  description = "EC2 instance ID."
  value       = aws_instance.main.id
}

output "ami_id" {
  description = "AMI ID resolved for Ubuntu 24.04 LTS in this region."
  value       = data.aws_ami.ubuntu.id
}

output "ami_name" {
  description = "Full AMI name resolved for Ubuntu 24.04 LTS in this region."
  value       = data.aws_ami.ubuntu.name
}

output "region" {
  description = "AWS region where resources were deployed."
  value       = var.region
}

output "allowed_ssh_ips" {
  description = "IP addresses currently permitted SSH access via the security group."
  value       = var.allowed_ssh_ips
}

output "ebs_encrypted" {
  description = "Confirms that root EBS volume encryption is active."
  value       = aws_instance.main.root_block_device[0].encrypted
}
