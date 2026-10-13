output "vpc_id" {
  value = aws_vpc.this.id
}

output "vpc_cidr" {
  value = aws_vpc.this.cidr_block
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_app_subnet_ids" {
  description = "Fargate tasks + internal NLB (S2/S1 ECS module)."
  value       = aws_subnet.private_app[*].id
}

output "private_worker_subnet_ids" {
  description = "EC2 report-worker — the PB-01 forensic target (S3)."
  value       = aws_subnet.private_worker[*].id
}

output "forensics_subnet_id" {
  value = aws_subnet.forensics.id
}

output "private_route_table_id" {
  value = aws_route_table.private.id
}

output "nat_public_ip" {
  description = "Egress IP — useful when reading GuardDuty findings and flow logs."
  value       = aws_eip.nat.public_ip
}

output "nlb_security_group_id" {
  value = aws_security_group.nlb.id
}

output "app_security_group_id" {
  value = aws_security_group.app.id
}

output "worker_security_group_id" {
  value = aws_security_group.worker.id
}

output "quarantine_security_group_id" {
  description = "Consumed by modules/soar (PB-01 isolation target)."
  value       = aws_security_group.quarantine.id
}

output "private_worker_network_acl_id" {
  description = "Consumed by modules/soar: the only NACL PB-01 may add quarantine deny entries to."
  value       = aws_network_acl.private_worker.id
}

output "app_port" {
  value = var.app_port
}

output "nlb_listener_port" {
  value = var.nlb_listener_port
}

output "flow_log_id" {
  value = aws_flow_log.this.id
}
