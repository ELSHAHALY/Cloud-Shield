output "kms_key_arn" {
  value = aws_kms_key.this.arn
}

output "ecr_repository_url" {
  description = "CI pushes here (by digest) once the push role exists."
  value       = aws_ecr_repository.app.repository_url
}

output "ecr_repository_arn" {
  value = aws_ecr_repository.app.arn
}

output "ecs_cluster_arn" {
  value = aws_ecs_cluster.this.arn
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "task_role_name" {
  description = "modules/data attaches the data-plane policy to this role."
  value       = aws_iam_role.task.name
}

output "task_role_arn" {
  value = aws_iam_role.task.arn
}

output "app_log_group_name" {
  value = aws_cloudwatch_log_group.app.name
}

output "service_enabled" {
  value = local.enable_service
}

output "nlb_arn" {
  description = "Target of the REST API Gateway VPC Link (future edge module). null while the service is disabled."
  value       = try(aws_lb.app[0].arn, null)
}

output "nlb_dns_name" {
  value = try(aws_lb.app[0].dns_name, null)
}

output "ecs_service_name" {
  value = try(aws_ecs_service.app[0].name, null)
}

output "report_worker_role_arn" {
  description = "Instance role whose sessions PB-01 revokes (scenario A steals its credentials). null while disabled."
  value       = try(aws_iam_role.worker[0].arn, null)
}

output "report_worker_instance_id" {
  description = "PB-01 forensic target / scenario A host. null while disabled."
  value       = try(aws_instance.worker[0].id, null)
}
