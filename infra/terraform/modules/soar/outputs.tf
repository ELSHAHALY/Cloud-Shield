output "kms_key_arn" {
  value = aws_kms_key.this.arn
}

output "sns_topic_arn" {
  value = aws_sns_topic.incidents.arn
}

output "incidents_table_name" {
  value = aws_dynamodb_table.incidents.name
}

output "incidents_table_arn" {
  value = aws_dynamodb_table.incidents.arn
}

output "evidence_bucket_name" {
  value = aws_s3_bucket.evidence.bucket
}

output "event_rule_arn" {
  value = aws_cloudwatch_event_rule.guardduty.arn
}

output "dry_run_parameter_name" {
  value = aws_ssm_parameter.dry_run.name
}

output "target_permissions_boundary_arn" {
  description = "Attach to every principal SOAR may revoke (report-worker role, honeytoken user)."
  value       = aws_iam_policy.target_boundary.arn
}

output "playbooks_enabled" {
  value = local.enable_playbooks
}

output "state_machine_arn" {
  description = "cs-ir-router. null while playbooks are disabled."
  value       = try(aws_sfn_state_machine.router[0].arn, null)
}

output "playbook_function_names" {
  value = { for k, f in aws_lambda_function.playbook : k => f.function_name }
}

output "evidence_bucket_arn" {
  value = aws_s3_bucket.evidence.arn
}
