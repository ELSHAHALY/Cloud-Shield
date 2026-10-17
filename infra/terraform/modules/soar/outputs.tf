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

output "edge_event_bus_arn" {
  description = "PB-05 dedicated edge bus (named publishers only). null without enable_pb05."
  value       = one(aws_cloudwatch_event_bus.edge[*].arn)
}

output "edge_event_bus_name" {
  description = "Phase E publishers put CloudShield edge events here (their role ARN must be in pb05_publisher_arns)."
  value       = one(aws_cloudwatch_event_bus.edge[*].name)
}

output "pb05_never_block_parameter" {
  description = "SSM parameter holding the CIDRs PB-05 never blocks. null without enable_pb05."
  value       = one(aws_ssm_parameter.never_block[*].name)
}

output "pb05_harvester_function_name" {
  value = one(aws_lambda_function.harvester[*].function_name)
}

output "notifier_function_name" {
  description = "ChatOps notifier Lambda. null unless chatops_webhook_param_name is set (and the playbook package exists)."
  value       = one(aws_lambda_function.notifier[*].function_name)
}

output "pb05_sweeper_function_name" {
  description = "Lifts expired PB-05 blocks on a schedule (audit A2). null without enable_pb05."
  value       = one(aws_lambda_function.sweeper[*].function_name)
}

output "pb05_harvest_state_table_name" {
  description = "Per-address sighting counters (>= 2 consecutive harvests before a publish). null without enable_pb05."
  value       = one(aws_dynamodb_table.harvest_state[*].name)
}

output "app_environment" {
  description = "Non-secret SOC settings for the docs-api container (merged into modules/compute container_environment). Built from names and locals only (F35)."
  value = {
    INCIDENTS_TABLE        = local.app_incidents_table_name
    INCIDENTS_STATUS_INDEX = local.app_incidents_index_name
    EVIDENCE_BUCKET        = local.app_evidence_bucket_name
    SOAR_DRY_RUN_PARAM     = local.app_dry_run_param_name
    SOAR_PLAYBOOKS_ENABLED = tostring(local.enable_playbooks)
    EDGE_EVENT_SOURCE      = local.edge_event_source
    EDGE_BUS_NAME          = local.app_publishes_decoy ? local.edge_bus_name : ""
    DECOY_PUBLISH_ENABLED  = tostring(local.app_publishes_decoy)
    AWS_ACCOUNT_ID         = local.account_id
  }
}
