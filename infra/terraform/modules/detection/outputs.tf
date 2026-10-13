output "guardduty_detector_id" {
  description = "null when manage_guardduty_detector = false."
  value       = local.detector_id
}

output "cloudtrail_arn" {
  value = one(aws_cloudtrail.this[*].arn)
}

output "athena_workgroup" {
  value = aws_athena_workgroup.forensics.name
}

output "athena_results_bucket" {
  value = aws_s3_bucket.athena_results.bucket
}

output "glue_database" {
  value = aws_glue_catalog_database.forensics.name
}

output "hunt_queries" {
  description = "Named query name -> id, one per detection/athena-queries/*.sql."
  value       = { for k, q in aws_athena_named_query.hunt : q.name => q.id }
}

output "config_rule_names" {
  value = var.enable_config ? values(local.config_rule_names) : []
}

output "config_notify_rule_name" {
  description = "Pass to modules/soar extra_notify_rule_names so the SOAR topic accepts it."
  value       = "${var.name}-soar-config-noncompliant"
}
