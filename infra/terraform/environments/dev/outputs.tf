# ---------------- network ----------------
output "vpc_id" {
  value = module.network.vpc_id
}

output "private_app_subnet_ids" {
  value = module.network.private_app_subnet_ids
}

output "private_worker_subnet_ids" {
  value = module.network.private_worker_subnet_ids
}

output "forensics_subnet_id" {
  value = module.network.forensics_subnet_id
}

output "quarantine_security_group_id" {
  value = module.network.quarantine_security_group_id
}

output "nat_public_ip" {
  value = module.network.nat_public_ip
}

# ---------------- compute ----------------
output "ecr_repository_url" {
  value = module.compute.ecr_repository_url
}

output "ecs_cluster_name" {
  value = module.compute.ecs_cluster_name
}

output "nlb_arn" {
  value = module.compute.nlb_arn
}

output "report_worker_instance_id" {
  value = module.compute.report_worker_instance_id
}

# ---------------- data ----------------
output "documents_table_name" {
  value = module.data.documents_table_name
}

output "audit_table_name" {
  value = module.data.audit_table_name
}

output "documents_bucket_name" {
  value = module.data.documents_bucket_name
}

# ---------------- logging / soar ----------------
output "log_archive_bucket" {
  value = module.log_archive.bucket_name
}

output "log_archive_kms_key_arn" {
  value = module.log_archive.kms_key_arn
}

output "soar_incidents_table" {
  value = module.soar.incidents_table_name
}

output "soar_evidence_bucket" {
  value = module.soar.evidence_bucket_name
}

output "soar_sns_topic_arn" {
  value = module.soar.sns_topic_arn
}

output "soar_dry_run_parameter" {
  value = module.soar.dry_run_parameter_name
}

output "soar_state_machine_arn" {
  value = module.soar.state_machine_arn
}

# ---------------- S3 detection / hunting ----------------
output "athena_workgroup" {
  value = module.detection.athena_workgroup
}

output "glue_database" {
  value = module.detection.glue_database
}

output "hunt_queries" {
  value = module.detection.hunt_queries
}

output "lab_targets" {
  description = "null unless enable_lab_targets."
  value = var.enable_lab_targets ? {
    honeytoken_user = module.lab_targets[0].honeytoken_user_name
    lab_bucket      = module.lab_targets[0].lab_bucket_name
  } : null
}
