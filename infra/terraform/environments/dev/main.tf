###############################################################################
# Environment: dev  (single-account model — ADR-0001, module map ADR-0002)
#
# Composition only: no resources are declared directly in this file. Each
# domain owner edits the block under their own banner, which keeps merge
# conflicts between S1/S2/S3 to a minimum.
#
# Feature flags (all OFF by default — nothing code-dependent is created):
#   var.container_image        -> NLB + task definition + ECS service
#   var.enable_report_worker   -> EC2 forensic target
#   var.soar_playbook_package  -> Lambdas + Step Functions cs-ir-router
###############################################################################

locals {
  name = "${var.project_name}-${var.environment}"

  # The ONE tag that makes a resource eligible for SOAR automation. Applied
  # explicitly to lab targets only — never put it in provider default_tags,
  # or every resource becomes in scope and the safety guard is meaningless.
  soar_scope_tag = { "cloudshield:soar-scope" = "in-scope" }

  # Shared by log-archive (bucket policy scoped to this trail ARN) and
  # detection (creates it): a name, not a reference, so there is no cycle.
  trail_name = "${local.name}-trail"
}

data "aws_availability_zones" "available" {
  #checkov:skip=CKV_AWS_394:Only the first two names are used (slice); newly added AZs sort last and cannot change the result
  state = "available"
}

# ===================== S1 — Platform / Infra / CI-CD (@ELSHAHALY) ============

module "network" {
  source = "../../modules/network"

  name                       = local.name
  azs                        = slice(data.aws_availability_zones.available.names, 0, 2)
  flow_logs_destination_arn  = module.log_archive.flow_logs_destination_arn
  enable_interface_endpoints = var.enable_interface_endpoints
  allow_worker_lab_scan      = var.allow_worker_lab_scan
}

module "compute" {
  source = "../../modules/compute"

  name                      = local.name
  vpc_id                    = module.network.vpc_id
  private_app_subnet_ids    = module.network.private_app_subnet_ids
  private_worker_subnet_ids = module.network.private_worker_subnet_ids
  nlb_security_group_id     = module.network.nlb_security_group_id
  app_security_group_id     = module.network.app_security_group_id
  worker_security_group_id  = module.network.worker_security_group_id
  app_port                  = module.network.app_port
  nlb_listener_port         = module.network.nlb_listener_port

  container_image       = var.container_image
  container_environment = module.data.app_environment

  enable_report_worker            = var.enable_report_worker
  soar_scope_tag                  = local.soar_scope_tag
  worker_permissions_boundary_arn = module.soar.target_permissions_boundary_arn
}

# TODO(S1): module "edge" — REST API Gateway + VPC Link (-> module.compute.nlb_arn), WAF x2, CloudFront

# ===================== S2 — App / Identity / Data (@YasseenAbdelghany) =======

module "data" {
  source = "../../modules/data"

  name               = local.name
  app_task_role_name = module.compute.task_role_name
}

# TODO(S2): module "identity" — Cognito user pool, MFA, app client, RBAC groups

# ===================== S3 — SecOps / SOAR / Forensics (@ahklsfg) =============

module "log_archive" {
  source = "../../modules/log-archive"

  name                       = local.name
  force_destroy              = var.log_archive_force_destroy
  object_lock_retention_days = var.log_archive_object_lock_days

  cloudtrail_trail_name   = local.trail_name
  enable_config_delivery  = var.enable_config
  enable_guardduty_export = var.manage_guardduty_detector
}

module "soar" {
  source = "../../modules/soar"

  name                         = local.name
  quarantine_security_group_id = module.network.quarantine_security_group_id
  quarantine_network_acl_ids   = [module.network.private_worker_network_acl_id]
  notification_emails          = var.soar_notification_emails
  dry_run                      = var.soar_dry_run
  min_severity                 = var.soar_min_severity
  soar_scope_tag               = local.soar_scope_tag
  playbook_package             = var.soar_playbook_package

  # Known at plan time (a bool), so the IAM document shape never depends on
  # an unknown ARN.
  revocable_role_arns = var.enable_report_worker ? [module.compute.report_worker_role_arn] : []

  # Config NON_COMPLIANT notifications from module.detection (by name: no cycle).
  extra_notify_rule_names = var.enable_config ? ["${local.name}-soar-config-noncompliant"] : []
}

module "detection" {
  source = "../../modules/detection"

  name                    = local.name
  log_archive_bucket_name = module.log_archive.bucket_name
  log_archive_bucket_arn  = module.log_archive.bucket_arn
  log_archive_kms_key_arn = module.log_archive.kms_key_arn

  cloudtrail_trail_name = local.trail_name
  # Object-level audit of the sensitive buckets (gap 16) + the lab bucket.
  data_event_bucket_arns = concat(
    [module.soar.evidence_bucket_arn, module.data.documents_bucket_arn],
    var.enable_lab_targets ? [module.lab_targets[0].lab_bucket_arn] : [],
  )
  cloudtrail_regions = distinct([var.aws_region, "us-east-1"])

  manage_guardduty_detector    = var.manage_guardduty_detector
  guardduty_s3_protection      = var.guardduty_s3_protection
  guardduty_runtime_monitoring = var.guardduty_runtime_monitoring
  guardduty_malware_protection = var.guardduty_malware_protection

  enable_security_hub = var.enable_security_hub
  securityhub_cis     = var.securityhub_cis
  securityhub_pci_dss = var.securityhub_pci_dss

  enable_config              = var.enable_config
  notify_config_noncompliant = var.enable_config
  notify_sns_topic_arn       = module.soar.sns_topic_arn
}

# Scenario B/C targets (plan §7). Off unless a simulation is being run.
module "lab_targets" {
  count  = var.enable_lab_targets ? 1 : 0
  source = "../../modules/lab-targets"

  name                     = local.name
  soar_scope_tag           = local.soar_scope_tag
  soar_target_boundary_arn = module.soar.target_permissions_boundary_arn
}
