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
}

module "soar" {
  source = "../../modules/soar"

  name                         = local.name
  quarantine_security_group_id = module.network.quarantine_security_group_id
  notification_emails          = var.soar_notification_emails
  dry_run                      = var.soar_dry_run
  min_severity                 = var.soar_min_severity
  soar_scope_tag               = local.soar_scope_tag
  playbook_package             = var.soar_playbook_package

  # Known at plan time (a bool), so the IAM document shape never depends on
  # an unknown ARN.
  revocable_role_arns = var.enable_report_worker ? [module.compute.report_worker_role_arn] : []
}

# TODO(S3): module "detection" — GuardDuty detector, Security Hub, Config rules,
#           CloudTrail (+S3 data events), Glue tables, Athena workgroup w/ scan cap
