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
#   var.enable_edge            -> CloudFront + WAF x2 + SPA bucket (+ REST API
#                                 when container_image is set), the WAF log
#                                 bucket and the waf_logs Athena table
#   var.github_oidc_provider_arn -> CI ECR push role
#   var.enable_decoy_route     -> unauthenticated /api/admin* decoy (with the API)
#   var.enable_decoy_publisher -> the decoy publishes notify-only edge findings
#                                 (needs enable_edge + soar_playbook_package)
# Always on: modules/identity (Cognito; zero idle cost on Essentials).
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

  # Plan-time bool (D6): the REST API needs the NLB, which exists only with
  # a container image. Never derived from module.compute.nlb_arn (unknown,
  # not null, while the NLB is being created — F4).
  enable_api = var.enable_edge && var.container_image != null

  # PB-04 (plan "Dev wiring"): the ECS service must exist, Runtime Monitoring
  # must produce the findings, and the service must opt in to the scope tag.
  enable_pb04 = var.container_image != null && var.guardduty_runtime_monitoring && var.soar_scope_app_service

  # GuardDuty Runtime Monitoring Fargate agent repository (F20), from the
  # GuardDuty user guide ("ECR Repository for GuardDuty agent on AWS Fargate").
  # Single region by design (plan §1.2): add the region here before moving.
  guardduty_agent_ecr_repository_arns = {
    "us-east-1" = "arn:aws:ecr:us-east-1:593207742271:repository/aws-guardduty-agent-fargate"
  }
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

  container_image = var.container_image
  # Phase E: data + identity + SOAR (read-only SOC, decoy bus) settings. The
  # module filters local-mode keys and refuses them by precondition (D22);
  # it injects APP_IMAGE and ECR_REPOSITORY_NAME itself (D18).
  container_environment = merge(
    module.data.app_environment,
    module.identity.app_environment,
    module.soar.app_environment,
    {
      CLOUDSHIELD_ENV  = "aws"
      AWS_REGION       = var.aws_region
      MAX_UPLOAD_BYTES = "5242880"
    },
  )

  enable_report_worker            = var.enable_report_worker
  soar_scope_tag                  = local.soar_scope_tag
  worker_permissions_boundary_arn = module.soar.target_permissions_boundary_arn

  # PB-04 prerequisites (Phase D): opt-in scope tag on the app service, and
  # the GuardDuty agent pull when Runtime Monitoring is on.
  soar_scope_app_service = var.soar_scope_app_service
  guardduty_agent_ecr_repository_arns = var.guardduty_runtime_monitoring ? compact([
    lookup(local.guardduty_agent_ecr_repository_arns, var.aws_region, ""),
  ]) : []

  # CI push role (gap 9): null = not created.
  github_oidc_provider_arn = var.github_oidc_provider_arn
  github_repository        = var.github_repository
}

# Edge (TB1): CloudFront + both WAFs + SPA bucket (+ REST API with
# local.enable_api). No us_east_1 provider alias: the module uses the F17
# fallback and refuses any region but us-east-1 (modules/edge/main.tf).
# Edge never consumes soar outputs, so soar may consume edge's: no cycle.
module "edge" {
  count  = var.enable_edge ? 1 : 0
  source = "../../modules/edge"

  name       = local.name
  enable_api = local.enable_api
  # Phase E D14: unauthenticated /api/admin* decoy (static 403). Off by default.
  enable_decoy_route = var.enable_decoy_route

  nlb_arn               = module.compute.nlb_arn
  nlb_dns_name          = module.compute.nlb_dns_name
  nlb_listener_port     = module.network.nlb_listener_port
  cognito_user_pool_arn = module.identity.user_pool_arn

  waf_log_bucket_arn        = module.log_archive.waf_log_bucket_arn
  waf_rate_limit            = var.waf_rate_limit
  waf_api_rate_limit        = var.waf_api_rate_limit
  manage_apigw_account_role = var.manage_apigw_account_role
}

# ===================== S2 — App / Identity / Data (@YasseenAbdelghany) =======

module "data" {
  source = "../../modules/data"

  name               = local.name
  app_task_role_name = module.compute.task_role_name
}

# Always on (D6): Cognito Essentials has no idle cost.
module "identity" {
  source = "../../modules/identity"

  name                = local.name
  mfa_configuration   = var.cognito_mfa_configuration
  deletion_protection = var.cognito_deletion_protection
}

# ===================== S3 — SecOps / SOAR / Forensics (@ahklsfg) =============

module "log_archive" {
  source = "../../modules/log-archive"

  name                       = local.name
  force_destroy              = var.log_archive_force_destroy
  object_lock_retention_days = var.log_archive_object_lock_days

  cloudtrail_trail_name   = local.trail_name
  enable_config_delivery  = var.enable_config
  enable_guardduty_export = var.manage_guardduty_detector

  # aws-waf-logs-* bucket for both web ACLs (F1, D8).
  enable_waf_logs = var.enable_edge
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
  evidence_object_lock_days    = var.evidence_object_lock_days

  # Known at plan time (a bool), so the IAM document shape never depends on
  # an unknown ARN.
  revocable_role_arns = var.enable_report_worker ? [module.compute.report_worker_role_arn] : []

  # Config NON_COMPLIANT notifications from module.detection (by name: no cycle).
  extra_notify_rule_names = var.enable_config ? ["${local.name}-soar-config-noncompliant"] : []

  # Phase D stage 2b. Plan-time bools only (D6); edge never consumes soar
  # outputs, so reading module.edge[0] here is cycle-free.
  # PB-04: needs the app service, GuardDuty Runtime Monitoring (paid, off by
  # default, F20) and the opt-in scope tag on the service.
  enable_pb04       = local.enable_pb04
  ecs_cluster_name  = module.compute.ecs_cluster_name
  ecs_cluster_arn   = module.compute.ecs_cluster_arn
  ecs_service_names = local.enable_pb04 ? [module.compute.ecs_service_name] : []

  # PB-05: on with the edge. The WAF lives in this (us-east-1) region (F17
  # fallback), so the soar module's own us-east-1 precondition applies too.
  enable_pb05       = var.enable_edge
  block_ip_set_arns = var.enable_edge ? values(module.edge[0].block_ip_set_arns) : []
  waf_web_acl       = var.enable_edge ? module.edge[0].cloudfront_web_acl : null
  # Only the /api/*-scoped rule feeds PB-05 (audit A2); RateLimitPerIp is 429-only.
  waf_rate_rule_name = var.enable_edge ? module.edge[0].soar_rate_rule_name : "SoarApiRateLimit"
  nat_public_ip      = module.network.nat_public_ip

  # ChatOps notifier (plan §5.1): off unless an operator-created SecureString
  # is named (docs/runbooks/chatops-setup.md). The URL never enters state.
  chatops_webhook_param_name = var.chatops_webhook_param_name

  # Phase E (D13, D16): read-only SOC access for the docs-api task role, and
  # the decoy publisher (notify-only in the guard). Plan-time bools only;
  # soar derives the bus publisher list from app_publishes_decoy itself.
  # No resource cycle: soar.app_environment is built from names only (F35).
  enable_app_integration = var.container_image != null
  app_task_role_name     = module.compute.task_role_name
  app_task_role_arn      = module.compute.task_role_arn
  app_publishes_decoy    = var.enable_decoy_publisher && local.enable_api
}

module "detection" {
  source = "../../modules/detection"

  name                    = local.name
  log_archive_bucket_name = module.log_archive.bucket_name
  log_archive_bucket_arn  = module.log_archive.bucket_arn
  log_archive_kms_key_arn = module.log_archive.kms_key_arn

  cloudtrail_trail_name = local.trail_name
  # Object-level audit of the sensitive buckets (gap 16), the lab bucket, and
  # the SPA bucket (the edge's CKV_AWS_18 compensating control, audit A8).
  data_event_bucket_arns = concat(
    [module.soar.evidence_bucket_arn, module.data.documents_bucket_arn],
    var.enable_lab_targets ? [module.lab_targets[0].lab_bucket_arn] : [],
    var.enable_edge ? [module.edge[0].spa_bucket_arn] : [],
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

  # waf_logs table + hunt query 04 (Phase D).
  enable_waf_logs     = var.enable_edge
  waf_log_bucket_name = var.enable_edge ? module.log_archive.waf_log_bucket_name : ""
  waf_web_acl_names   = var.enable_edge ? module.edge[0].web_acl_names : []
}

# Scenario B/C targets (plan §7). Off unless a simulation is being run.
module "lab_targets" {
  count  = var.enable_lab_targets ? 1 : 0
  source = "../../modules/lab-targets"

  name                     = local.name
  soar_scope_tag           = local.soar_scope_tag
  soar_target_boundary_arn = module.soar.target_permissions_boundary_arn
}
