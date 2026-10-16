variable "project_name" {
  type    = string
  default = "cloudshield"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "owner" {
  description = "Tag value identifying who to ask about these resources."
  type        = string
  default     = "depi-cloudshield-team"
}

# ---------------- S1 ----------------
variable "enable_interface_endpoints" {
  description = "See modules/network — costs ~US$100/month when true."
  type        = bool
  default     = false
}

variable "container_image" {
  description = "Digest-pinned docs-api image. null = no NLB/service (app code not ready)."
  type        = string
  default     = null
}

variable "enable_report_worker" {
  description = "Create the EC2 forensic target. Turn on for attack/IR sessions, off overnight (R3)."
  type        = bool
  default     = false
}

variable "allow_worker_lab_scan" {
  description = "LAB ONLY: open worker egress inside the VPC for scenario A (T1046)."
  type        = bool
  default     = false
}

variable "enable_edge" {
  description = "CloudFront + both WAFs + SPA bucket (+ REST API when container_image is set) and WAF logging. ~US$19/month for the WAFs (plan §8). Requires aws_region = us-east-1."
  type        = bool
  default     = false
}

variable "waf_rate_limit" {
  description = "Requests per client IP per 5 minutes before CloudFront's WAF answers 429."
  type        = number
  default     = 300
}

variable "manage_apigw_account_role" {
  description = "Manage the account-level API Gateway CloudWatch role (regional singleton). false if the account already has one."
  type        = bool
  default     = true
}

variable "github_oidc_provider_arn" {
  description = "bootstrap output github_oidc_provider_arn. null = no CI ECR push role."
  type        = string
  default     = null
}

variable "github_repository" {
  description = "owner/repo whose main-branch workflow may push images (exact match)."
  type        = string
  default     = "ELSHAHALY/Cloud-Shield"
}

variable "soar_scope_app_service" {
  description = "Put the SOAR scope tag on the docs-api service and its tasks (PB-04 targets). Off by default."
  type        = bool
  default     = false
}

# ---------------- S2 ----------------
variable "cognito_mfa_configuration" {
  description = "ON (default) or OPTIONAL. OFF is rejected by modules/identity."
  type        = string
  default     = "ON"
}

variable "cognito_deletion_protection" {
  description = "Block deleting the user pool. false in the lab so nightly teardown works; set true before real users exist."
  type        = bool
  default     = false
}

# ---------------- S3 ----------------
variable "log_archive_force_destroy" {
  description = "true in the lab so teardown works; set false before the final demo if evidence must survive."
  type        = bool
  default     = true
}

variable "log_archive_object_lock_days" {
  description = "0 = off. Turn on only for the graded run; it blocks destroy for N days."
  type        = number
  default     = 0
}

variable "soar_notification_emails" {
  description = "Analyst emails for incident notifications (each must confirm the subscription)."
  type        = list(string)
  default     = []
}

variable "soar_dry_run" {
  description = "SOAR global dry-run. Keep true until PB-01 passes its dry-run test."
  type        = bool
  default     = true
}

variable "soar_min_severity" {
  type    = number
  default = 7
}

variable "manage_guardduty_detector" {
  description = "Create the GuardDuty detector (one per region). false if it already exists and you won't import it."
  type        = bool
  default     = true
}

variable "guardduty_s3_protection" {
  type    = bool
  default = false
}

variable "guardduty_runtime_monitoring" {
  type    = bool
  default = false
}

variable "guardduty_malware_protection" {
  type    = bool
  default = false
}

variable "enable_security_hub" {
  type    = bool
  default = false
}

variable "securityhub_cis" {
  type    = bool
  default = false
}

variable "securityhub_pci_dss" {
  type    = bool
  default = false
}

variable "enable_config" {
  description = "Config recorder (S3 buckets only) + S3 public-access rules. One recorder per region: import an existing one."
  type        = bool
  default     = true
}

variable "enable_lab_targets" {
  description = "LAB ONLY: honeytoken user + exposure bucket for the scenario B/C simulations."
  type        = bool
  default     = false
}

variable "soar_playbook_package" {
  description = "S3 location of the built soar/ Lambda zip. null = playbooks and cs-ir-router disabled."
  type = object({
    s3_bucket         = string
    s3_key            = string
    s3_object_version = optional(string)
  })
  default = null
}

variable "chatops_webhook_param_name" {
  description = "SSM SecureString holding the ChatOps webhook URL, created out of band with the SOAR key (docs/runbooks/chatops-setup.md). \"\" = no notifier. Needs soar_playbook_package."
  type        = string
  default     = ""
  nullable    = false
}
