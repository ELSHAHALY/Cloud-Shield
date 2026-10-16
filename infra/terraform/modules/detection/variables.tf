variable "name" {
  description = "Name prefix (e.g. cloudshield-dev)."
  type        = string
}

# --- log archive (modules/log-archive outputs) --------------------------------
variable "log_archive_bucket_name" {
  description = "Destination for CloudTrail, Config and the GuardDuty findings export."
  type        = string
}

variable "log_archive_bucket_arn" {
  type = string
}

variable "log_archive_kms_key_arn" {
  description = "Log-archive CMK: encrypts delivered logs; Athena readers need kms:Decrypt on it."
  type        = string
}

# --- CloudTrail ---------------------------------------------------------------
variable "enable_cloudtrail" {
  type    = bool
  default = true
}

variable "cloudtrail_trail_name" {
  description = "Must equal the name passed to modules/log-archive (its bucket policy is scoped to this trail ARN)."
  type        = string
}

variable "data_event_bucket_arns" {
  description = "Buckets whose OBJECT-level reads/writes CloudTrail records (S3 data events). Compensating control for server access logs (handoff gap 16): the evidence and documents buckets, plus the lab bucket when enabled."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.data_event_bucket_arns : can(regex("^arn:aws[a-z-]*:s3:::[a-z0-9.-]+$", a))])
    error_message = "data_event_bucket_arns must be bucket ARNs (arn:aws:s3:::name), without a key path."
  }
}

# --- GuardDuty ------------------------------------------------------------------
variable "manage_guardduty_detector" {
  description = "Create the GuardDuty detector. A region holds ONE detector: if one already exists (e.g. created with `aws guardduty create-detector`), import it instead — see detection/README.md."
  type        = bool
  default     = true
}

variable "guardduty_s3_protection" {
  description = "GuardDuty S3 Protection (S3 data-event analysis: Exfiltration:S3/*, Impact:S3/*). Paid after the trial. Not needed for Policy:S3/* (scenario C)."
  type        = bool
  default     = false
}

variable "guardduty_runtime_monitoring" {
  description = "GuardDuty Runtime Monitoring with the managed ECS Fargate agent. Paid after the trial."
  type        = bool
  default     = false
}

variable "guardduty_malware_protection" {
  description = "GuardDuty Malware Protection for EC2 (EBS scans on findings). Paid after the trial."
  type        = bool
  default     = false
}

variable "guardduty_export_findings" {
  description = "Export findings to the log archive (guardduty/) for the Athena guardduty_findings table. Needs log-archive enable_guardduty_export."
  type        = bool
  default     = true
}

# --- Security Hub -------------------------------------------------------------
variable "enable_security_hub" {
  description = "Enable Security Hub. Off by default: per-check cost after the trial, and its controls depend on Config recording more than S3 buckets."
  type        = bool
  default     = false
}

variable "securityhub_cis" {
  description = "Subscribe to CIS AWS Foundations Benchmark v3.0.0 (needs enable_security_hub)."
  type        = bool
  default     = false
}

variable "securityhub_pci_dss" {
  description = "Subscribe to PCI DSS v3.2.1 (needs enable_security_hub)."
  type        = bool
  default     = false
}

# --- AWS Config ---------------------------------------------------------------
variable "enable_config" {
  description = "Config recorder (S3 buckets only, to bound cost) + the two S3 public-access managed rules."
  type        = bool
  default     = true
}

variable "notify_config_noncompliant" {
  description = "Send Config NON_COMPLIANT results to notify_sns_topic_arn. A plain bool (not 'topic != null') so count is known at plan time."
  type        = bool
  default     = false
}

variable "notify_sns_topic_arn" {
  description = "SOAR incidents topic (modules/soar), used when notify_config_noncompliant is true."
  type        = string
  default     = null
}

# --- Athena -------------------------------------------------------------------
variable "athena_bytes_scanned_cutoff" {
  description = "Per-query scan cap for the forensics workgroup (plan §6.1 cost protection). Athena cancels any query that scans more."
  type        = number
  default     = 1073741824 # 1 GiB

  validation {
    condition     = var.athena_bytes_scanned_cutoff >= 10485760 && var.athena_bytes_scanned_cutoff <= 10737418240
    error_message = "Between 10 MiB (Athena's minimum) and 10 GiB."
  }
}

variable "athena_results_retention_days" {
  type    = number
  default = 30
}

variable "athena_results_force_destroy" {
  type    = bool
  default = true
}

variable "cloudtrail_regions" {
  description = "Regions the cloudtrail table projects over (multi-region trail). Include us-east-1: global-service events (IAM, STS global) land there."
  type        = list(string)
  default     = ["us-east-1"]
}

variable "projection_start_date" {
  description = "First date (yyyy/MM/dd) the date projections cover."
  type        = string
  default     = "2026/10/01"

  validation {
    condition     = can(regex("^\\d{4}/\\d{2}/\\d{2}$", var.projection_start_date))
    error_message = "Format yyyy/MM/dd."
  }
}

# --- WAF logs (modules/log-archive waf-logs.tf, modules/edge) -----------------
variable "enable_waf_logs" {
  description = "Create the waf_logs Glue table. A plan-time bool (the bucket name comes from another module's resource)."
  type        = bool
  default     = false
}

variable "waf_log_bucket_name" {
  description = "modules/log-archive waf_log_bucket_name (aws-waf-logs-*). Required with enable_waf_logs."
  type        = string
  default     = ""

  validation {
    condition     = !var.enable_waf_logs || startswith(coalesce(var.waf_log_bucket_name, "-"), "aws-waf-logs-")
    error_message = "With enable_waf_logs, waf_log_bucket_name must be the aws-waf-logs-* bucket."
  }
}

variable "waf_web_acl_names" {
  description = "Web ACL names that log to the WAF bucket (modules/edge web_acl_names): the webacl partition enum."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for n in var.waf_web_acl_names : can(regex("^[A-Za-z0-9_-]{1,128}$", n))])
    error_message = "Web ACL names: letters, digits, '-' and '_' (1-128)."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
