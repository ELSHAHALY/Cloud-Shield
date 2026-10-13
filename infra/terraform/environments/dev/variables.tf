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
