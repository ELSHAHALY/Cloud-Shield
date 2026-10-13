variable "name" {
  description = "Name prefix (e.g. cloudshield-dev). Also the bucket-name prefix PB-03 is allowed to touch."
  type        = string
}

variable "quarantine_security_group_id" {
  description = "modules/network output — PB-01 swaps compromised instances onto it."
  type        = string
}

variable "quarantine_network_acl_ids" {
  description = "modules/network output — the only NACLs PB-01 may add quarantine deny entries to (cuts established connections the SG swap leaves alive). Empty = PB-01 cannot isolate and fails closed."
  type        = list(string)
  default     = []
}

variable "quarantine_nacl_rule_number" {
  description = "Rule number PB-01 uses for its deny-all ingress + egress entries. Must be below the worker NACL's allow rules (100)."
  type        = number
  default     = 10

  validation {
    condition     = var.quarantine_nacl_rule_number >= 1 && var.quarantine_nacl_rule_number < 100
    error_message = "Must be 1-99 so the deny is evaluated before the allow at 100."
  }
}

variable "notification_emails" {
  description = "Analyst emails subscribed to the incident topic. Each must confirm the AWS subscription email. Empty = no subscriptions (topic still created)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for e in var.notification_emails : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", e))])
    error_message = "notification_emails must be valid email addresses."
  }
}

variable "dry_run" {
  description = "Global SOAR dry-run switch (SSM parameter read by the safety guard). true = playbooks record what they WOULD do and change nothing. Default true: automation must be turned on deliberately."
  type        = bool
  default     = true
}

variable "min_severity" {
  description = "Lowest GuardDuty severity routed to SOAR. 7.0 = High and above."
  type        = number
  default     = 7

  validation {
    condition     = var.min_severity >= 1 && var.min_severity <= 10
    error_message = "GuardDuty severities range from 1.0 to 10.0."
  }
}

variable "always_route_finding_types" {
  description = "GuardDuty finding types routed to SOAR regardless of min_severity (EventBridge content-filter list: strings or {prefix=...})."
  # `any`, not list(any): the list mixes strings and {prefix=…} objects,
  # which a typed list would reject.
  type = any
  default = [
    "Recon:EC2/Portscan",
    { prefix = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration" },
    { prefix = "Policy:S3/" },
  ]
}

variable "soar_scope_tag" {
  description = "Tag that marks a resource in scope for automation. The safety guard refuses anything without it; IAM conditions enforce the same rule."
  type        = map(string)
  default     = { "cloudshield:soar-scope" = "in-scope" }

  validation {
    condition     = length(var.soar_scope_tag) == 1
    error_message = "Exactly one scope tag key/value pair."
  }
}

variable "playbook_package" {
  description = "Lambda deployment zip of the soar/ package in S3. null = no Lambdas and no state machine are created; GuardDuty findings go straight to SNS."
  type = object({
    s3_bucket         = string
    s3_key            = string
    s3_object_version = optional(string)
  })
  default = null
}

variable "revocable_role_arns" {
  description = "IAM roles whose sessions PB-01 may revoke (e.g. the report-worker instance role, whose credentials scenario A steals)."
  type        = list(string)
  default     = []
}

variable "evidence_force_destroy" {
  description = "Allow destroying the evidence bucket with objects in it. true for the lab; false before the graded run."
  type        = bool
  default     = true
}

variable "evidence_object_lock_days" {
  description = "0 = off. >0 = GOVERNANCE retention on evidence (chain of custody) — blocks teardown for that long. Only settable at bucket creation."
  type        = number
  default     = 0

  validation {
    condition     = var.evidence_object_lock_days >= 0
    error_message = "Must be 0 (disabled) or a positive number of days."
  }
}

variable "lambda_reserved_concurrency" {
  description = "Per-playbook concurrency cap (R2: a finding storm must not become an automation storm). -1 = unreserved. New accounts often have a total limit of 10, and AWS refuses ANY reservation that leaves fewer than 100 unreserved, so set 5 only after `aws lambda get-account-settings` shows ConcurrentExecutions >= 120."
  type        = number
  default     = -1

  validation {
    condition     = var.lambda_reserved_concurrency == -1 || var.lambda_reserved_concurrency >= 1
    error_message = "Use -1 (unreserved) or a positive cap."
  }
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "extra_notify_rule_names" {
  description = "Names of other EventBridge rules in this account allowed to publish to the incidents topic (notify only, never the router)."
  type        = list(string)
  default     = []
}

variable "tags" {
  type    = map(string)
  default = {}
}
