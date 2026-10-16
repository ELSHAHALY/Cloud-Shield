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

# -----------------------------------------------------------------------------
# Phase D: PB-04 (ECS task containment) and PB-05 (WAF IP block). Both are
# plan-time bools (D6) and need playbook_package as well. Off by default.
# -----------------------------------------------------------------------------
variable "enable_pb04" {
  description = "Create PB-04 (stop a compromised ECS task + redeploy its service). Dev sets it only with a container image, GuardDuty Runtime Monitoring and the scope-tagged app service (D19, F20)."
  type        = bool
  default     = false
}

variable "ecs_cluster_name" {
  description = "PB-04: the only ECS cluster it may act in (IAM ARNs are built from it)."
  type        = string
  default     = null

  validation {
    condition     = !var.enable_pb04 || can(regex("^[A-Za-z0-9_-]{1,255}$", var.ecs_cluster_name))
    error_message = "enable_pb04 needs ecs_cluster_name (1-255 letters, digits, - or _)."
  }
}

variable "ecs_cluster_arn" {
  description = "PB-04: ARN of ecs_cluster_name (the ecs:cluster condition value and ECS_CLUSTER_ARN)."
  type        = string
  default     = null

  validation {
    condition     = !var.enable_pb04 || var.ecs_cluster_arn != null
    error_message = "enable_pb04 needs ecs_cluster_arn."
  }
}

variable "ecs_service_names" {
  description = "PB-04: the only ECS services it may redeploy (and whose tasks it may stop)."
  type        = list(string)
  default     = []

  validation {
    condition     = !var.enable_pb04 || length(var.ecs_service_names) > 0
    error_message = "enable_pb04 needs at least one ECS service name."
  }
  validation {
    condition     = alltrue([for s in var.ecs_service_names : can(regex("^[A-Za-z0-9_-]{1,255}$", s))])
    error_message = "ECS service names are 1-255 letters, digits, - or _."
  }
}

variable "enable_pb05" {
  description = "Create PB-05 (block a client IP in the CloudFront WAF), the dedicated edge bus, the never-block list and the rate-rule harvester. Requires us-east-1 (F2)."
  type        = bool
  default     = false
}

variable "block_ip_set_arns" {
  description = "PB-05: the two CLOUDFRONT-scope IP sets it may append to (modules/edge block_ip_set_arns, v4 and v6)."
  type        = list(string)
  default     = []

  validation {
    condition     = !var.enable_pb05 || length(var.block_ip_set_arns) == 2
    error_message = "enable_pb05 needs exactly the two PB-05 IP set ARNs (IPv4 and IPv6)."
  }
}

variable "waf_web_acl" {
  description = "PB-05 harvester: the CloudFront web ACL holding the rate rule (modules/edge cloudfront_web_acl)."
  type = object({
    name = string
    id   = string
    arn  = string
  })
  default = null

  validation {
    condition     = !var.enable_pb05 || var.waf_web_acl != null
    error_message = "enable_pb05 needs waf_web_acl."
  }
}

variable "waf_rate_rule_name" {
  description = "PB-05 harvester: name of the per-IP rate-based rule (modules/edge rate_rule_name)."
  type        = string
  default     = "RateLimitPerIp"
}

variable "pb05_publisher_arns" {
  description = "IAM role ARNs allowed to publish onto the edge bus besides the harvester (Phase E: the docs-api task role; optionally an operator replay role). Everyone else is explicitly denied."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.pb05_publisher_arns : can(regex("^arn:aws[a-zA-Z-]*:iam::[0-9]{12}:role/", a))])
    error_message = "pb05_publisher_arns must be IAM role ARNs."
  }
}

variable "pb05_never_block_cidrs" {
  description = "Operator CIDRs PB-05 must never block (added to the NAT EIP /32 in the never-block SSM parameter)."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for c in var.pb05_never_block_cidrs : can(cidrhost(c, 0))])
    error_message = "pb05_never_block_cidrs must be CIDRs (e.g. 198.51.100.7/32)."
  }
}

variable "nat_public_ip" {
  description = "The VPC's NAT egress IP (modules/network nat_public_ip); seeded into the never-block list."
  type        = string
  default     = null

  validation {
    condition     = var.nat_public_ip == null || can(cidrhost("${var.nat_public_ip}/32", 0))
    error_message = "nat_public_ip must be an IPv4 address."
  }
}

variable "pb05_block_ttl_hours" {
  description = "blockExpiresAt = block time + this. Nothing lifts a block automatically (D15)."
  type        = number
  default     = 24

  validation {
    condition     = var.pb05_block_ttl_hours >= 1 && var.pb05_block_ttl_hours <= 168 && floor(var.pb05_block_ttl_hours) == var.pb05_block_ttl_hours
    error_message = "pb05_block_ttl_hours must be a whole number from 1 to 168."
  }
}

variable "pb05_ip_set_max" {
  description = "PB-05 refuses to grow an IP set beyond this many entries (WAF allows 10,000; F23)."
  type        = number
  default     = 1000

  validation {
    condition     = var.pb05_ip_set_max >= 1 && var.pb05_ip_set_max <= 9000 && floor(var.pb05_ip_set_max) == var.pb05_ip_set_max
    error_message = "pb05_ip_set_max must be a whole number from 1 to 9000."
  }
}

variable "pb05_harvest_schedule" {
  description = "Optional extra harvester trigger, e.g. \"rate(5 minutes)\", for IPs that become rate-limited while the alarm is already in ALARM. null = alarm transitions only."
  type        = string
  default     = null

  validation {
    condition     = var.pb05_harvest_schedule == null || can(regex("^(rate|cron)[(].+[)]$", var.pb05_harvest_schedule))
    error_message = "pb05_harvest_schedule must be an EventBridge rate(...) or cron(...) expression."
  }
}
