variable "name" {
  description = "Name prefix (e.g. cloudshield-dev)."
  type        = string
}

# ---------------- API (D6: plan-time bool) ----------------
variable "enable_api" {
  description = "Create the REST API, VPC Link, regional WAF and the /api/* behaviour. A plan-time bool: the NLB ARN is unknown (not null) while it is being created (F4)."
  type        = bool
  default     = false
}

variable "nlb_arn" {
  description = "modules/compute nlb_arn (VPC Link target). Required with enable_api."
  type        = string
  default     = null

  validation {
    condition     = !var.enable_api || var.nlb_arn != null
    error_message = "enable_api needs nlb_arn (modules/compute with a container image)."
  }
}

variable "nlb_dns_name" {
  description = "modules/compute nlb_dns_name (integration URI host). Required with enable_api."
  type        = string
  default     = null

  validation {
    condition     = !var.enable_api || var.nlb_dns_name != null
    error_message = "enable_api needs nlb_dns_name."
  }
}

variable "nlb_listener_port" {
  type    = number
  default = 80
}

variable "cognito_user_pool_arn" {
  description = "modules/identity user_pool_arn (REST API authorizer). Required with enable_api."
  type        = string
  default     = null

  validation {
    condition     = !var.enable_api || var.cognito_user_pool_arn != null
    error_message = "enable_api needs cognito_user_pool_arn (modules/identity)."
  }
}

variable "api_throttle_burst" {
  type    = number
  default = 50
}

variable "api_throttle_rate" {
  type    = number
  default = 20
}

variable "manage_apigw_account_role" {
  description = "Manage the account-level API Gateway CloudWatch role (a regional singleton, F6). false if the account already has one."
  type        = bool
  default     = true
}

# ---------------- WAF ----------------
variable "waf_log_bucket_arn" {
  description = "modules/log-archive waf_log_bucket_arn. WAF only logs to buckets named aws-waf-logs-* (F1)."
  type        = string

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:s3:::aws-waf-logs-[a-z0-9.-]+$", var.waf_log_bucket_arn))
    error_message = "waf_log_bucket_arn must be the ARN of a bucket whose name starts with aws-waf-logs-."
  }
}

variable "waf_rate_limit" {
  description = "Requests per client IP per 5 minutes before the CloudFront ACL answers 429."
  type        = number
  default     = 300

  validation {
    condition     = var.waf_rate_limit >= 10 && var.waf_rate_limit <= 2000000
    error_message = "waf_rate_limit must be between 10 and 2,000,000 (WAF limits)."
  }
}

variable "waf_api_rate_limit" {
  description = "Requests per client IP per 5 minutes to /api/* before the PB-05-feeding SoarApiRateLimit rule answers 429. Only this rule's rate-limited addresses can become PB-05 blocks (and only after two consecutive harvests)."
  type        = number
  default     = 200

  validation {
    condition     = var.waf_api_rate_limit >= 10 && var.waf_api_rate_limit <= 2000000
    error_message = "waf_api_rate_limit must be between 10 and 2,000,000 (WAF limits)."
  }
}

# ---------------- housekeeping ----------------
variable "spa_force_destroy" {
  description = "Allow destroying the SPA bucket while it holds a build (the SPA is a rebuildable artefact; lab teardown)."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "tags" {
  type    = map(string)
  default = {}
}
