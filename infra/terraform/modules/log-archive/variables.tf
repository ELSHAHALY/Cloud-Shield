variable "name" {
  description = "Name prefix (e.g. cloudshield-dev)."
  type        = string
}

variable "force_destroy" {
  description = "Allow terraform destroy to delete a non-empty bucket. true for the lab (cost teardown), false anywhere evidence must survive."
  type        = bool
  default     = false
}

variable "object_lock_retention_days" {
  description = "0 disables Object Lock. >0 enables GOVERNANCE-mode retention (immutable logs) but blocks teardown for that many days. Can only be turned on at bucket creation."
  type        = number
  default     = 0

  validation {
    condition     = var.object_lock_retention_days >= 0
    error_message = "Must be 0 (disabled) or a positive number of days."
  }
}

variable "glacier_transition_days" {
  description = "Days before objects move to Glacier Instant Retrieval (still Athena-queryable)."
  type        = number
  default     = 90
}

variable "expiration_days" {
  description = "Days before log objects are deleted."
  type        = number
  default     = 365

  validation {
    condition     = var.expiration_days > var.glacier_transition_days
    error_message = "expiration_days must be greater than glacier_transition_days."
  }
}

variable "tags" {
  description = "Extra tags (provider default_tags already apply Project/Environment/ManagedBy)."
  type        = map(string)
  default     = {}
}
