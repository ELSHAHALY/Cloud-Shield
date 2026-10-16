variable "name" {
  description = "Name prefix (e.g. cloudshield-dev)."
  type        = string
}

variable "mfa_configuration" {
  description = "ON (every user enrols TOTP) or OPTIONAL. OFF is not allowed."
  type        = string
  default     = "ON"

  validation {
    condition     = contains(["ON", "OPTIONAL"], var.mfa_configuration)
    error_message = "mfa_configuration must be ON or OPTIONAL; OFF is rejected."
  }
}

variable "user_pool_tier" {
  description = "Cognito feature plan. ESSENTIALS covers the lab; threat protection needs PLUS (F15)."
  type        = string
  default     = "ESSENTIALS"

  validation {
    condition     = contains(["LITE", "ESSENTIALS", "PLUS"], var.user_pool_tier)
    error_message = "user_pool_tier must be LITE, ESSENTIALS or PLUS."
  }
}

variable "threat_protection_mode" {
  description = "Cognito threat protection (advanced security): OFF, AUDIT or ENFORCED. Anything but OFF needs user_pool_tier = PLUS."
  type        = string
  default     = "OFF"

  validation {
    condition     = contains(["OFF", "AUDIT", "ENFORCED"], var.threat_protection_mode)
    error_message = "threat_protection_mode must be OFF, AUDIT or ENFORCED."
  }
  validation {
    condition     = var.threat_protection_mode == "OFF" || var.user_pool_tier == "PLUS"
    error_message = "Threat protection (AUDIT/ENFORCED) requires user_pool_tier = PLUS."
  }
}

variable "deletion_protection" {
  description = "Block deleting the user pool (and every user in it)."
  type        = bool
  default     = true
}

variable "access_token_minutes" {
  description = "Access and ID token lifetime."
  type        = number
  default     = 60

  validation {
    condition     = var.access_token_minutes >= 5 && var.access_token_minutes <= 60
    error_message = "access_token_minutes must be between 5 and 60."
  }
}

variable "refresh_token_days" {
  type    = number
  default = 1

  validation {
    condition     = var.refresh_token_days >= 1 && var.refresh_token_days <= 30
    error_message = "refresh_token_days must be between 1 and 30."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
