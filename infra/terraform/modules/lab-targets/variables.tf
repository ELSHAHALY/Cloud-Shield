variable "name" {
  description = "Name prefix. Must equal the SOAR bucket prefix (modules/soar BUCKET_NAME_PREFIX = \"<name>-\") so PB-03 may act on the lab bucket."
  type        = string
}

variable "soar_scope_tag" {
  description = "The SOAR scope tag (same map passed to modules/soar)."
  type        = map(string)

  validation {
    condition     = length(var.soar_scope_tag) == 1
    error_message = "Exactly one scope tag key/value pair."
  }
}

variable "soar_target_boundary_arn" {
  description = "modules/soar target_permissions_boundary_arn. Required on the honeytoken user: PB-02 may only revoke sessions of users that carry it."
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
