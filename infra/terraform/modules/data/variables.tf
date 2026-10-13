variable "name" {
  description = "Name prefix (e.g. cloudshield-dev)."
  type        = string
}

variable "app_task_role_name" {
  description = "ECS task role (modules/compute output task_role_name) that receives data-plane access."
  type        = string
}

variable "documents_bucket_force_destroy" {
  description = "Allow destroying the documents bucket while it holds objects (lab teardown)."
  type        = bool
  default     = true
}

variable "table_deletion_protection" {
  description = "DynamoDB deletion protection. false in the lab so teardown works; true before the graded demo."
  type        = bool
  default     = false
}

variable "presigned_url_max_seconds" {
  description = "Upper bound the app should use for S3 pre-signed URLs (flow 6 in Figure 7.1). Exposed to the app as config, enforced by bucket policy."
  type        = number
  default     = 300

  validation {
    condition     = var.presigned_url_max_seconds >= 60 && var.presigned_url_max_seconds <= 3600
    error_message = "Keep pre-signed URLs between 60 s and 1 h."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
