variable "name" {
  description = "Name prefix (e.g. cloudshield-dev)."
  type        = string
}

# ---------------- network inputs (from modules/network) ----------------
variable "vpc_id" {
  type = string
}

variable "private_app_subnet_ids" {
  type = list(string)

  validation {
    condition     = length(var.private_app_subnet_ids) == 2
    error_message = "Two private-app subnets expected (two-AZ design)."
  }
}

variable "private_worker_subnet_ids" {
  type = list(string)

  validation {
    condition     = length(var.private_worker_subnet_ids) >= 1
    error_message = "At least one private-worker subnet is required."
  }
}

variable "nlb_security_group_id" {
  type = string
}

variable "app_security_group_id" {
  type = string
}

variable "worker_security_group_id" {
  type = string
}

variable "app_port" {
  type    = number
  default = 3000
}

variable "nlb_listener_port" {
  type    = number
  default = 80
}

# ---------------- feature flag: app service ----------------
variable "container_image" {
  description = "Digest-pinned image (…/repo@sha256:<64 hex>). null = no NLB, task definition or service is created (code not ready yet)."
  type        = string
  default     = null

  validation {
    condition     = var.container_image == null || can(regex("@sha256:[a-f0-9]{64}$", var.container_image))
    error_message = "container_image must be pinned by digest (…@sha256:<64 hex chars>), never by tag: tags are mutable and break the scanned-image guarantee."
  }
}

variable "container_user" {
  description = "UID:GID the container runs as. 1000:1000 is the 'node' user in official Node images."
  type        = string
  default     = "1000:1000"

  validation {
    condition     = !can(regex("^(0|root)(:|$)", var.container_user))
    error_message = "The container must not run as root."
  }
}

variable "container_environment" {
  description = "Non-secret environment variables for the app (table names, bucket, Cognito pool ID…)."
  type        = map(string)
  default     = {}
}

variable "task_cpu" {
  type    = number
  default = 256

  validation {
    condition     = contains([256, 512, 1024], var.task_cpu)
    error_message = "task_cpu must be 256, 512 or 1024 for this lab."
  }
}

variable "task_memory" {
  type    = number
  default = 512
}

variable "desired_count" {
  description = "2 = one task per AZ (plan §3.3)."
  type        = number
  default     = 2
}

variable "health_check_path" {
  type    = string
  default = "/healthz"
}

variable "nlb_deletion_protection" {
  type    = bool
  default = false
}

# ---------------- feature flag: forensic target ----------------
variable "enable_report_worker" {
  description = "Create the EC2 report-worker (PB-01 forensic target). ~US$8/month on t3.micro; destroy nightly (R3)."
  type        = bool
  default     = false
}

variable "report_worker_instance_type" {
  type    = string
  default = "t3.micro"
}

variable "worker_permissions_boundary_arn" {
  description = "modules/soar output target_permissions_boundary_arn. Without it PB-01 cannot revoke the worker role's sessions (by design)."
  type        = string
  default     = null
}

variable "soar_scope_tag" {
  description = "Tag that marks a resource as in scope for SOAR automation. Applied ONLY to the report-worker (and its volume) here."
  type        = map(string)
  default     = { "cloudshield:soar-scope" = "in-scope" }

  validation {
    condition     = length(var.soar_scope_tag) == 1
    error_message = "Exactly one scope tag key/value pair."
  }
}

# ---------------- housekeeping ----------------
variable "ecr_force_delete" {
  description = "Allow destroying the ECR repo while it still holds images (lab teardown)."
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
