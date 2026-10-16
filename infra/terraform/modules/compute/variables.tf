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
  description = "Tag that marks a resource as in scope for SOAR automation. Applied to the report-worker (and its volume) and, only with soar_scope_app_service, to the docs-api service and its tasks."
  type        = map(string)
  default     = { "cloudshield:soar-scope" = "in-scope" }

  validation {
    condition     = length(var.soar_scope_tag) == 1
    error_message = "Exactly one scope tag key/value pair."
  }
}

# ---------------- PB-04 prerequisites (Phase D) ----------------
variable "soar_scope_app_service" {
  description = "Put the SOAR scope tag on the docs-api ECS service (propagated to its tasks), making them PB-04 targets. Off by default: auto-stopping production tasks is opt-in."
  type        = bool
  default     = false
}

variable "guardduty_agent_ecr_repository_arns" {
  description = "GuardDuty Runtime Monitoring Fargate agent repositories the execution role may pull from (per-region ARNs from the GuardDuty docs). Empty = this repository only."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.guardduty_agent_ecr_repository_arns : can(regex("^arn:aws[a-z-]*:ecr:[a-z0-9-]+:\\d{12}:repository/aws-guardduty-agent-fargate$", a))])
    error_message = "Each entry must be a GuardDuty agent ECR repository ARN (…:repository/aws-guardduty-agent-fargate)."
  }
}

# ---------------- CI image push (gap 9, decision D7) ----------------
variable "github_oidc_provider_arn" {
  description = "bootstrap output github_oidc_provider_arn. null = no CI push role."
  type        = string
  default     = null

  validation {
    condition     = var.github_oidc_provider_arn == null || can(regex("^arn:aws[a-z-]*:iam::\\d{12}:oidc-provider/token\\.actions\\.githubusercontent\\.com$", var.github_oidc_provider_arn))
    error_message = "Must be the GitHub Actions OIDC provider ARN (…:oidc-provider/token.actions.githubusercontent.com)."
  }
}

variable "github_repository" {
  description = "owner/repo whose workflow may push images. Case-sensitive, exact."
  type        = string
  default     = "ELSHAHALY/Cloud-Shield"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$", var.github_repository))
    error_message = "github_repository must be owner/repo, with no wildcards."
  }
}

variable "ecr_push_branch" {
  description = "The only branch allowed to push (exact match on the OIDC sub claim)."
  type        = string
  default     = "main"

  validation {
    condition     = can(regex("^[A-Za-z0-9._/-]{1,100}$", var.ecr_push_branch)) && !strcontains(var.ecr_push_branch, "*")
    error_message = "ecr_push_branch must be a plain branch name, with no wildcards."
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
