variable "name" {
  description = "Name prefix (e.g. cloudshield-dev)."
  type        = string
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid CIDR block."
  }
}

variable "azs" {
  description = "Exactly two AZs (plan §3.3: workload spans two AZs)."
  type        = list(string)

  validation {
    condition     = length(var.azs) == 2
    error_message = "The design is a two-AZ layout; provide exactly 2 AZs."
  }
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.20.0.0/24", "10.20.1.0/24"]
}

variable "private_app_subnet_cidrs" {
  type    = list(string)
  default = ["10.20.10.0/24", "10.20.11.0/24"]
}

variable "private_worker_subnet_cidrs" {
  type    = list(string)
  default = ["10.20.20.0/24", "10.20.21.0/24"]
}

variable "forensics_subnet_cidr" {
  type    = string
  default = "10.20.99.0/26"
}

variable "flow_logs_destination_arn" {
  description = "S3 ARN (with prefix) for flow logs — output of modules/log-archive."
  type        = string

  validation {
    condition     = startswith(var.flow_logs_destination_arn, "arn:")
    error_message = "Must be an S3 ARN, e.g. arn:aws:s3:::bucket/vpc-flow-logs/."
  }
}

variable "enable_interface_endpoints" {
  description = "Create SSM/ECR/Logs/STS interface endpoints. ~US$100/month for 2 AZs; leave false in the lab."
  type        = bool
  default     = false
}

variable "app_port" {
  description = "Container port of the docs API (NLB target port)."
  type        = number
  default     = 3000

  validation {
    condition     = var.app_port >= 1024 && var.app_port <= 65535
    error_message = "Use an unprivileged port (1024-65535); the container runs as non-root."
  }
}

variable "nlb_listener_port" {
  description = "Internal NLB listener port (API Gateway VPC Link target)."
  type        = number
  default     = 80
}

variable "allow_worker_lab_scan" {
  description = "LAB ONLY: let the report-worker reach all TCP ports inside the VPC for attack scenario A (T1046). Keep false outside the attack window."
  type        = bool
  default     = false
}

variable "tags" {
  type    = map(string)
  default = {}
}
