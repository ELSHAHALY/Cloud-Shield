variable "project_name" {
  description = "Prefix for every resource name."
  type        = string
  default     = "cloudshield"
}

variable "aws_region" {
  description = "Single region by design (plan §1.2)."
  type        = string
  default     = "us-east-1"
}

variable "github_repository" {
  description = "owner/repo allowed to assume the CI role via OIDC. Must match exactly (case-sensitive)."
  type        = string
  default     = "ELSHAHALY/Cloud-Shield"
}

variable "monthly_budget_usd" {
  description = "Monthly budget limit. Alerts fire at 50% and 100% actual, and 100% forecast. Set to your real allowance (plan gap G4)."
  type        = number
  default     = 100
}

variable "budget_alert_emails" {
  description = "Who receives budget alerts. Use the whole team."
  type        = list(string)

  validation {
    condition     = length(var.budget_alert_emails) > 0
    error_message = "Provide at least one email for budget alerts."
  }
}
