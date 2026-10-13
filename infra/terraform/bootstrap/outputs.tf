output "state_bucket" {
  description = "Put this in environments/*/backend.hcl"
  value       = aws_s3_bucket.tfstate.bucket
}

output "state_kms_key_arn" {
  description = "Put this in environments/*/backend.hcl as kms_key_id"
  value       = aws_kms_key.tfstate.arn
}

output "gha_plan_role_arn" {
  description = "Set as the GitHub repository variable AWS_PLAN_ROLE_ARN"
  value       = aws_iam_role.gha_plan.arn
}
