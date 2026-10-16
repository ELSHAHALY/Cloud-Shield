# The execute-api URL is deliberately NOT output: the API is meant to be
# reached only through CloudFront. The origin-verify secret is never output.

output "cloudfront_domain_name" {
  description = "https://<this> is the app URL (CI variable STAGING_URL)."
  value       = aws_cloudfront_distribution.this.domain_name
}

output "distribution_id" {
  value = aws_cloudfront_distribution.this.id
}

output "distribution_arn" {
  value = aws_cloudfront_distribution.this.arn
}

output "spa_bucket_name" {
  description = "Upload the SPA build here (SSE-KMS with the edge key)."
  value       = aws_s3_bucket.spa.bucket
}

output "kms_key_arn" {
  description = "Edge key: SPA objects and API Gateway log groups."
  value       = aws_kms_key.edge.arn
}

output "cloudfront_web_acl" {
  description = "PB-05 harvester target (stage 2b)."
  value = {
    name = aws_wafv2_web_acl.cloudfront.name
    id   = aws_wafv2_web_acl.cloudfront.id
    arn  = aws_wafv2_web_acl.cloudfront.arn
  }
}

output "api_web_acl_arn" {
  description = "null without enable_api."
  value       = one(aws_wafv2_web_acl.api[*].arn)
}

output "web_acl_names" {
  description = "Names of the web ACLs that log to S3 (modules/detection waf_web_acl_names)."
  value       = concat([aws_wafv2_web_acl.cloudfront.name], aws_wafv2_web_acl.api[*].name)
}

output "rate_rule_name" {
  description = "Name of the per-IP rate-based rule on the CloudFront ACL (PB-05 harvester)."
  value       = local.rate_rule_name
}

output "block_ip_set_arns" {
  description = "PB-05 block lists (CLOUDFRONT scope, us-east-1)."
  value = {
    v4 = aws_wafv2_ip_set.soar_blocked_v4.arn
    v6 = aws_wafv2_ip_set.soar_blocked_v6.arn
  }
}

output "rest_api_id" {
  description = "null without enable_api."
  value       = one(aws_api_gateway_rest_api.this[*].id)
}
