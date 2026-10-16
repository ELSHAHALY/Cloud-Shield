# Policy-content tests. edge.tftest.hcl mocks the provider, which renders
# every aws_iam_policy_document as a fixed empty document. Here the REAL
# provider renders them locally (no API calls): identity and CloudFront
# managed-policy lookups are overridden, and EVERY managed resource is
# overridden, so `apply` never calls AWS (pattern: modules/soar/tests/iam.tftest.hcl).
# A new resource added to the module without an override here fails this test
# with an auth error, never by touching an account.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "mock"
  secret_key                  = "mock"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

override_data {
  target = data.aws_caller_identity.current
  values = { account_id = "123456789012" }
}
override_data {
  target = data.aws_region.current
  values = { region = "us-east-1" }
}
override_data {
  target = data.aws_partition.current
  values = { partition = "aws" }
}
override_data {
  target = data.aws_cloudfront_cache_policy.caching_optimized
  values = {}
}
override_data {
  target = data.aws_cloudfront_cache_policy.caching_disabled
  values = {}
}
override_data {
  target = data.aws_cloudfront_origin_request_policy.all_viewer_except_host
  values = {}
}

# --- main.tf / spa.tf ---------------------------------------------------------
override_resource {
  target = aws_kms_key.edge
  values = { arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000", key_id = "00000000-0000-0000-0000-000000000000" }
}
override_resource {
  target = aws_kms_alias.edge
}
override_resource {
  target = aws_kms_key_policy.edge
}
override_resource {
  target = aws_s3_bucket.spa
  values = { arn = "arn:aws:s3:::cs-test-spa-123456789012", bucket = "cs-test-spa-123456789012", bucket_regional_domain_name = "cs-test-spa-123456789012.s3.us-east-1.amazonaws.com" }
}
override_resource {
  target = aws_s3_bucket_versioning.spa
}
override_resource {
  target = aws_s3_bucket_server_side_encryption_configuration.spa
}
override_resource {
  target = aws_s3_bucket_public_access_block.spa
}
override_resource {
  target = aws_s3_bucket_ownership_controls.spa
}
override_resource {
  target = aws_s3_bucket_lifecycle_configuration.spa
}
override_resource {
  target = aws_s3_bucket_policy.spa
}
override_resource {
  target = aws_cloudfront_origin_access_control.spa
}
override_resource {
  target = aws_cloudfront_function.spa_rewrite
  values = { arn = "arn:aws:cloudfront::123456789012:function/cs-test-spa-rewrite" }
}

# --- waf.tf ---------------------------------------------------------------------
override_resource {
  target = aws_wafv2_ip_set.soar_blocked_v4
  values = { arn = "arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v4/11111111-1111-1111-1111-111111111111" }
}
override_resource {
  target = aws_wafv2_ip_set.soar_blocked_v6
  values = { arn = "arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v6/22222222-2222-2222-2222-222222222222" }
}
override_resource {
  target = aws_wafv2_web_acl.cloudfront
  values = { arn = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/cs-test-cloudfront/33333333-3333-3333-3333-333333333333" }
}
override_resource {
  target = aws_wafv2_web_acl.api
  values = { arn = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/cs-test-api/44444444-4444-4444-4444-444444444444" }
}
override_resource {
  target = aws_wafv2_web_acl_association.api
}
override_resource {
  target = aws_wafv2_web_acl_logging_configuration.cloudfront
}
override_resource {
  target = aws_wafv2_web_acl_logging_configuration.api
}

# --- cdn.tf ---------------------------------------------------------------------
override_resource {
  target = aws_cloudfront_response_headers_policy.security
}
override_resource {
  target = aws_cloudfront_distribution.this
  values = { arn = "arn:aws:cloudfront::123456789012:distribution/E0000000000000" }
}

# --- api.tf ---------------------------------------------------------------------
override_resource {
  target = aws_api_gateway_rest_api.this
  values = { id = "a1b2c3d4e5", root_resource_id = "r00t000000" }
}
override_resource {
  target = aws_api_gateway_vpc_link.this
}
override_resource {
  target = aws_api_gateway_authorizer.cognito
}
override_resource {
  target = aws_api_gateway_resource.api
}
override_resource {
  target = aws_api_gateway_resource.healthz
}
override_resource {
  target = aws_api_gateway_resource.proxy
}
override_resource {
  target = aws_api_gateway_method.healthz
}
override_resource {
  target = aws_api_gateway_method.proxy
}
override_resource {
  target = aws_api_gateway_integration.healthz
}
override_resource {
  target = aws_api_gateway_integration.proxy
}
override_resource {
  target = aws_api_gateway_deployment.this
}
override_resource {
  target = aws_cloudwatch_log_group.execution
  values = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:API-Gateway-Execution-Logs_a1b2c3d4e5/v1" }
}
override_resource {
  target = aws_cloudwatch_log_group.access
  values = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/cs-test/edge/api-access" }
}
override_resource {
  target = aws_api_gateway_stage.v1
  values = { arn = "arn:aws:apigateway:us-east-1::/restapis/a1b2c3d4e5/stages/v1" }
}
override_resource {
  target = aws_api_gateway_method_settings.all
}
override_resource {
  target = aws_iam_role.apigw_cloudwatch
  values = { arn = "arn:aws:iam::123456789012:role/cs-test-apigw-cloudwatch" }
}
override_resource {
  target = aws_iam_role_policy_attachment.apigw_cloudwatch
}
override_resource {
  target = aws_api_gateway_account.this
}

variables {
  name                  = "cs-test"
  waf_log_bucket_arn    = "arn:aws:s3:::aws-waf-logs-cs-test-123456789012"
  enable_api            = true
  nlb_arn               = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/cs-test-api-nlb/0123456789abcdef"
  nlb_dns_name          = "cs-test-api-nlb-0123456789abcdef.elb.us-east-1.amazonaws.com"
  cognito_user_pool_arn = "arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_AbCdEfGhI"
}

run "spa_bucket_readable_only_by_this_distribution" {
  command = apply

  assert {
    condition     = toset([for s in jsondecode(data.aws_iam_policy_document.spa_bucket.json).Statement : s.Sid]) == toset(["DenyInsecureTransport", "AllowCloudFrontOacRead"])
    error_message = "SPA bucket policy: TLS deny + the OAC read only."
  }
  assert {
    condition = one([
      for s in jsondecode(data.aws_iam_policy_document.spa_bucket.json).Statement : s if s.Sid == "AllowCloudFrontOacRead"
      ]) == {
      Sid       = "AllowCloudFrontOacRead"
      Effect    = "Allow"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::cs-test-spa-123456789012/*"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Condition = { StringEquals = { "AWS:SourceArn" = "arn:aws:cloudfront::123456789012:distribution/E0000000000000" } }
    }
    error_message = "Only s3:GetObject, only for CloudFront acting for THIS distribution."
  }
}

run "edge_key_policy_is_scoped" {
  command = apply

  assert {
    condition     = toset([for s in jsondecode(data.aws_iam_policy_document.edge_kms.json).Statement : s.Sid]) == toset(["AccountAdmin", "AllowCloudFrontDecryptForThisDistribution", "CloudWatchLogsForEdgeLogGroupsOnly"])
    error_message = "Edge key policy: admin, CloudFront decrypt, CloudWatch Logs — nothing else."
  }
  assert {
    condition = one([
      for s in jsondecode(data.aws_iam_policy_document.edge_kms.json).Statement : s if s.Sid == "AllowCloudFrontDecryptForThisDistribution"
      ]) == {
      Sid       = "AllowCloudFrontDecryptForThisDistribution"
      Effect    = "Allow"
      Action    = "kms:Decrypt"
      Resource  = "*"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Condition = { StringEquals = { "AWS:SourceArn" = "arn:aws:cloudfront::123456789012:distribution/E0000000000000" } }
    }
    error_message = "CloudFront may only Decrypt, only for this distribution."
  }
  assert {
    condition = toset(one([
      for s in jsondecode(data.aws_iam_policy_document.edge_kms.json).Statement : s if s.Sid == "CloudWatchLogsForEdgeLogGroupsOnly"
      ]).Condition.ArnLike["kms:EncryptionContext:aws:logs:arn"]) == toset([
      "arn:aws:logs:us-east-1:123456789012:log-group:/cs-test/edge/*",
      "arn:aws:logs:us-east-1:123456789012:log-group:API-Gateway-Execution-Logs_*",
    ])
    error_message = "CloudWatch Logs may use the key only for the two edge log-group patterns."
  }
  assert {
    condition = one([
      for s in jsondecode(data.aws_iam_policy_document.edge_kms.json).Statement : s if s.Sid == "CloudWatchLogsForEdgeLogGroupsOnly"
    ]).Principal.Service == "logs.us-east-1.amazonaws.com"
    error_message = "Only the regional CloudWatch Logs service principal."
  }
}

run "api_gateway_logging_role_trust" {
  command = apply

  assert {
    condition     = one(jsondecode(data.aws_iam_policy_document.apigw_trust.json).Statement).Principal.Service == "apigateway.amazonaws.com" && one(jsondecode(data.aws_iam_policy_document.apigw_trust.json).Statement).Action == "sts:AssumeRole"
    error_message = "Only API Gateway may assume the CloudWatch logging role."
  }
  assert {
    condition     = !can(one(jsondecode(data.aws_iam_policy_document.apigw_trust.json).Statement).Condition)
    error_message = "No trust conditions until verified on apply (HANDOFF M3; verify-on-apply item 6)."
  }
  assert {
    condition     = aws_iam_role_policy_attachment.apigw_cloudwatch[0].policy_arn == "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
    error_message = "The logging role carries only the AWS push-to-CloudWatch policy."
  }
}
