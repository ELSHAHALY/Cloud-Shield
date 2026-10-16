# terraform test — offline, mocked AWS provider (no credentials).
# Shape of the edge: WAF rule lists and priorities, PB-05 IP sets, the API
# chain, CloudFront behaviours and headers. Policy CONTENT is tested with the
# real provider in policies.tftest.hcl (the mock renders every document as
# the fixed JSON below).
#
# Single provider: the module uses the F17 fallback (no us_east_1 alias, a
# region precondition instead) — see main.tf.

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }
  mock_data "aws_region" {
    defaults = {
      region = "us-east-1"
    }
  }
  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }
  mock_resource "aws_kms_key" {
    defaults = {
      arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    }
  }
  mock_resource "aws_s3_bucket" {
    defaults = {
      arn                         = "arn:aws:s3:::cs-test-spa-123456789012"
      bucket_regional_domain_name = "cs-test-spa-123456789012.s3.us-east-1.amazonaws.com"
    }
  }
  mock_resource "aws_cloudfront_distribution" {
    defaults = {
      arn         = "arn:aws:cloudfront::123456789012:distribution/E0000000000000"
      domain_name = "d0000000000000.cloudfront.net"
    }
  }
  mock_resource "aws_cloudfront_function" {
    defaults = {
      arn = "arn:aws:cloudfront::123456789012:function/cs-test-spa-rewrite"
    }
  }
  mock_resource "aws_wafv2_web_acl" {
    defaults = {
      arn = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/mock/00000000-0000-0000-0000-000000000000"
    }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-east-1:123456789012:log-group:mock"
    }
  }
  mock_resource "aws_api_gateway_rest_api" {
    defaults = {
      id               = "a1b2c3d4e5"
      root_resource_id = "r00t000000"
    }
  }
  mock_resource "aws_api_gateway_stage" {
    defaults = {
      arn = "arn:aws:apigateway:us-east-1::/restapis/a1b2c3d4e5/stages/v1"
    }
  }
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/mock"
    }
  }
}

# Distinct ARNs, so "references BOTH sets" is a real check.
override_resource {
  target = aws_wafv2_ip_set.soar_blocked_v4
  values = { arn = "arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v4/11111111-1111-1111-1111-111111111111" }
}
override_resource {
  target = aws_wafv2_ip_set.soar_blocked_v6
  values = { arn = "arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v6/22222222-2222-2222-2222-222222222222" }
}
override_resource {
  target = aws_wafv2_web_acl.api
  values = { arn = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/cs-test-api/33333333-3333-3333-3333-333333333333" }
}

variables {
  name               = "cs-test"
  waf_log_bucket_arn = "arn:aws:s3:::aws-waf-logs-cs-test-123456789012"
}

run "defaults_edge_without_api" {
  command = apply

  assert {
    condition     = length(aws_api_gateway_rest_api.this) == 0 && length(aws_api_gateway_vpc_link.this) == 0 && length(aws_wafv2_web_acl.api) == 0
    error_message = "No API, VPC Link or regional ACL without enable_api."
  }
  assert {
    condition     = length(aws_api_gateway_account.this) == 0 && length(aws_wafv2_web_acl_association.api) == 0
    error_message = "No account-level API Gateway role or association without enable_api."
  }
  assert {
    condition     = length(aws_cloudfront_distribution.this.ordered_cache_behavior) == 0 && length(aws_cloudfront_distribution.this.origin) == 1
    error_message = "Only the SPA origin and default behaviour without enable_api."
  }
  assert {
    condition     = output.api_web_acl_arn == null && output.rest_api_id == null
    error_message = "API outputs are null without enable_api."
  }
}

run "cloudfront_acl_rules_and_pb05_ip_sets" {
  command = apply

  assert {
    condition     = aws_wafv2_web_acl.cloudfront.scope == "CLOUDFRONT" && length(aws_wafv2_web_acl.cloudfront.default_action[0].allow) == 1
    error_message = "CloudFront ACL: CLOUDFRONT scope, default allow."
  }
  assert {
    condition = { for r in aws_wafv2_web_acl.cloudfront.rule : tostring(r.priority) => r.name } == {
      "0" = "SoarBlockedIps"
      "1" = "AWSManagedRulesAmazonIpReputationList"
      "2" = "RateLimitPerIp"
      "3" = "AWSManagedRulesCommonRuleSet"
      "4" = "AWSManagedRulesKnownBadInputsRuleSet"
    }
    error_message = "CloudFront ACL rules and priorities must be exactly D4 (PB-05 list first)."
  }
  assert {
    condition = toset([
      for s in one([for r in aws_wafv2_web_acl.cloudfront.rule : r if r.name == "SoarBlockedIps"]).statement[0].or_statement[0].statement :
      s.ip_set_reference_statement[0].arn
      ]) == toset([
      "arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v4/11111111-1111-1111-1111-111111111111",
      "arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v6/22222222-2222-2222-2222-222222222222",
    ])
    error_message = "SoarBlockedIps must reference BOTH PB-05 IP sets."
  }
  assert {
    condition     = length(one([for r in aws_wafv2_web_acl.cloudfront.rule : r if r.name == "SoarBlockedIps"]).action[0].block) == 1
    error_message = "SoarBlockedIps must block."
  }
  assert {
    condition = (
      aws_wafv2_ip_set.soar_blocked_v4.scope == "CLOUDFRONT" && aws_wafv2_ip_set.soar_blocked_v4.ip_address_version == "IPV4" &&
      aws_wafv2_ip_set.soar_blocked_v6.scope == "CLOUDFRONT" && aws_wafv2_ip_set.soar_blocked_v6.ip_address_version == "IPV6"
    )
    error_message = "PB-05 IP sets: CLOUDFRONT scope, one per IP version."
  }
  assert {
    condition     = length(aws_wafv2_ip_set.soar_blocked_v4.addresses) == 0 && length(aws_wafv2_ip_set.soar_blocked_v6.addresses) == 0
    error_message = "PB-05 IP sets start empty (Terraform never manages the addresses)."
  }
  assert {
    condition = (
      one([for r in aws_wafv2_web_acl.cloudfront.rule : r if r.name == "RateLimitPerIp"]).action[0].block[0].custom_response[0].response_code == 429 &&
      one([for r in aws_wafv2_web_acl.cloudfront.rule : r if r.name == "RateLimitPerIp"]).statement[0].rate_based_statement[0].limit == 300 &&
      one([for r in aws_wafv2_web_acl.cloudfront.rule : r if r.name == "RateLimitPerIp"]).statement[0].rate_based_statement[0].aggregate_key_type == "IP" &&
      one([for r in aws_wafv2_web_acl.cloudfront.rule : r if r.name == "RateLimitPerIp"]).statement[0].rate_based_statement[0].evaluation_window_sec == 300
    )
    error_message = "Rate rule: 300 requests per IP per 300 s, blocked with 429."
  }
  assert {
    condition     = alltrue([for r in aws_wafv2_web_acl.cloudfront.rule : r.visibility_config[0].cloudwatch_metrics_enabled && r.visibility_config[0].sampled_requests_enabled])
    error_message = "Metrics and sampled requests on every rule."
  }
  assert {
    condition     = output.block_ip_set_arns.v4 == aws_wafv2_ip_set.soar_blocked_v4.arn && output.block_ip_set_arns.v6 == aws_wafv2_ip_set.soar_blocked_v6.arn && output.rate_rule_name == "RateLimitPerIp"
    error_message = "PB-05 outputs: both IP-set ARNs and the rate rule name."
  }
  assert {
    condition     = toset([for f in aws_wafv2_web_acl_logging_configuration.cloudfront.redacted_fields : f.single_header[0].name]) == toset(["authorization", "cookie", "x-origin-verify"])
    error_message = "WAF logs must redact authorization, cookie and x-origin-verify (D8)."
  }
  assert {
    condition     = aws_wafv2_web_acl_logging_configuration.cloudfront.log_destination_configs == toset(["arn:aws:s3:::aws-waf-logs-cs-test-123456789012"])
    error_message = "The CloudFront ACL logs to the aws-waf-logs-* bucket."
  }
}

run "distribution_spa_behaviour_and_headers" {
  command = apply

  assert {
    condition     = length(aws_cloudfront_distribution.this.custom_error_response) == 0
    error_message = "No custom_error_response: it would turn WAF/API errors into 200 index.html (F11)."
  }
  assert {
    condition = alltrue(concat(
      [aws_cloudfront_distribution.this.default_cache_behavior[0].viewer_protocol_policy != "allow-all"],
      [for b in aws_cloudfront_distribution.this.ordered_cache_behavior : b.viewer_protocol_policy != "allow-all"],
    ))
    error_message = "No behaviour may allow plain HTTP."
  }
  assert {
    condition     = aws_cloudfront_distribution.this.web_acl_id == aws_wafv2_web_acl.cloudfront.arn
    error_message = "The distribution must be protected by the CloudFront ACL."
  }
  assert {
    condition     = one(aws_cloudfront_distribution.this.default_cache_behavior[0].function_association).event_type == "viewer-request" && one(aws_cloudfront_distribution.this.default_cache_behavior[0].function_association).function_arn == aws_cloudfront_function.spa_rewrite.arn
    error_message = "The SPA rewrite function runs on viewer-request of the default behaviour (D10)."
  }
  assert {
    condition     = aws_cloudfront_function.spa_rewrite.runtime == "cloudfront-js-2.0" && strcontains(aws_cloudfront_function.spa_rewrite.code, "/index.html")
    error_message = "SPA rewrite: cloudfront-js-2.0, rewrites to /index.html."
  }
  assert {
    condition     = data.aws_cloudfront_cache_policy.caching_optimized.name == "Managed-CachingOptimized" && aws_cloudfront_distribution.this.default_cache_behavior[0].cache_policy_id == data.aws_cloudfront_cache_policy.caching_optimized.id && aws_cloudfront_distribution.this.default_cache_behavior[0].response_headers_policy_id == aws_cloudfront_response_headers_policy.security.id
    error_message = "SPA: CachingOptimized + the security headers policy."
  }
  assert {
    condition     = one(aws_cloudfront_distribution.this.origin).origin_access_control_id == aws_cloudfront_origin_access_control.spa.id && aws_cloudfront_origin_access_control.spa.signing_behavior == "always" && aws_cloudfront_origin_access_control.spa.signing_protocol == "sigv4"
    error_message = "SPA origin through OAC (SigV4, always sign)."
  }
  assert {
    condition = (
      aws_cloudfront_response_headers_policy.security.security_headers_config[0].strict_transport_security[0].access_control_max_age_sec >= 31536000 &&
      aws_cloudfront_response_headers_policy.security.security_headers_config[0].strict_transport_security[0].include_subdomains &&
      aws_cloudfront_response_headers_policy.security.security_headers_config[0].content_type_options[0].override &&
      aws_cloudfront_response_headers_policy.security.security_headers_config[0].frame_options[0].frame_option == "DENY"
    )
    error_message = "ZAP headers: HSTS >= 1 y with subdomains, nosniff, frame DENY (10035, 10021, 10020)."
  }
  assert {
    condition     = aws_cloudfront_response_headers_policy.security.security_headers_config[0].content_security_policy[0].content_security_policy == "default-src 'self'; connect-src 'self' https://cognito-idp.us-east-1.amazonaws.com; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
    error_message = "CSP must be exactly the planned policy (ZAP 10038, F10)."
  }
  assert {
    condition     = aws_cloudfront_distribution.this.viewer_certificate[0].cloudfront_default_certificate && aws_cloudfront_distribution.this.default_root_object == "index.html"
    error_message = "Default certificate (D11) and index.html root object."
  }
  assert {
    condition     = aws_s3_bucket_public_access_block.spa.block_public_acls && aws_s3_bucket_public_access_block.spa.block_public_policy && aws_s3_bucket_public_access_block.spa.ignore_public_acls && aws_s3_bucket_public_access_block.spa.restrict_public_buckets
    error_message = "SPA bucket must block all public access."
  }
}

run "api_chain_when_enabled" {
  command = apply

  variables {
    enable_api            = true
    nlb_arn               = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/cs-test-api-nlb/0123456789abcdef"
    nlb_dns_name          = "cs-test-api-nlb-0123456789abcdef.elb.us-east-1.amazonaws.com"
    cognito_user_pool_arn = "arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_AbCdEfGhI"
  }

  assert {
    condition     = toset(aws_api_gateway_vpc_link.this[0].target_arns) == toset([var.nlb_arn])
    error_message = "The VPC Link targets exactly the compute NLB."
  }
  assert {
    condition     = toset(aws_api_gateway_rest_api.this[0].endpoint_configuration[0].types) == toset(["REGIONAL"])
    error_message = "REGIONAL REST API (CloudFront in front)."
  }
  assert {
    condition     = aws_api_gateway_authorizer.cognito[0].type == "COGNITO_USER_POOLS" && toset(aws_api_gateway_authorizer.cognito[0].provider_arns) == toset([var.cognito_user_pool_arn]) && aws_api_gateway_authorizer.cognito[0].identity_source == "method.request.header.Authorization"
    error_message = "Cognito authorizer on the identity user pool, token from Authorization."
  }
  assert {
    condition     = aws_api_gateway_method.proxy[0].authorization == "COGNITO_USER_POOLS" && aws_api_gateway_method.proxy[0].authorizer_id == aws_api_gateway_authorizer.cognito[0].id && aws_api_gateway_method.proxy[0].http_method == "ANY"
    error_message = "ANY /api/{proxy+} requires the Cognito authorizer."
  }
  assert {
    condition     = aws_api_gateway_method.healthz[0].authorization == "NONE" && aws_api_gateway_method.healthz[0].http_method == "GET" && aws_api_gateway_resource.healthz[0].path_part == "healthz"
    error_message = "Only GET /api/healthz is unauthenticated."
  }
  assert {
    condition = alltrue([
      for i in [aws_api_gateway_integration.healthz[0], aws_api_gateway_integration.proxy[0]] :
      i.request_parameters["integration.request.header.x-origin-verify"] == "''" && i.type == "HTTP_PROXY" && i.connection_type == "VPC_LINK" && i.connection_id == aws_api_gateway_vpc_link.this[0].id
    ])
    error_message = "Both integrations go over the VPC Link and blank the origin secret."
  }
  assert {
    condition     = aws_api_gateway_integration.proxy[0].uri == "http://cs-test-api-nlb-0123456789abcdef.elb.us-east-1.amazonaws.com:80/{proxy}" && aws_api_gateway_integration.healthz[0].uri == "http://cs-test-api-nlb-0123456789abcdef.elb.us-east-1.amazonaws.com:80/healthz"
    error_message = "Integrations target the NLB listener."
  }
  assert {
    condition = { for r in aws_wafv2_web_acl.api[0].rule : tostring(r.priority) => r.name } == {
      "0" = "OriginVerify"
      "1" = "AWSManagedRulesKnownBadInputsRuleSet"
      "2" = "AWSManagedRulesSQLiRuleSet"
    }
    error_message = "Regional ACL rules and priorities must be exactly D4."
  }
  assert {
    condition = (
      aws_wafv2_web_acl.api[0].scope == "REGIONAL" &&
      one([for r in aws_wafv2_web_acl.api[0].rule : r if r.priority == 0]).statement[0].not_statement[0].statement[0].byte_match_statement[0].positional_constraint == "EXACTLY" &&
      one([for r in aws_wafv2_web_acl.api[0].rule : r if r.priority == 0]).statement[0].not_statement[0].statement[0].byte_match_statement[0].field_to_match[0].single_header[0].name == "x-origin-verify" &&
      one([for r in aws_wafv2_web_acl.api[0].rule : r if r.priority == 0]).statement[0].not_statement[0].statement[0].byte_match_statement[0].search_string == random_password.origin_verify.result &&
      length(one([for r in aws_wafv2_web_acl.api[0].rule : r if r.priority == 0]).action[0].block) == 1
    )
    error_message = "OriginVerify (p0) blocks anything without the exact x-origin-verify secret."
  }
  assert {
    condition     = aws_wafv2_web_acl_association.api[0].resource_arn == aws_api_gateway_stage.v1[0].arn && aws_wafv2_web_acl_association.api[0].web_acl_arn == aws_wafv2_web_acl.api[0].arn
    error_message = "The regional ACL is associated with the v1 stage."
  }
  assert {
    condition     = toset([for f in aws_wafv2_web_acl_logging_configuration.api[0].redacted_fields : f.single_header[0].name]) == toset(["authorization", "cookie", "x-origin-verify"])
    error_message = "Regional WAF logs must redact authorization, cookie and x-origin-verify (D8)."
  }
  assert {
    condition = (
      aws_api_gateway_method_settings.all[0].settings[0].data_trace_enabled == false &&
      aws_api_gateway_method_settings.all[0].settings[0].logging_level == "ERROR" &&
      aws_api_gateway_method_settings.all[0].settings[0].caching_enabled == false &&
      aws_api_gateway_method_settings.all[0].settings[0].metrics_enabled &&
      aws_api_gateway_method_settings.all[0].settings[0].throttling_burst_limit == 50 &&
      aws_api_gateway_method_settings.all[0].settings[0].throttling_rate_limit == 20
    )
    error_message = "Method settings: ERROR logs, no data trace (JWTs), no cache, metrics, throttle 50/20."
  }
  assert {
    condition     = aws_api_gateway_stage.v1[0].xray_tracing_enabled && strcontains(aws_api_gateway_stage.v1[0].access_log_settings[0].format, "$context.wafResponseCode") && strcontains(aws_api_gateway_stage.v1[0].access_log_settings[0].format, "custom:tenant_id")
    error_message = "Stage: X-Ray + JSON access log with tenant claim and WAF response code."
  }
  assert {
    condition     = aws_cloudwatch_log_group.execution[0].name == "API-Gateway-Execution-Logs_a1b2c3d4e5/v1" && aws_cloudwatch_log_group.execution[0].kms_key_id == aws_kms_key.edge.arn && aws_cloudwatch_log_group.access[0].kms_key_id == aws_kms_key.edge.arn
    error_message = "Execution and access log groups are pre-created and KMS-encrypted (F7)."
  }
  assert {
    condition = (
      aws_cloudfront_distribution.this.ordered_cache_behavior[0].path_pattern == "/api/*" &&
      data.aws_cloudfront_cache_policy.caching_disabled.name == "Managed-CachingDisabled" &&
      data.aws_cloudfront_origin_request_policy.all_viewer_except_host.name == "Managed-AllViewerExceptHostHeader" &&
      aws_cloudfront_distribution.this.ordered_cache_behavior[0].cache_policy_id == data.aws_cloudfront_cache_policy.caching_disabled.id &&
      aws_cloudfront_distribution.this.ordered_cache_behavior[0].origin_request_policy_id == data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id &&
      aws_cloudfront_distribution.this.ordered_cache_behavior[0].response_headers_policy_id == aws_cloudfront_response_headers_policy.security.id &&
      aws_cloudfront_distribution.this.ordered_cache_behavior[0].viewer_protocol_policy == "https-only" &&
      length(aws_cloudfront_distribution.this.ordered_cache_behavior[0].allowed_methods) == 7 &&
      length(aws_cloudfront_distribution.this.ordered_cache_behavior[0].function_association) == 0
    )
    error_message = "/api/*: CachingDisabled + AllViewerExceptHostHeader + headers policy, https-only, 7 methods, no SPA rewrite (F5)."
  }
  assert {
    condition     = one([for o in nonsensitive(aws_cloudfront_distribution.this.origin) : o if o.origin_id == "api-gateway"]).domain_name == "a1b2c3d4e5.execute-api.us-east-1.amazonaws.com" && one([for o in nonsensitive(aws_cloudfront_distribution.this.origin) : o if o.origin_id == "api-gateway"]).origin_path == "/v1"
    error_message = "API origin: execute-api of this API, stage path /v1."
  }
  assert {
    condition     = one([for o in nonsensitive(aws_cloudfront_distribution.this.origin) : o if o.origin_id == "api-gateway"]).custom_origin_config[0].origin_protocol_policy == "https-only" && toset(one([for o in nonsensitive(aws_cloudfront_distribution.this.origin) : o if o.origin_id == "api-gateway"]).custom_origin_config[0].origin_ssl_protocols) == toset(["TLSv1.2"])
    error_message = "API origin: https-only, TLSv1.2."
  }
  assert {
    condition     = [for h in one([for o in nonsensitive(aws_cloudfront_distribution.this.origin) : o if o.origin_id == "api-gateway"]).custom_header : h.name] == ["x-origin-verify"]
    error_message = "API origin: CloudFront adds the x-origin-verify header (D3)."
  }
  assert {
    condition     = length(aws_api_gateway_account.this) == 1
    error_message = "The account-level CloudWatch role is managed by default with the API (F6)."
  }
}

run "rejects_non_waf_log_bucket" {
  command = plan

  variables {
    waf_log_bucket_arn = "arn:aws:s3:::cs-test-log-archive-123456789012-us-east-1"
  }

  expect_failures = [var.waf_log_bucket_arn]
}

run "rejects_rate_limit_below_waf_minimum" {
  command = plan

  variables {
    waf_rate_limit = 5
  }

  expect_failures = [var.waf_rate_limit]
}

run "api_needs_nlb_and_user_pool" {
  command = plan

  variables {
    enable_api = true
  }

  expect_failures = [var.nlb_arn, var.nlb_dns_name, var.cognito_user_pool_arn]
}

run "refuses_regions_other_than_us_east_1" {
  command = plan

  override_data {
    target          = data.aws_region.current
    override_during = plan
    values          = { region = "eu-west-1" }
  }

  # The web ACL carries the same precondition, but plan stops at the IP sets
  # it depends on.
  expect_failures = [aws_wafv2_ip_set.soar_blocked_v4, aws_wafv2_ip_set.soar_blocked_v6]
}
