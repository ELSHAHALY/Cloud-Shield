###############################################################################
# WAF (decision D4). Behind CloudFront the regional ACL sees CloudFront's IP
# (F3), so every per-IP control — reputation, rate limit and the PB-05 block
# list — lives on the CloudFront ACL. The regional ACL locks the API origin to
# CloudFront and inspects payloads.
###############################################################################

# Shared secret CloudFront adds to every /api/* origin request (D3). A bypass
# deterrent, NOT authentication: anyone with WAF or CloudFront read access
# can see it. API Gateway blanks it before the backend (api.tf), and the WAF
# logs redact it.
resource "random_password" "origin_verify" {
  length  = 48
  special = false
}

# -----------------------------------------------------------------------------
# PB-05 block lists (F23). Terraform creates them empty and then never touches
# the addresses again: PB-05 adds to them, and an apply must never lift a
# block (same principle as ADR-0003). Removal is a documented human step.
# -----------------------------------------------------------------------------
resource "aws_wafv2_ip_set" "soar_blocked_v4" {
  name               = "${var.name}-soar-blocked-ips-v4"
  description        = "PB-05 automated block list (IPv4 /32). Managed by SOAR; Terraform ignores the addresses."
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  addresses          = []
  tags               = var.tags

  lifecycle {
    ignore_changes = [addresses]
    precondition {
      condition     = local.region_ok
      error_message = local.region_error
    }
  }
}

resource "aws_wafv2_ip_set" "soar_blocked_v6" {
  name               = "${var.name}-soar-blocked-ips-v6"
  description        = "PB-05 automated block list (IPv6 /128). Managed by SOAR; Terraform ignores the addresses."
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV6"
  addresses          = []
  tags               = var.tags

  lifecycle {
    ignore_changes = [addresses]
    precondition {
      condition     = local.region_ok
      error_message = local.region_error
    }
  }
}

# -----------------------------------------------------------------------------
# CloudFront web ACL
# -----------------------------------------------------------------------------
resource "aws_wafv2_web_acl" "cloudfront" {
  name        = "${var.name}-cloudfront"
  description = "CloudShield edge: PB-05 block list, IP reputation, per-IP rate limit, common + known-bad-input rules"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "SoarBlockedIps"
    priority = 0
    action {
      block {}
    }
    statement {
      or_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.soar_blocked_v4.arn
          }
        }
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.soar_blocked_v6.arn
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SoarBlockedIps"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesAmazonIpReputationList"
      sampled_requests_enabled   = true
    }
  }

  # PB-05's harvester (stage 2b) reads the keys this rule is limiting.
  rule {
    name     = local.rate_rule_name
    priority = 2
    action {
      block {
        custom_response {
          response_code = 429
        }
      }
    }
    statement {
      rate_based_statement {
        limit                 = var.waf_rate_limit
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = local.rate_rule_name
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 3
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 4
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesKnownBadInputsRuleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-cloudfront"
    sampled_requests_enabled   = true
  }

  tags = var.tags

  lifecycle {
    precondition {
      condition     = local.region_ok
      error_message = local.region_error
    }
  }
}

# -----------------------------------------------------------------------------
# Regional web ACL on the REST API stage (enable_api)
# -----------------------------------------------------------------------------
resource "aws_wafv2_web_acl" "api" {
  count       = var.enable_api ? 1 : 0
  name        = "${var.name}-api"
  description = "CloudShield API origin: only CloudFront (origin-verify header), known-bad inputs, SQLi"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # Anything that did not come through our distribution (no or wrong header)
  # is blocked: execute-api is not reachable around the CloudFront WAF.
  rule {
    name     = "OriginVerify"
    priority = 0
    action {
      block {}
    }
    statement {
      not_statement {
        statement {
          byte_match_statement {
            search_string         = random_password.origin_verify.result
            positional_constraint = "EXACTLY"
            field_to_match {
              single_header {
                name = "x-origin-verify"
              }
            }
            text_transformation {
              priority = 0
              type     = "NONE"
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "OriginVerify"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesKnownBadInputsRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesSQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-api"
    sampled_requests_enabled   = true
  }

  tags = var.tags
}

resource "aws_wafv2_web_acl_association" "api" {
  count        = var.enable_api ? 1 : 0
  resource_arn = aws_api_gateway_stage.v1[0].arn
  web_acl_arn  = aws_wafv2_web_acl.api[0].arn
}

# -----------------------------------------------------------------------------
# Logging (D8): every request of both ACLs to the aws-waf-logs-* bucket
# (modules/log-archive), with credentials and the origin secret redacted.
# -----------------------------------------------------------------------------
locals {
  rate_rule_name          = "RateLimitPerIp"
  waf_redacted_header_set = ["authorization", "cookie", "x-origin-verify"]
}

resource "aws_wafv2_web_acl_logging_configuration" "cloudfront" {
  resource_arn            = aws_wafv2_web_acl.cloudfront.arn
  log_destination_configs = [var.waf_log_bucket_arn]

  dynamic "redacted_fields" {
    for_each = local.waf_redacted_header_set
    content {
      single_header {
        name = redacted_fields.value
      }
    }
  }
}

resource "aws_wafv2_web_acl_logging_configuration" "api" {
  count                   = var.enable_api ? 1 : 0
  resource_arn            = aws_wafv2_web_acl.api[0].arn
  log_destination_configs = [var.waf_log_bucket_arn]

  dynamic "redacted_fields" {
    for_each = local.waf_redacted_header_set
    content {
      single_header {
        name = redacted_fields.value
      }
    }
  }
}
