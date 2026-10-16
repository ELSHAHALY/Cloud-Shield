###############################################################################
# CloudFront distribution: one origin for the SPA and the API (same origin,
# so no CORS — decision D2).
###############################################################################

# AWS managed policies, looked up by name.
data "aws_cloudfront_cache_policy" "caching_optimized" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_cache_policy" "caching_disabled" {
  name = "Managed-CachingDisabled"
}

# Forwards every viewer header (incl. Authorization) except Host, which must
# not reach execute-api (F5). Caching is disabled on that behaviour, so the
# Authorization header is never part of a shared cache key.
data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

locals {
  spa_origin_id = "spa-s3"
  api_origin_id = "api-gateway"

  content_security_policy = join("; ", [
    "default-src 'self'",
    "connect-src 'self' https://cognito-idp.${local.region}.amazonaws.com",
    "img-src 'self' data:",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
  ])
}

# The four headers the ZAP gate FAILs on (.zap/rules.tsv: 10020, 10021,
# 10035, 10038), on every response of both behaviours (F10).
resource "aws_cloudfront_response_headers_policy" "security" {
  name    = "${var.name}-security-headers"
  comment = "HSTS, nosniff, frame DENY, referrer policy, CSP"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
    content_security_policy {
      content_security_policy = local.content_security_policy
      override                = true
    }
  }
}

resource "aws_cloudfront_distribution" "this" {
  #checkov:skip=CKV_AWS_86:Every viewer request is logged by the CloudFront web ACL to the aws-waf-logs-* bucket (D8); standard access logs would duplicate it
  #checkov:skip=CKV_AWS_174:No custom domain yet: the default *.cloudfront.net certificate fixes the minimum viewer protocol at TLSv1 (F12, D11). Follow-up: custom domain + ACM with TLSv1.2_2021
  #checkov:skip=CKV2_AWS_42:No custom domain yet, so no ACM certificate to attach (F12, D11)
  #checkov:skip=CKV_AWS_310:Single region by design (plan §1.2): no secondary origin to fail over to
  #checkov:skip=CKV2_AWS_47:The Log4j AMR is attached: AWSManagedRulesKnownBadInputsRuleSet (its Log4JRCE rules) is on the CloudFront ACL; the check also demands AWSManagedRulesAnonymousIpList, which D4 leaves out (it would block VPN/Tor users of a SaaS; IP reputation + rate limit + PB-05 cover abusive sources)
  #checkov:skip=CKV_AWS_374:No geo restriction: the SaaS has no country allow-list; abusive sources are handled by the WAF (IP reputation, rate limit, PB-05 block list)
  enabled             = true
  comment             = "${var.name} SPA + API"
  is_ipv6_enabled     = true
  http_version        = "http2and3"
  price_class         = "PriceClass_100"
  default_root_object = "index.html"
  web_acl_id          = aws_wafv2_web_acl.cloudfront.arn

  origin {
    origin_id                = local.spa_origin_id
    domain_name              = aws_s3_bucket.spa.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.spa.id
  }

  dynamic "origin" {
    for_each = var.enable_api ? [1] : []
    content {
      origin_id   = local.api_origin_id
      domain_name = "${aws_api_gateway_rest_api.this[0].id}.execute-api.${local.region}.amazonaws.com"
      origin_path = "/${local.api_stage}"

      custom_origin_config {
        http_port              = 80
        https_port             = 443
        origin_protocol_policy = "https-only"
        origin_ssl_protocols   = ["TLSv1.2"]
      }

      custom_header {
        name  = "x-origin-verify"
        value = random_password.origin_verify.result
      }
    }
  }

  default_cache_behavior {
    target_origin_id           = local.spa_origin_id
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
    compress                   = true
    cache_policy_id            = data.aws_cloudfront_cache_policy.caching_optimized.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.spa_rewrite.arn
    }
  }

  dynamic "ordered_cache_behavior" {
    for_each = var.enable_api ? [1] : []
    content {
      path_pattern               = "/api/*"
      target_origin_id           = local.api_origin_id
      viewer_protocol_policy     = "https-only"
      allowed_methods            = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
      cached_methods             = ["GET", "HEAD"]
      compress                   = true
      cache_policy_id            = data.aws_cloudfront_cache_policy.caching_disabled.id
      origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
      response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id
    }
  }

  # Deliberately NO custom_error_response: it would also rewrite WAF blocks
  # and API 401/403/404s into "200 index.html" (F11). SPA routes are handled
  # by the viewer-request function instead (D10).

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = var.tags
}
