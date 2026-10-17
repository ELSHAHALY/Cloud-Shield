###############################################################################
# REST API (enable_api): CloudFront /api/* --> stage v1 --VPC Link--> NLB.
#
#   GET /api/healthz      no auth          -> http://<nlb>/healthz
#   ANY /api/{proxy+}     Cognito ID token -> http://<nlb>/{proxy}
#   ANY /api/admin        no auth, ONLY with enable_decoy_route (Phase E D14)
#   ANY /api/admin/{proxy+}                -> http://<nlb>/admin[/{proxy}]
#                         The app's decoy answers a static 403 problem and
#                         records the hit; it never serves data.
#
# The authorizer checks signature, issuer and expiry of the ID token; the app
# re-verifies iss, aud and token_use=id and takes the tenant ONLY from the
# verified custom:tenant_id claim (F8, decision D5).
###############################################################################

locals {
  api_count        = var.enable_api ? 1 : 0
  decoy_count      = var.enable_api && var.enable_decoy_route ? 1 : 0
  api_stage        = "v1"
  backend_base_url = var.nlb_dns_name == null ? null : "http://${var.nlb_dns_name}:${var.nlb_listener_port}"
  # API Gateway overwrites the origin secret with an empty static value, so
  # the backend never sees it (D3).
  blank_origin_verify = { "integration.request.header.x-origin-verify" = "''" }
}

resource "aws_api_gateway_rest_api" "this" {
  count       = local.api_count
  name        = "${var.name}-api"
  description = "CloudShield docs-api, reachable only through CloudFront (regional WAF OriginVerify)"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_vpc_link" "this" {
  count       = local.api_count
  name        = "${var.name}-api-link"
  description = "REST API -> internal NLB (modules/compute)"
  target_arns = [var.nlb_arn]
  tags        = var.tags
}

resource "aws_api_gateway_authorizer" "cognito" {
  count           = local.api_count
  name            = "${var.name}-cognito"
  rest_api_id     = aws_api_gateway_rest_api.this[0].id
  type            = "COGNITO_USER_POOLS"
  provider_arns   = [var.cognito_user_pool_arn]
  identity_source = "method.request.header.Authorization"
}

# --- resources -----------------------------------------------------------------
resource "aws_api_gateway_resource" "api" {
  count       = local.api_count
  rest_api_id = aws_api_gateway_rest_api.this[0].id
  parent_id   = aws_api_gateway_rest_api.this[0].root_resource_id
  path_part   = "api"
}

resource "aws_api_gateway_resource" "healthz" {
  count       = local.api_count
  rest_api_id = aws_api_gateway_rest_api.this[0].id
  parent_id   = aws_api_gateway_resource.api[0].id
  path_part   = "healthz"
}

resource "aws_api_gateway_resource" "proxy" {
  count       = local.api_count
  rest_api_id = aws_api_gateway_rest_api.this[0].id
  parent_id   = aws_api_gateway_resource.api[0].id
  path_part   = "{proxy+}"
}

# --- GET /api/healthz (unauthenticated liveness only) -------------------------
resource "aws_api_gateway_method" "healthz" {
  #checkov:skip=CKV_AWS_59:Liveness endpoint only (GET /api/healthz returns a static status, no data); every other route requires the Cognito authorizer
  #checkov:skip=CKV2_AWS_53:No request body or parameters to validate on a GET liveness probe
  count         = local.api_count
  rest_api_id   = aws_api_gateway_rest_api.this[0].id
  resource_id   = aws_api_gateway_resource.healthz[0].id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "healthz" {
  count                   = local.api_count
  rest_api_id             = aws_api_gateway_rest_api.this[0].id
  resource_id             = aws_api_gateway_resource.healthz[0].id
  http_method             = aws_api_gateway_method.healthz[0].http_method
  type                    = "HTTP_PROXY"
  integration_http_method = "GET"
  connection_type         = "VPC_LINK"
  connection_id           = aws_api_gateway_vpc_link.this[0].id
  uri                     = "${local.backend_base_url}/healthz"
  request_parameters      = local.blank_origin_verify
}

# --- ANY /api/{proxy+} (Cognito) ----------------------------------------------
resource "aws_api_gateway_method" "proxy" {
  #checkov:skip=CKV2_AWS_53:Request validation is done in the app against its OpenAPI schema (HTTP_PROXY passes the request through unchanged)
  count         = local.api_count
  rest_api_id   = aws_api_gateway_rest_api.this[0].id
  resource_id   = aws_api_gateway_resource.proxy[0].id
  http_method   = "ANY"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito[0].id

  request_parameters = {
    "method.request.path.proxy" = true
  }
}

resource "aws_api_gateway_integration" "proxy" {
  count                   = local.api_count
  rest_api_id             = aws_api_gateway_rest_api.this[0].id
  resource_id             = aws_api_gateway_resource.proxy[0].id
  http_method             = aws_api_gateway_method.proxy[0].http_method
  type                    = "HTTP_PROXY"
  integration_http_method = "ANY"
  connection_type         = "VPC_LINK"
  connection_id           = aws_api_gateway_vpc_link.this[0].id
  uri                     = "${local.backend_base_url}/{proxy}"

  request_parameters = merge(local.blank_origin_verify, {
    "integration.request.path.proxy" = "method.request.path.proxy"
  })
}

# --- ANY /api/admin and /api/admin/{proxy+} (decoy, Phase E D14) -------------
# Unauthenticated by design so the decoy also sees scanners without a token.
# API Gateway prefers the more specific resource, so these beat {proxy+}
# [inferred: verify-on-apply §16 #2]. Every other route still requires the
# Cognito authorizer.
resource "aws_api_gateway_resource" "admin" {
  count       = local.decoy_count
  rest_api_id = aws_api_gateway_rest_api.this[0].id
  parent_id   = aws_api_gateway_resource.api[0].id
  path_part   = "admin"
}

resource "aws_api_gateway_resource" "admin_proxy" {
  count       = local.decoy_count
  rest_api_id = aws_api_gateway_rest_api.this[0].id
  parent_id   = aws_api_gateway_resource.admin[0].id
  path_part   = "{proxy+}"
}

resource "aws_api_gateway_method" "admin" {
  #checkov:skip=CKV_AWS_59:decoy route: unauthenticated by design, returns a static 403; every other route requires Cognito
  #checkov:skip=CKV2_AWS_53:decoy route: unauthenticated by design, returns a static 403; every other route requires Cognito
  count         = local.decoy_count
  rest_api_id   = aws_api_gateway_rest_api.this[0].id
  resource_id   = aws_api_gateway_resource.admin[0].id
  http_method   = "ANY"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "admin" {
  count                   = local.decoy_count
  rest_api_id             = aws_api_gateway_rest_api.this[0].id
  resource_id             = aws_api_gateway_resource.admin[0].id
  http_method             = aws_api_gateway_method.admin[0].http_method
  type                    = "HTTP_PROXY"
  integration_http_method = "ANY"
  connection_type         = "VPC_LINK"
  connection_id           = aws_api_gateway_vpc_link.this[0].id
  uri                     = "${local.backend_base_url}/admin"
  request_parameters      = local.blank_origin_verify
}

resource "aws_api_gateway_method" "admin_proxy" {
  #checkov:skip=CKV_AWS_59:decoy route: unauthenticated by design, returns a static 403; every other route requires Cognito
  #checkov:skip=CKV2_AWS_53:decoy route: unauthenticated by design, returns a static 403; every other route requires Cognito
  count         = local.decoy_count
  rest_api_id   = aws_api_gateway_rest_api.this[0].id
  resource_id   = aws_api_gateway_resource.admin_proxy[0].id
  http_method   = "ANY"
  authorization = "NONE"

  request_parameters = {
    "method.request.path.proxy" = true
  }
}

resource "aws_api_gateway_integration" "admin_proxy" {
  count                   = local.decoy_count
  rest_api_id             = aws_api_gateway_rest_api.this[0].id
  resource_id             = aws_api_gateway_resource.admin_proxy[0].id
  http_method             = aws_api_gateway_method.admin_proxy[0].http_method
  type                    = "HTTP_PROXY"
  integration_http_method = "ANY"
  connection_type         = "VPC_LINK"
  connection_id           = aws_api_gateway_vpc_link.this[0].id
  uri                     = "${local.backend_base_url}/admin/{proxy}"

  request_parameters = merge(local.blank_origin_verify, {
    "integration.request.path.proxy" = "method.request.path.proxy"
  })
}

# --- deployment + stage ----------------------------------------------------------
resource "aws_api_gateway_deployment" "this" {
  count       = local.api_count
  rest_api_id = aws_api_gateway_rest_api.this[0].id

  triggers = {
    # The decoy entries are appended only when the route exists, so turning
    # it on (or off) redeploys, and the hash is unchanged while it stays off.
    redeployment = sha1(jsonencode(concat([
      aws_api_gateway_resource.api[0].id,
      aws_api_gateway_resource.healthz[0].id,
      aws_api_gateway_resource.proxy[0].id,
      aws_api_gateway_authorizer.cognito[0].id,
      aws_api_gateway_method.healthz[0].id,
      aws_api_gateway_method.healthz[0].authorization,
      aws_api_gateway_method.proxy[0].id,
      aws_api_gateway_method.proxy[0].authorization,
      aws_api_gateway_integration.healthz[0].id,
      aws_api_gateway_integration.healthz[0].uri,
      aws_api_gateway_integration.healthz[0].request_parameters,
      aws_api_gateway_integration.proxy[0].id,
      aws_api_gateway_integration.proxy[0].uri,
      aws_api_gateway_integration.proxy[0].request_parameters,
      ], local.decoy_count == 1 ? [jsonencode([
        aws_api_gateway_resource.admin[0].id,
        aws_api_gateway_resource.admin_proxy[0].id,
        aws_api_gateway_method.admin[0].id,
        aws_api_gateway_method.admin[0].authorization,
        aws_api_gateway_method.admin_proxy[0].id,
        aws_api_gateway_method.admin_proxy[0].authorization,
        aws_api_gateway_integration.admin[0].id,
        aws_api_gateway_integration.admin[0].uri,
        aws_api_gateway_integration.admin[0].request_parameters,
        aws_api_gateway_integration.admin_proxy[0].id,
        aws_api_gateway_integration.admin_proxy[0].uri,
        aws_api_gateway_integration.admin_proxy[0].request_parameters,
    ])] : [])))
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Pre-created so it is KMS-encrypted and expires (F7); API Gateway would
# otherwise create it unencrypted with no retention.
resource "aws_cloudwatch_log_group" "execution" {
  #checkov:skip=CKV_AWS_338:30-day retention is a deliberate lab cost choice; ERROR-level execution logs only
  count             = local.api_count
  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.this[0].id}/${local.api_stage}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.edge.arn
  tags              = var.tags
  depends_on        = [aws_kms_key_policy.edge]
}

resource "aws_cloudwatch_log_group" "access" {
  #checkov:skip=CKV_AWS_338:30-day retention is a deliberate lab cost choice; the app's FR-4 audit trail is the long-term record
  count             = local.api_count
  name              = "/${var.name}/edge/api-access"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.edge.arn
  tags              = var.tags
  depends_on        = [aws_kms_key_policy.edge]
}

resource "aws_api_gateway_stage" "v1" {
  #checkov:skip=CKV_AWS_120:Caching off on purpose: responses are per-tenant and per-user and must never be served from a shared cache
  #checkov:skip=CKV2_AWS_77:The Log4j AMR is attached: AWSManagedRulesKnownBadInputsRuleSet is on the regional ACL; the check also demands AWSManagedRulesAnonymousIpList, which is meaningless here because behind CloudFront this ACL only ever sees CloudFront's IPs (F3); per-IP rules live on the CloudFront ACL
  #checkov:skip=CKV2_AWS_51:Backend is reached only over the private VPC Link (and execute-api only through CloudFront's origin-verify header); no client certificate hop exists
  count                = local.api_count
  rest_api_id          = aws_api_gateway_rest_api.this[0].id
  deployment_id        = aws_api_gateway_deployment.this[0].id
  stage_name           = local.api_stage
  xray_tracing_enabled = true

  # sourceIp is CloudFront's address (F3); the WAF logs hold the client IP.
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.access[0].arn
    format = jsonencode({
      requestId        = "$context.requestId"
      requestTime      = "$context.requestTime"
      httpMethod       = "$context.httpMethod"
      resourcePath     = "$context.resourcePath"
      status           = "$context.status"
      responseLength   = "$context.responseLength"
      integrationError = "$context.integration.error"
      sourceIp         = "$context.identity.sourceIp"
      sub              = "$context.authorizer.claims.sub"
      tenantId         = "$context.authorizer.claims['custom:tenant_id']"
      wafResponseCode  = "$context.wafResponseCode"
    })
  }

  tags = var.tags

  depends_on = [aws_cloudwatch_log_group.execution, aws_api_gateway_account.this]
}

resource "aws_api_gateway_method_settings" "all" {
  #checkov:skip=CKV_AWS_225:Caching is disabled (per-tenant responses are never cached), so there is no cache to encrypt
  count       = local.api_count
  rest_api_id = aws_api_gateway_rest_api.this[0].id
  stage_name  = aws_api_gateway_stage.v1[0].stage_name
  method_path = "*/*"

  settings {
    logging_level = "ERROR"
    # Full request/response logging would write JWTs and document bodies to
    # CloudWatch.
    data_trace_enabled     = false
    metrics_enabled        = true
    caching_enabled        = false
    throttling_burst_limit = var.api_throttle_burst
    throttling_rate_limit  = var.api_throttle_rate
  }
}

# -----------------------------------------------------------------------------
# Account-level CloudWatch role for REST API logging (F6): a regional
# singleton. If the account already has one, set manage_apigw_account_role =
# false or import it: terraform import 'module.edge[0].aws_api_gateway_account.this[0]' api-gateway-account
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "apigw_trust" {
  # No aws:SourceAccount / SourceArn condition until verified on apply
  # (lesson of HANDOFF M3: a wrong condition silently breaks API logging).
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["apigateway.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "apigw_cloudwatch" {
  count              = var.enable_api && var.manage_apigw_account_role ? 1 : 0
  name               = "${var.name}-apigw-cloudwatch"
  description        = "API Gateway (account-level) writes REST API execution and access logs"
  assume_role_policy = data.aws_iam_policy_document.apigw_trust.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "apigw_cloudwatch" {
  count      = var.enable_api && var.manage_apigw_account_role ? 1 : 0
  role       = aws_iam_role.apigw_cloudwatch[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

resource "aws_api_gateway_account" "this" {
  count               = var.enable_api && var.manage_apigw_account_role ? 1 : 0
  cloudwatch_role_arn = aws_iam_role.apigw_cloudwatch[0].arn
  depends_on          = [aws_iam_role_policy_attachment.apigw_cloudwatch]
}
