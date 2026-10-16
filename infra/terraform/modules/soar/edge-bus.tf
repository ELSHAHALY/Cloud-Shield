###############################################################################
# PB-05 trigger path (plan §4.2, D13) — only with enable_pb05 + playbooks.
#
#   WAF rate rule BlockedRequests >= 1 ─► CloudWatch alarm ─► (default bus)
#   "CloudWatch Alarm State Change" to ALARM ─► harvester Lambda
#   ─► GetRateBasedStatementManagedKeys ─► ONE event per IP onto
#   ${name}-soar-edge ─► rule {source cloudshield.edge, IPAddress} ─► cs-ir-router
#
# The dedicated bus is the ONLY way an edge event reaches the router. Its
# policy explicitly denies events:PutEvents to every principal not named in
# the publisher list, so a same-account identity policy cannot publish to it
# (F24). Residual risk (ADR-0001): an account admin can rewrite the policy.
# The bus rule matches only IPAddress edge events, so PB-01..PB-04 can never
# be triggered through it; the guard then vets every address on its own.
###############################################################################

locals {
  never_block_param_name = "${local.ssm_prefix}/pb05_never_block"
  edge_bus_name          = "${var.name}-soar-edge"
  harvester_name         = "${var.name}-soar-pb05-harvester"

  # NAT egress /32 + operator CIDRs. Never empty when PB-05 is on (precondition).
  never_block_cidrs = concat(
    var.nat_public_ip != null ? ["${var.nat_public_ip}/32"] : [],
    var.pb05_never_block_cidrs,
  )

  # The harvester always publishes; Phase E adds the docs-api task role.
  pb05_publishers = local.enable_pb05 ? concat(aws_iam_role.harvester[*].arn, var.pb05_publisher_arns) : []

  edge_region_error = "PB-05 needs a us-east-1 provider: the CLOUDFRONT web ACL and its IP sets exist only there (F2, F17 fallback)."
}

# -----------------------------------------------------------------------------
# Dedicated bus + deny-by-default policy
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_event_bus" "edge" {
  count = local.enable_pb05 ? 1 : 0
  name  = local.edge_bus_name
  tags  = var.tags

  lifecycle {
    precondition {
      condition     = local.region == "us-east-1"
      error_message = local.edge_region_error
    }
  }
}

data "aws_iam_policy_document" "edge_bus" {
  count = local.enable_pb05 ? 1 : 0

  statement {
    sid       = "NamedPublishersOnly"
    actions   = ["events:PutEvents"]
    resources = [aws_cloudwatch_event_bus.edge[0].arn]
    principals {
      type        = "AWS"
      identifiers = local.pb05_publishers
    }
  }
  # Explicit Deny: beats any same-account identity policy allowing PutEvents.
  statement {
    sid       = "DenyEveryOtherPublisher"
    effect    = "Deny"
    actions   = ["events:PutEvents"]
    resources = [aws_cloudwatch_event_bus.edge[0].arn]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = local.pb05_publishers
    }
  }
}

resource "aws_cloudwatch_event_bus_policy" "edge" {
  count          = local.enable_pb05 ? 1 : 0
  event_bus_name = aws_cloudwatch_event_bus.edge[0].name
  policy         = data.aws_iam_policy_document.edge_bus[0].json
}

# -----------------------------------------------------------------------------
# Never-block list (guard rule 4): read by the guard on every IP evaluation.
# -----------------------------------------------------------------------------
resource "aws_ssm_parameter" "never_block" {
  #checkov:skip=CKV2_AWS_34:Non-secret configuration (the NAT egress IP and operator CIDRs); SecureString adds KMS calls on the guard's hot path for no confidentiality gain
  count       = local.enable_pb05 ? 1 : 0
  name        = local.never_block_param_name
  description = "Comma-separated CIDRs PB-05 must never block (NAT egress /32 + operator CIDRs). Unreadable or empty = every block is refused."
  type        = "String"
  value       = join(",", local.never_block_cidrs)
  tags        = var.tags

  lifecycle {
    precondition {
      condition     = length(local.never_block_cidrs) > 0
      error_message = "PB-05 needs a never-block list: set nat_public_ip and/or pb05_never_block_cidrs."
    }
  }
}

# -----------------------------------------------------------------------------
# Edge bus -> router. Only IPAddress events from the edge source.
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "edge" {
  count          = local.enable_pb05 ? 1 : 0
  name           = "${var.name}-soar-edge-to-router"
  description    = "PB-05: edge IP findings on the dedicated bus -> cs-ir-router"
  event_bus_name = aws_cloudwatch_event_bus.edge[0].name
  event_pattern = jsonencode({
    source = [local.edge_event_source]
    detail = { resource = { resourceType = ["IPAddress"] } }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "edge" {
  count          = local.enable_pb05 ? 1 : 0
  rule           = aws_cloudwatch_event_rule.edge[0].name
  event_bus_name = aws_cloudwatch_event_bus.edge[0].name
  target_id      = "cs-ir-router"
  arn            = aws_sfn_state_machine.router[0].arn
  role_arn       = aws_iam_role.events[0].arn
}

# -----------------------------------------------------------------------------
# Harvester: alarm -> one edge event per rate-limited IP.
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "harvester" {
  count = local.enable_pb05 ? 1 : 0

  statement {
    sid       = "ReadRateLimitedKeys"
    actions   = ["wafv2:GetRateBasedStatementManagedKeys"]
    resources = [var.waf_web_acl.arn]
  }
  statement {
    sid       = "PublishToEdgeBus"
    actions   = ["events:PutEvents"]
    resources = [aws_cloudwatch_event_bus.edge[0].arn]
  }
}

data "aws_iam_policy_document" "harvester_runtime" {
  count = local.enable_pb05 ? 1 : 0

  statement {
    sid       = "OwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.harvester[0].arn}:*"]
  }
  statement {
    sid       = "Tracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"] # X-Ray has no resource-level permissions for these
  }
}

resource "aws_iam_role" "harvester" {
  count              = local.enable_pb05 ? 1 : 0
  name               = local.harvester_name
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "harvester" {
  count  = local.enable_pb05 ? 1 : 0
  name   = "harvest"
  role   = aws_iam_role.harvester[0].id
  policy = data.aws_iam_policy_document.harvester[0].json
}

resource "aws_iam_role_policy" "harvester_runtime" {
  count  = local.enable_pb05 ? 1 : 0
  name   = "runtime"
  role   = aws_iam_role.harvester[0].id
  policy = data.aws_iam_policy_document.harvester_runtime[0].json
}

resource "aws_cloudwatch_log_group" "harvester" {
  #checkov:skip=CKV_AWS_338:30-day retention is a deliberate lab cost choice; every published event becomes an incident row
  count             = local.enable_pb05 ? 1 : 0
  name              = "/aws/lambda/${local.harvester_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
  tags              = var.tags
}

resource "aws_lambda_function" "harvester" {
  #checkov:skip=CKV_AWS_116:Invoked asynchronously by EventBridge on an alarm transition (or the optional schedule); a lost run only delays blocks until the next trigger (documented gap), and failed PutEvents entries raise so Lambda's async retry re-publishes (the router drops duplicate ids)
  #checkov:skip=CKV_AWS_117:Only calls AWS control-plane APIs (WAFv2, EventBridge); a VPC attachment would add a NAT dependency to the PB-05 path
  #checkov:skip=CKV_AWS_272:Code signing deferred; the package comes from the gated CI pipeline (stretch goal: AWS Signer profile)
  #checkov:skip=CKV_AWS_115:Reserved concurrency is a variable; default -1 because new accounts (limit 10) reject any reservation — set 5 once the quota allows
  count         = local.enable_pb05 ? 1 : 0
  function_name = local.harvester_name
  role          = aws_iam_role.harvester[0].arn
  runtime       = "python3.13"
  architectures = ["arm64"]
  handler       = "playbooks.pb05_waf_ip_block.harvest_handler"
  timeout       = 30
  memory_size   = 256
  kms_key_arn   = aws_kms_key.this.arn

  s3_bucket         = var.playbook_package.s3_bucket
  s3_key            = var.playbook_package.s3_key
  s3_object_version = var.playbook_package.s3_object_version

  reserved_concurrent_executions = var.lambda_reserved_concurrency

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      EDGE_BUS_NAME      = aws_cloudwatch_event_bus.edge[0].name
      EDGE_EVENT_SOURCE  = local.edge_event_source
      WAF_WEB_ACL_NAME   = var.waf_web_acl.name
      WAF_WEB_ACL_ID     = var.waf_web_acl.id
      WAF_RATE_RULE_NAME = var.waf_rate_rule_name
      WAF_SCOPE          = "CLOUDFRONT"
      WAF_REGION         = local.region
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.harvester,
    aws_iam_role_policy.harvester,
    aws_iam_role_policy.harvester_runtime,
  ]

  tags = var.tags
}

# Rate rule firing at all -> ALARM. Dimensions for CLOUDFRONT scope are
# [inferred] (verify-on-apply #12): WebACL = the ACL's metric name, Rule =
# the rule's metric name; modules/edge sets both equal to the names.
resource "aws_cloudwatch_metric_alarm" "rate_limited" {
  count               = local.enable_pb05 ? 1 : 0
  alarm_name          = "${var.name}-soar-pb05-rate-limited"
  alarm_description   = "PB-05: the CloudFront rate rule is blocking clients; EventBridge runs the harvester on the transition to ALARM."
  namespace           = "AWS/WAFV2"
  metric_name         = "BlockedRequests"
  dimensions          = { WebACL = var.waf_web_acl.name, Rule = var.waf_rate_rule_name }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  tags                = var.tags
}

resource "aws_cloudwatch_event_rule" "harvest" {
  count       = local.enable_pb05 ? 1 : 0
  name        = "${var.name}-soar-pb05-harvest"
  description = "PB-05: rate-rule alarm -> ALARM runs the harvester"
  event_pattern = jsonencode({
    source        = ["aws.cloudwatch"]
    "detail-type" = ["CloudWatch Alarm State Change"]
    resources     = [aws_cloudwatch_metric_alarm.rate_limited[0].arn]
    detail        = { state = { value = ["ALARM"] } }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "harvest" {
  count     = local.enable_pb05 ? 1 : 0
  rule      = aws_cloudwatch_event_rule.harvest[0].name
  target_id = "pb05-harvester"
  arn       = aws_lambda_function.harvester[0].arn
}

resource "aws_lambda_permission" "harvest" {
  count         = local.enable_pb05 ? 1 : 0
  statement_id  = "AllowRateAlarmRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.harvester[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.harvest[0].arn
}

# Optional (default off): IPs that become rate-limited while the alarm is
# already in ALARM otherwise wait for the next transition (known gap).
resource "aws_cloudwatch_event_rule" "harvest_schedule" {
  count               = local.enable_pb05 && var.pb05_harvest_schedule != null ? 1 : 0
  name                = "${var.name}-soar-pb05-harvest-schedule"
  description         = "PB-05: periodic harvest of rate-limited IPs"
  schedule_expression = var.pb05_harvest_schedule
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "harvest_schedule" {
  count     = local.enable_pb05 && var.pb05_harvest_schedule != null ? 1 : 0
  rule      = aws_cloudwatch_event_rule.harvest_schedule[0].name
  target_id = "pb05-harvester"
  arn       = aws_lambda_function.harvester[0].arn
}

resource "aws_lambda_permission" "harvest_schedule" {
  count         = local.enable_pb05 && var.pb05_harvest_schedule != null ? 1 : 0
  statement_id  = "AllowHarvestSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.harvester[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.harvest_schedule[0].arn
}
