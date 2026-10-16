###############################################################################
# PB-05 trigger path (plan §4.2, D13) — only with enable_pb05 + playbooks.
#
#   SoarApiRateLimit (/api/* only) BlockedRequests >= 1 ─► CloudWatch alarm
#   ─► "Alarm State Change" to ALARM ─┐
#   schedule rate(5 minutes) ─────────┴► harvester Lambda
#   ─► GetRateBasedStatementManagedKeys ─► sighting table (>= 2 consecutive
#   harvests) ─► ONE event per persistent IP onto ${name}-soar-edge
#   ─► rule {source cloudshield.edge, type CloudShield:IPAddress/*, IPAddress}
#   ─► cs-ir-router ─► guard ─► PB-05 (corroborates with WAF, then blocks)
#
# The dedicated bus is the AUTOMATIC path, not the only one. Its policy
# explicitly denies events:PutEvents to every principal not named in the
# publisher list, so a same-account identity policy cannot publish to it
# (F24). But anyone allowed states:StartExecution on cs-ir-router (or
# lambda:InvokeFunction on PB-05) can hand the router a forged edge event.
# So PB-05 does not trust the event (audit A1): it re-reads the never-block
# list and refuses unless WAF ITSELF reports the address as a managed key of
# the rate rule at block time. Residual risk: an address WAF really is
# rate-limiting at that moment can be blocked by such a principal (the
# harvester would publish it anyway once it persists), and an account admin
# can rewrite the bus policy (ADR-0001). The bus rule matches only IPAddress
# edge events, so PB-01..PB-04 can never be triggered through it.
###############################################################################

locals {
  never_block_param_name = "${local.ssm_prefix}/pb05_never_block"
  edge_bus_name          = "${var.name}-soar-edge"
  harvester_name         = "${var.name}-soar-pb05-harvester"
  harvest_state_name     = "${var.name}-soar-pb05-harvest-state"

  # NAT egress /32 + operator CIDRs. Never empty when PB-05 is on (precondition).
  never_block_cidrs = concat(
    var.nat_public_ip != null ? ["${var.nat_public_ip}/32"] : [],
    var.pb05_never_block_cidrs,
  )

  # The harvester always publishes. Phase E: the docs-api task role is
  # derived HERE from app_publishes_decoy (D13), so the Allow list, the Deny
  # exception list and the role's own PutEvents grant cannot drift apart.
  # distinct(): the same role may also be listed in pb05_publisher_arns.
  pb05_publishers = local.enable_pb05 ? distinct(concat(
    aws_iam_role.harvester[*].arn,
    var.pb05_publisher_arns,
    local.app_publishes_decoy ? [var.app_task_role_arn] : [],
  )) : []

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
# Never-block list (guard rule 4): read by the guard on every IP evaluation,
# and again by PB-05 itself right before it blocks (audit A1).
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
# Edge bus -> router. Only IPAddress events from the edge source whose type
# is a CloudShield IP finding (audit A5); the guard then allows only the
# explicit type allow-list.
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "edge" {
  count          = local.enable_pb05 ? 1 : 0
  name           = "${var.name}-soar-edge-to-router"
  description    = "PB-05: edge IP findings on the dedicated bus -> cs-ir-router"
  event_bus_name = aws_cloudwatch_event_bus.edge[0].name
  event_pattern = jsonencode({
    source = [local.edge_event_source]
    detail = {
      type     = [{ prefix = "CloudShield:IPAddress/" }]
      resource = { resourceType = ["IPAddress"] }
    }
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
# Persistence state (audit A2): per-address sighting counters. An address is
# published only once it was a managed key in >= 2 consecutive harvests.
# Harvester-only IAM; items expire through the TTL attribute.
# -----------------------------------------------------------------------------
resource "aws_dynamodb_table" "harvest_state" {
  #checkov:skip=CKV_AWS_28:Ephemeral sighting counters that expire within minutes (TTL); losing them only delays a block by one harvest, so point-in-time recovery would protect nothing
  count        = local.enable_pb05 ? 1 : 0
  name         = local.harvest_state_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "ipAddress"

  attribute {
    name = "ipAddress"
    type = "S"
  }

  ttl {
    attribute_name = "expiresAt"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = false
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.this.arn
  }

  tags = var.tags
}

# -----------------------------------------------------------------------------
# Harvester: alarm or schedule -> one edge event per PERSISTENT rate-limited IP.
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
  statement {
    sid       = "SightingState"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem"]
    resources = [aws_dynamodb_table.harvest_state[0].arn]
  }
  # The table is SSE-KMS with the SOAR key [inferred: Decrypt suffices for
  # item reads and writes through the table key; verify on apply].
  statement {
    sid       = "DecryptWithSoarKey"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.this.arn]
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
  #checkov:skip=CKV_AWS_116:Invoked asynchronously by EventBridge on an alarm transition or the schedule; a lost run only delays blocks until the next harvest, and failed PutEvents entries raise so Lambda's async retry re-publishes (the router drops duplicate ids)
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
      # Persistence (audit A2): >= 2 consecutive harvests before publishing.
      HARVEST_STATE_TABLE     = aws_dynamodb_table.harvest_state[0].name
      HARVEST_MIN_GAP_SECONDS = tostring(var.pb05_harvest_min_gap_seconds)
      HARVEST_MAX_GAP_SECONDS = tostring(var.pb05_harvest_max_gap_seconds)
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.harvester,
    aws_iam_role_policy.harvester,
    aws_iam_role_policy.harvester_runtime,
  ]

  tags = var.tags
}

# The PB-05 feed rule (SoarApiRateLimit, /api/* only) firing at all -> ALARM.
# Dimensions for CLOUDFRONT scope are [inferred] (verify-on-apply #12):
# WebACL = the ACL's metric name, Rule = the rule's metric name; modules/edge
# sets both equal to the names.
resource "aws_cloudwatch_metric_alarm" "rate_limited" {
  count               = local.enable_pb05 ? 1 : 0
  alarm_name          = "${var.name}-soar-pb05-rate-limited"
  alarm_description   = "PB-05: the /api/* rate rule (SoarApiRateLimit) is blocking clients; EventBridge runs the harvester on the transition to ALARM."
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

# On by default (audit A2): the scheduled harvest provides the second
# consecutive sighting, and catches IPs that become rate-limited while the
# alarm is already in ALARM. null turns it off.
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
