###############################################################################
# PB-05 auto-expiry sweeper (audit A2, ADR-0005 D15) — only with enable_pb05.
#
#   schedule (default rate(15 minutes)) ─► sweeper Lambda
#   ─► Scan incidents (rows with blockedCidr) ─► group by (IP set, address)
#   ─► GetIPSet ─► remove ONLY row-tracked, expired, uncovered entries
#   ─► UpdateIPSet (LockToken, bounded retry) ─► read back
#   ─► blockLiftedAt + "unblock" action on the rows
#
# A short rate-limit must not become an indefinite block for everyone behind
# a shared egress IP. Untracked (orphan) entries are reported, never removed.
# The sweeper never reads the dry-run switch: it only undoes blocks PB-05
# made while live, and dry-run never creates one.
#
# Exactly four grants: Get/UpdateIPSet on the two IP sets, Scan/UpdateItem on
# the incidents table, kms:Decrypt on the SOAR key, and its own logs.
###############################################################################

locals {
  sweeper_name = "${var.name}-soar-pb05-sweeper"
}

data "aws_iam_policy_document" "sweeper" {
  count = local.enable_pb05 ? 1 : 0

  statement {
    sid       = "LiftExpiredBlocks"
    actions   = ["wafv2:GetIPSet", "wafv2:UpdateIPSet"]
    resources = var.block_ip_set_arns
  }
  statement {
    sid       = "TrackedBlockRows"
    actions   = ["dynamodb:Scan", "dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.incidents.arn]
  }
  statement {
    sid       = "DecryptWithSoarKey"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.this.arn]
  }
  statement {
    sid       = "OwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.sweeper[0].arn}:*"]
  }
}

resource "aws_iam_role" "sweeper" {
  count              = local.enable_pb05 ? 1 : 0
  name               = local.sweeper_name
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "sweeper" {
  count  = local.enable_pb05 ? 1 : 0
  name   = "sweep"
  role   = aws_iam_role.sweeper[0].id
  policy = data.aws_iam_policy_document.sweeper[0].json
}

resource "aws_cloudwatch_log_group" "sweeper" {
  #checkov:skip=CKV_AWS_338:30-day retention is a deliberate lab cost choice; every lift is also recorded on the incident row (blockLiftedAt + an unblock action)
  count             = local.enable_pb05 ? 1 : 0
  name              = "/aws/lambda/${local.sweeper_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
  tags              = var.tags
}

resource "aws_lambda_function" "sweeper" {
  #checkov:skip=CKV_AWS_116:Invoked asynchronously by an EventBridge schedule; a failed run lifts nothing (lifts are recorded only after the read-back) and the next scheduled run retries, so a DLQ adds nothing
  #checkov:skip=CKV_AWS_117:Only calls AWS control-plane APIs (WAFv2, DynamoDB); a VPC attachment would add a NAT dependency
  #checkov:skip=CKV_AWS_272:Code signing deferred; the package comes from the gated CI pipeline (stretch goal: AWS Signer profile)
  #checkov:skip=CKV_AWS_115:Reserved concurrency is a variable; default -1 because new accounts (limit 10) reject any reservation — set 5 once the quota allows
  #checkov:skip=CKV_AWS_50:X-Ray tracing would need xray:Put* on the role; the sweeper's role is deliberately exactly WAF/DynamoDB/KMS/logs (audit A2), and it is outside the containment (MTTC) path
  count         = local.enable_pb05 ? 1 : 0
  function_name = local.sweeper_name
  role          = aws_iam_role.sweeper[0].arn
  runtime       = "python3.13"
  architectures = ["arm64"]
  handler       = "playbooks.pb05_unblock_sweeper.lambda_handler"
  timeout       = 60
  memory_size   = 256
  kms_key_arn   = aws_kms_key.this.arn

  s3_bucket         = var.playbook_package.s3_bucket
  s3_key            = var.playbook_package.s3_key
  s3_object_version = var.playbook_package.s3_object_version

  reserved_concurrent_executions = var.lambda_reserved_concurrency

  environment {
    variables = {
      INCIDENTS_TABLE   = aws_dynamodb_table.incidents.name
      BLOCK_IP_SET_ARNS = join(",", var.block_ip_set_arns)
      WAF_REGION        = local.region
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.sweeper,
    aws_iam_role_policy.sweeper,
  ]

  tags = var.tags
}

resource "aws_cloudwatch_event_rule" "sweep" {
  count               = local.enable_pb05 ? 1 : 0
  name                = "${var.name}-soar-pb05-sweep"
  description         = "PB-05: lift WAF IP blocks whose blockExpiresAt has passed"
  schedule_expression = var.pb05_sweep_schedule
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "sweep" {
  count     = local.enable_pb05 ? 1 : 0
  rule      = aws_cloudwatch_event_rule.sweep[0].name
  target_id = "pb05-sweeper"
  arn       = aws_lambda_function.sweeper[0].arn
}

resource "aws_lambda_permission" "sweep" {
  count         = local.enable_pb05 ? 1 : 0
  statement_id  = "AllowSweepSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sweeper[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sweep[0].arn
}
