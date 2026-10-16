###############################################################################
# ChatOps notifier (plan §5.1, D16) — only when chatops_webhook_param_name is
# set (a variable, so the count is known at plan time) AND the playbook
# package exists (the notifier ships in the same zip).
#
#   incidents SNS topic ─► notifier Lambda ─► GetItem(incident row)
#                                          └► SSM SecureString (webhook URL)
#                                          └► HTTPS POST, exact-host allow-list
#
# The webhook URL is a credential. The operator creates the SecureString out
# of band, encrypted with this module's key (docs/runbooks/chatops-setup.md),
# so the URL never enters Terraform state, a plan or this repository:
# Terraform only knows the parameter NAME.
###############################################################################

locals {
  enable_notifier = var.chatops_webhook_param_name != "" && local.enable_playbooks
  notifier_name   = "${var.name}-soar-notifier"

  # The ARN of a parameter whose name starts with "/" is ".../parameter/<path>".
  chatops_webhook_param_arn = "arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter${var.chatops_webhook_param_name}"
}

# Exactly four grants (plan §5.1): the one parameter, the one table's GetItem,
# decrypt with the SOAR key (SecureString + table SSE), and its own logs.
data "aws_iam_policy_document" "notifier" {
  count = local.enable_notifier ? 1 : 0

  statement {
    sid       = "ReadWebhookParameter"
    actions   = ["ssm:GetParameter"]
    resources = [local.chatops_webhook_param_arn]
  }
  statement {
    sid       = "ReadIncidentRow"
    actions   = ["dynamodb:GetItem"]
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
    resources = ["${aws_cloudwatch_log_group.notifier[0].arn}:*"]
  }
}

resource "aws_iam_role" "notifier" {
  count              = local.enable_notifier ? 1 : 0
  name               = local.notifier_name
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "notifier" {
  count  = local.enable_notifier ? 1 : 0
  name   = "notify"
  role   = aws_iam_role.notifier[0].id
  policy = data.aws_iam_policy_document.notifier[0].json
}

resource "aws_cloudwatch_log_group" "notifier" {
  #checkov:skip=CKV_AWS_338:30-day retention is a deliberate lab cost choice; incident records live in DynamoDB (PITR) and the evidence bucket
  count             = local.enable_notifier ? 1 : 0
  name              = "/aws/lambda/${local.notifier_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
  tags              = var.tags
}

resource "aws_lambda_function" "notifier" {
  #checkov:skip=CKV_AWS_116:SNS invokes this function asynchronously, but its contract is to never raise (every failure returns posted=false and is logged), so Lambda's async retries and a DLQ would never receive anything; the incident row and the email subscription remain the record of truth
  #checkov:skip=CKV_AWS_117:Only calls SSM, DynamoDB and one allow-listed HTTPS webhook host; a VPC attachment would add a NAT dependency to the notification path
  #checkov:skip=CKV_AWS_272:Code signing deferred; the package comes from the gated CI pipeline (stretch goal: AWS Signer profile)
  #checkov:skip=CKV_AWS_115:Reserved concurrency is a variable; default -1 because new accounts (limit 10) reject any reservation — set 5 once the quota allows
  #checkov:skip=CKV_AWS_50:X-Ray tracing would need xray:Put* on the role; the notifier's role is deliberately exactly SSM/DynamoDB/KMS/logs (plan §5.1), and it is outside the containment (MTTC) path
  count         = local.enable_notifier ? 1 : 0
  function_name = local.notifier_name
  role          = aws_iam_role.notifier[0].arn
  runtime       = "python3.13"
  architectures = ["arm64"]
  handler       = "notifier.handler.lambda_handler"
  timeout       = 15 # SSM + GetItem + one 3 s webhook POST
  memory_size   = 128
  kms_key_arn   = aws_kms_key.this.arn

  s3_bucket         = var.playbook_package.s3_bucket
  s3_key            = var.playbook_package.s3_key
  s3_object_version = var.playbook_package.s3_object_version

  reserved_concurrent_executions = var.lambda_reserved_concurrency

  environment {
    variables = {
      INCIDENTS_TABLE       = aws_dynamodb_table.incidents.name
      CHATOPS_WEBHOOK_PARAM = var.chatops_webhook_param_name
      CHATOPS_ALLOWED_HOSTS = join(",", var.chatops_allowed_hosts)
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.notifier,
    aws_iam_role_policy.notifier,
  ]

  tags = var.tags
}

resource "aws_sns_topic_subscription" "notifier" {
  count     = local.enable_notifier ? 1 : 0
  topic_arn = aws_sns_topic.incidents.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.notifier[0].arn
}

resource "aws_lambda_permission" "notifier" {
  count         = local.enable_notifier ? 1 : 0
  statement_id  = "AllowIncidentTopic"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.notifier[0].function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.incidents.arn
}
