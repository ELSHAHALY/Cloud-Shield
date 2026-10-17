###############################################################################
# Phase E (plan §9, D13, D16): the docs-api task role's window into TB5.
#
# The owner of the data decides who touches it (same principle as
# modules/data): this module attaches a READ-ONLY policy to the app task role
# so the SOC dashboard can read incidents, verify evidence hashes and show
# the dry-run switch. It never grants writes, Scan or kms:GenerateDataKey.
#
#   IncidentsGetItem      GetItem on the incidents table
#   IncidentsQueryIndex   Query on the status-eventTime index ONLY (no Scan;
#                         the base table is never queried)
#   EvidenceRead          object reads under incidents/ only, incl. pinned
#                         versions, retention and legal hold
#   EvidenceLockConfig    the bucket's Object Lock configuration (honest
#                         "not enabled" in the UI)
#   SoarKeyDecrypt        kms:Decrypt on the SOAR key (table + bucket SSE),
#                         only via dynamodb / s3 / ssm (kms:ViaService)
#   DryRunSwitch          ssm:GetParameter on the dry-run parameter
#   PublishDecoy          only with PB-05 AND app_publishes_decoy:
#                         events:PutEvents on the edge bus, pinned to
#                         source cloudshield.edge + detail-type
#                         "CloudShield Edge Finding". The guard treats the
#                         decoy type as notify-only (D13): no block.
#
# Residual risk (ADR-0006): a compromised task can read incident rows and
# evidence objects. Mitigations: read-only, the incidents/ prefix, CloudTrail
# S3 data events on the evidence bucket.
###############################################################################

locals {
  # Names and locals only (F35): the app environment never depends on a
  # resource attribute, so compute's task definition can consume it without
  # creating an edge back into this module's resources.
  app_incidents_table_name = "${var.name}-soar-incidents"
  app_evidence_bucket_name = "${var.name}-soar-evidence-${local.account_id}"
  app_dry_run_param_name   = "${local.ssm_prefix}/dry_run"
  app_incidents_index_name = "status-eventTime"

  app_publishes_decoy = local.enable_pb05 && var.app_publishes_decoy
}

data "aws_iam_policy_document" "app_soc_read" {
  count = var.enable_app_integration ? 1 : 0

  statement {
    sid       = "IncidentsGetItem"
    actions   = ["dynamodb:GetItem"]
    resources = [aws_dynamodb_table.incidents.arn]
  }
  statement {
    sid       = "IncidentsQueryIndex"
    actions   = ["dynamodb:Query"]
    resources = ["${aws_dynamodb_table.incidents.arn}/index/${local.app_incidents_index_name}"]
  }
  statement {
    sid = "EvidenceRead"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:GetObjectRetention",
      "s3:GetObjectLegalHold",
    ]
    resources = ["${aws_s3_bucket.evidence.arn}/incidents/*"]
  }
  statement {
    sid       = "EvidenceLockConfig"
    actions   = ["s3:GetBucketObjectLockConfiguration"]
    resources = [aws_s3_bucket.evidence.arn]
  }
  # Decrypt only: the app reads SOAR-CMK data, it never encrypts with it.
  statement {
    sid       = "SoarKeyDecrypt"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.this.arn]
    # The SOAR key also encrypts the SNS topic and SOAR logs: only through the
    # services the SOC read actually uses (audit E11).
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["dynamodb.${local.region}.amazonaws.com", "s3.${local.region}.amazonaws.com", "ssm.${local.region}.amazonaws.com"]
    }
  }
  statement {
    sid       = "DryRunSwitch"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.dry_run.arn]
  }

  dynamic "statement" {
    for_each = local.app_publishes_decoy ? [1] : []
    content {
      sid       = "PublishDecoy"
      actions   = ["events:PutEvents"]
      resources = [aws_cloudwatch_event_bus.edge[0].arn]
      condition {
        test     = "StringEquals"
        variable = "events:source"
        values   = [local.edge_event_source]
      }
      condition {
        test     = "StringEquals"
        variable = "events:detail-type"
        values   = ["CloudShield Edge Finding"]
      }
    }
  }
}

resource "aws_iam_role_policy" "app_soc_read" {
  count  = var.enable_app_integration ? 1 : 0
  name   = "soar-soc-read"
  role   = var.app_task_role_name
  policy = data.aws_iam_policy_document.app_soc_read[0].json
}
