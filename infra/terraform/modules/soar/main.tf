###############################################################################
# Module: soar — TB5 "Security account (highest trust)"   Owner: S3
#
# Always on (works today, no code needed):
#   KMS · SNS incident topic · incidents table · evidence bucket ·
#   SSM dry-run + scope-tag parameters · EventBridge rule for GuardDuty
#   -> while playbooks are disabled, findings go straight to SNS (analyst
#      still gets notified: a useful, honest baseline).
#
# Gated by var.playbook_package != null:
#   playbooks.tf     Lambda functions + per-playbook least-privilege roles
#   state-machine.tf Step Functions "cs-ir-router"; EventBridge retargets to it
#   edge-bus.tf      PB-05 only: dedicated edge bus, never-block list, harvester
#                    (+ its sighting table)
#   pb05-sweeper.tf  PB-05 only: lifts blocks whose blockExpiresAt has passed
#   notify.tf        ChatOps notifier, only with chatops_webhook_param_name
#
# MTTC (plan §2.4, decision 8 Oct): measured from the EventBridge event `time`
# to the CONTAINED transition. Both the event time and GuardDuty's own
# `createdAt` are stored on the incident row for auditability.
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id       = data.aws_caller_identity.current.account_id
  region           = data.aws_region.current.region
  partition        = data.aws_partition.current.partition
  enable_playbooks = var.playbook_package != null
  scope_tag_key    = keys(var.soar_scope_tag)[0]
  scope_tag_value  = values(var.soar_scope_tag)[0]
  ssm_prefix       = "/${var.name}/soar"

  # Phase D (plan §4.3): plan-time bools, and nothing without the package.
  enable_pb04       = var.enable_pb04 && local.enable_playbooks
  enable_pb05       = var.enable_pb05 && local.enable_playbooks
  edge_event_source = "cloudshield.edge"
}

# -----------------------------------------------------------------------------
# KMS
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "kms" {
  #checkov:skip=CKV_AWS_111:Key policy — Resource "*" means "this key"; access is constrained by principal + conditions
  #checkov:skip=CKV_AWS_356:Key policy — Resource "*" is the only valid value inside a KMS key policy
  #checkov:skip=CKV_AWS_109:Root kms:* is the AWS default key-policy baseline; prevents an unmanageable key
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  # EventBridge publishing to the KMS-encrypted SNS topic.
  statement {
    sid       = "EventBridgeToEncryptedSns"
    actions   = ["kms:GenerateDataKey*", "kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  # A CMK-encrypted state machine with CloudWatch logging needs the log
  # delivery service to be able to decrypt execution data (AWS Step
  # Functions "encryption at rest" docs).
  statement {
    sid       = "StepFunctionsLogDelivery"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid = "CloudWatchLogsForSoarOnly"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values = [
        "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/${var.name}/soar/*",
        "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${var.name}-soar-*",
      ]
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "${var.name} SOAR (incidents, evidence, notifications, logs)"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.kms.json
  tags                    = var.tags
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name}-soar"
  target_key_id = aws_kms_key.this.key_id
}

# -----------------------------------------------------------------------------
# SNS — analyst notifications
# -----------------------------------------------------------------------------
resource "aws_sns_topic" "incidents" {
  name              = "${var.name}-soar-incidents"
  kms_master_key_id = aws_kms_key.this.arn
  tags              = var.tags
}

data "aws_iam_policy_document" "sns" {
  statement {
    sid       = "EventBridgeGuardDutyRuleOnly"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.incidents.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.guardduty.arn]
    }
  }
  # Other notify-only rules (e.g. modules/detection Config NON_COMPLIANT),
  # named rather than referenced so detection -> soar has no cycle.
  dynamic "statement" {
    for_each = length(var.extra_notify_rule_names) > 0 ? [1] : []
    content {
      sid       = "EventBridgeExtraNotifyRules"
      actions   = ["sns:Publish"]
      resources = [aws_sns_topic.incidents.arn]
      principals {
        type        = "Service"
        identifiers = ["events.amazonaws.com"]
      }
      condition {
        test     = "ArnEquals"
        variable = "aws:SourceArn"
        values   = [for n in var.extra_notify_rule_names : "arn:${local.partition}:events:${local.region}:${local.account_id}:rule/${n}"]
      }
    }
  }
}

resource "aws_sns_topic_policy" "incidents" {
  arn    = aws_sns_topic.incidents.arn
  policy = data.aws_iam_policy_document.sns.json
}

resource "aws_sns_topic_subscription" "email" {
  for_each  = toset(var.notification_emails)
  topic_arn = aws_sns_topic.incidents.arn
  protocol  = "email"
  endpoint  = each.value
}

# -----------------------------------------------------------------------------
# Incidents table — the SOC dashboard / MTTC source of truth (plan §8.4, §8.8)
#   incidentId = GuardDuty finding id -> re-delivered findings are idempotent
# -----------------------------------------------------------------------------
resource "aws_dynamodb_table" "incidents" {
  name         = "${var.name}-soar-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incidentId"

  attribute {
    name = "incidentId"
    type = "S"
  }
  attribute {
    name = "status"
    type = "S"
  }
  attribute {
    name = "eventTime"
    type = "S"
  }

  # Dashboard query: "all CONTAINED incidents, newest first".
  global_secondary_index {
    name            = "status-eventTime"
    hash_key        = "status"
    range_key       = "eventTime"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.this.arn
  }

  tags = var.tags
}

# -----------------------------------------------------------------------------
# Evidence bucket — snapshot manifests, SHA-256 hashes, chain-of-custody
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "evidence" {
  #checkov:skip=CKV_AWS_18:Server access logs cannot target the SSE-KMS log archive. Compensating control = CloudTrail S3 data events, which arrive with the detection module (NOT built yet — tracked in README gaps)
  #checkov:skip=CKV_AWS_144:Cross-region replication out of scope (single-region by design, plan §1.2)
  #checkov:skip=CKV2_AWS_62:No event-driven processing of evidence
  bucket              = "${var.name}-soar-evidence-${local.account_id}"
  force_destroy       = var.evidence_force_destroy
  object_lock_enabled = var.evidence_object_lock_days > 0
  tags                = var.tags
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  count  = var.evidence_object_lock_days > 0 ? 1 : 0
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.evidence_object_lock_days
    }
  }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    id     = "abort-multipart"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

data "aws_iam_policy_document" "evidence_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket     = aws_s3_bucket.evidence.id
  policy     = data.aws_iam_policy_document.evidence_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.evidence]
}

# -----------------------------------------------------------------------------
# Runtime switches read by the safety guard on EVERY execution
# -----------------------------------------------------------------------------
resource "aws_ssm_parameter" "dry_run" {
  #checkov:skip=CKV2_AWS_34:Non-secret feature flag; SecureString adds KMS calls on the containment hot path for no confidentiality gain
  name        = "${local.ssm_prefix}/dry_run"
  description = "SOAR global dry-run switch. 'true' = playbooks change nothing. Managed by Terraform (var.dry_run)."
  type        = "String"
  value       = var.dry_run ? "true" : "false"
  tags        = var.tags
}

resource "aws_ssm_parameter" "scope_tag" {
  #checkov:skip=CKV2_AWS_34:Non-secret configuration
  name        = "${local.ssm_prefix}/scope_tag"
  description = "Tag key/value the safety guard requires on a target resource."
  type        = "String"
  value       = jsonencode({ key = local.scope_tag_key, value = local.scope_tag_value })
  tags        = var.tags
}

# -----------------------------------------------------------------------------
# EventBridge — GuardDuty findings at or above min_severity.
# NOTE: requires an enabled GuardDuty detector (future detection module, or
# `aws guardduty create-detector --enable` for now).
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "${var.name}-soar-guardduty"
  description = "GuardDuty findings >= ${var.min_severity} or scoped types -> SOAR"
  # Severity threshold OR an explicitly scoped finding type. The extra types
  # are below High but are exactly what scenarios A and C produce
  # (Recon:EC2/Portscan is Medium; Policy:S3/* are Low).
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      "$or" = [
        { severity = [{ numeric = [">=", var.min_severity] }] },
        { type = var.always_route_finding_types },
      ]
    }
  })
  tags = var.tags
}

# Baseline target while playbooks are disabled.
resource "aws_cloudwatch_event_target" "sns" {
  count     = local.enable_playbooks ? 0 : 1
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "notify-analyst"
  arn       = aws_sns_topic.incidents.arn
}

# -----------------------------------------------------------------------------
# Permissions boundary for SOAR TARGETS (M10).
# PB-01 may attach an inline policy to the report-worker role, and PB-02 to the
# honeytoken user, in order to revoke sessions. iam:Put*Policy accepts ANY
# document, so without a boundary a compromised playbook could grant those
# principals admin. Their effective permissions can never exceed this boundary,
# and IAM only lets the playbooks write to principals that carry it.
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "target_boundary" {
  #checkov:skip=CKV_AWS_111:Permissions BOUNDARY — caps the maximum a principal can ever do; grants nothing by itself
  #checkov:skip=CKV_AWS_356:SSM agent channels and the Describe/List reads have no resource-level permissions
  statement {
    sid = "SessionManagerCore"
    actions = [
      "ssm:UpdateInstanceInformation",
      "ssm:ListAssociations",
      "ssm:ListInstanceAssociations",
      "ssm:DescribeAssociation",
      "ssm:GetDocument",
      "ssm:DescribeDocument",
      "ssm:GetManifest",
      "ssm:PutInventory",
      "ssm:PutComplianceItems",
      "ssm:PutConfigurePackageResult",
      "ssm:UpdateAssociationStatus",
      "ssm:UpdateInstanceAssociationStatus",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
      "ec2messages:AcknowledgeMessage",
      "ec2messages:DeleteMessage",
      "ec2messages:FailMessage",
      "ec2messages:GetEndpoint",
      "ec2messages:GetMessages",
      "ec2messages:SendReply",
    ]
    resources = ["*"]
  }
  # Low-value reads that attack scenarios A/B use to generate anomalous API
  # activity for GuardDuty. Reads only; no data-plane access.
  statement {
    sid = "ScenarioReconReadsOnly"
    actions = [
      "sts:GetCallerIdentity",
      "ec2:DescribeInstances",
      "ec2:DescribeRegions",
      "s3:ListAllMyBuckets",
      "iam:ListUsers",
      "iam:ListRoles",
    ]
    resources = ["*"]
  }
  # Deny statements in an inline policy written by a playbook (session
  # revocation) still work: a boundary only caps Allows.
}

resource "aws_iam_policy" "target_boundary" {
  #checkov:skip=CKV_AWS_290:Boundary caps a principal's maximum permissions; it grants nothing by itself
  #checkov:skip=CKV_AWS_355:SSM agent, ssmmessages, ec2messages and the Describe/List reads have no resource-level permissions
  #checkov:skip=CKV_AWS_289:Same — boundary policy, grants nothing by itself
  name        = "${var.name}-soar-target-boundary"
  description = "Max permissions for any principal SOAR playbooks may write inline policies onto"
  policy      = data.aws_iam_policy_document.target_boundary.json
  tags        = var.tags
}
