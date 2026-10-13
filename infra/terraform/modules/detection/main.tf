###############################################################################
# Module: detection — TB5 "Security account"   Owner: S3 (@ahklsfg)
#
#   main.tf        GuardDuty detector (+ findings export), Security Hub, Config
#   cloudtrail.tf  multi-region trail, S3 data events on the sensitive buckets
#   athena.tf      cs-forensics workgroup (scan cap), Glue catalog, named queries
#
# Defaults (decision D3): GuardDuty, CloudTrail, Config (S3 buckets only) and
# Athena ON; Security Hub and the paid GuardDuty protections OFF.
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition

  config_rule_names = {
    public_read  = "${var.name}-s3-bucket-public-read-prohibited"
    public_write = "${var.name}-s3-bucket-public-write-prohibited"
  }
}

# -----------------------------------------------------------------------------
# GuardDuty — feeds the SOAR EventBridge rule (modules/soar)
# -----------------------------------------------------------------------------
resource "aws_guardduty_detector" "this" {
  #checkov:skip=CKV2_AWS_3:Single-account lab (ADR-0001); this IS the detector that feeds cs-ir-router. Org/region delegated-admin enrolment is the multi-account target state, not this build
  count                        = var.manage_guardduty_detector ? 1 : 0
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES" # export cadence; EventBridge gets new findings immediately
  tags                         = var.tags
}

locals {
  detector_id = one(aws_guardduty_detector.this[*].id)

  guardduty_features = var.manage_guardduty_detector ? {
    S3_DATA_EVENTS         = var.guardduty_s3_protection
    EBS_MALWARE_PROTECTION = var.guardduty_malware_protection
  } : {}
}

resource "aws_guardduty_detector_feature" "toggle" {
  for_each    = local.guardduty_features
  detector_id = local.detector_id
  name        = each.key
  status      = each.value ? "ENABLED" : "DISABLED"
}

resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  count       = var.manage_guardduty_detector ? 1 : 0
  detector_id = local.detector_id
  name        = "RUNTIME_MONITORING"
  status      = var.guardduty_runtime_monitoring ? "ENABLED" : "DISABLED"

  additional_configuration {
    name   = "ECS_FARGATE_AGENT_MANAGEMENT"
    status = var.guardduty_runtime_monitoring ? "ENABLED" : "DISABLED"
  }
}

# Findings -> log archive, for the Athena guardduty_findings table. The bucket
# and key policies that allow this live in modules/log-archive.
resource "aws_guardduty_publishing_destination" "log_archive" {
  count           = var.manage_guardduty_detector && var.guardduty_export_findings ? 1 : 0
  detector_id     = local.detector_id
  destination_arn = "${var.log_archive_bucket_arn}/guardduty"
  kms_key_arn     = var.log_archive_kms_key_arn
}

# -----------------------------------------------------------------------------
# Security Hub (off by default)
# -----------------------------------------------------------------------------
resource "aws_securityhub_account" "this" {
  count                    = var.enable_security_hub ? 1 : 0
  enable_default_standards = false # only the standards chosen below
}

resource "aws_securityhub_standards_subscription" "cis" {
  count         = var.enable_security_hub && var.securityhub_cis ? 1 : 0
  standards_arn = "arn:${local.partition}:securityhub:${local.region}::standards/cis-aws-foundations-benchmark/v/3.0.0"
  depends_on    = [aws_securityhub_account.this]
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  count         = var.enable_security_hub && var.securityhub_pci_dss ? 1 : 0
  standards_arn = "arn:${local.partition}:securityhub:${local.region}::standards/pci-dss/v/3.2.1"
  depends_on    = [aws_securityhub_account.this]
}

# -----------------------------------------------------------------------------
# AWS Config — S3 buckets only (cost), two managed public-access rules.
# A region holds ONE recorder; import an existing one (README).
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "config_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "config" {
  count              = var.enable_config ? 1 : 0
  name               = "${var.name}-config-recorder"
  assume_role_policy = data.aws_iam_policy_document.config_trust.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

data "aws_iam_policy_document" "config_delivery" {
  statement {
    sid       = "DeliverUnderConfigPrefix"
    actions   = ["s3:PutObject"]
    resources = ["${var.log_archive_bucket_arn}/config/AWSLogs/${local.account_id}/Config/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
  statement {
    sid       = "CheckBucket"
    actions   = ["s3:GetBucketAcl"]
    resources = [var.log_archive_bucket_arn]
  }
  statement {
    sid       = "EncryptDeliveries"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [var.log_archive_kms_key_arn]
  }
}

resource "aws_iam_role_policy" "config_delivery" {
  count  = var.enable_config ? 1 : 0
  name   = "deliver-to-log-archive"
  role   = aws_iam_role.config[0].id
  policy = data.aws_iam_policy_document.config_delivery.json
}

resource "aws_config_configuration_recorder" "this" {
  #checkov:skip=CKV2_AWS_48:Deliberately S3-buckets-only to bound Config cost (plan §6.1); scenario C only needs S3 public-access evaluation
  count    = var.enable_config ? 1 : 0
  name     = "${var.name}-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types                = ["AWS::S3::Bucket"]
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

resource "aws_config_delivery_channel" "this" {
  count          = var.enable_config ? 1 : 0
  name           = "${var.name}-delivery"
  s3_bucket_name = var.log_archive_bucket_name
  s3_key_prefix  = "config"
  s3_kms_key_arn = var.log_archive_kms_key_arn

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.this, aws_iam_role_policy.config_delivery]
}

resource "aws_config_configuration_recorder_status" "this" {
  #checkov:skip=CKV2_AWS_45:Recorder is enabled but scoped to AWS::S3::Bucket on purpose (cost); see CKV2_AWS_48 skip
  count      = var.enable_config ? 1 : 0
  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.this]
}

resource "aws_config_config_rule" "s3_public_read" {
  count = var.enable_config ? 1 : 0
  name  = local.config_rule_names.public_read
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }
  depends_on = [aws_config_configuration_recorder_status.this]
  tags       = var.tags
}

resource "aws_config_config_rule" "s3_public_write" {
  count = var.enable_config ? 1 : 0
  name  = local.config_rule_names.public_write
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }
  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }
  depends_on = [aws_config_configuration_recorder_status.this]
  tags       = var.tags
}

# NON_COMPLIANT -> SOAR topic (analyst). The router itself consumes GuardDuty
# findings only; scenario C containment is driven by GuardDuty Policy:S3/*.
# The rule NAME must match modules/soar `extra_notify_rule_names`.
resource "aws_cloudwatch_event_rule" "config_noncompliant" {
  count       = var.enable_config && var.notify_config_noncompliant ? 1 : 0
  name        = "${var.name}-soar-config-noncompliant"
  description = "Config S3 public-access rules -> NON_COMPLIANT -> analyst"
  event_pattern = jsonencode({
    source        = ["aws.config"]
    "detail-type" = ["Config Rules Compliance Change"]
    detail = {
      configRuleName      = values(local.config_rule_names)
      newEvaluationResult = { complianceType = ["NON_COMPLIANT"] }
    }
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "config_noncompliant" {
  count     = length(aws_cloudwatch_event_rule.config_noncompliant)
  rule      = aws_cloudwatch_event_rule.config_noncompliant[0].name
  target_id = "notify-analyst"
  arn       = var.notify_sns_topic_arn
}
