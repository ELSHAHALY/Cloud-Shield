###############################################################################
# Module: log-archive
# Central, KMS-encrypted S3 log archive (plan §6.1). In the single-account
# model it lives in the workload account; in the multi-account target it moves
# to the Security account unchanged — only the provider alias differs.
#
# Owner: S3 (SecOps). S1 consumes it for VPC Flow Logs.
# Currently grants write access to: VPC Flow Logs (delivery.logs.amazonaws.com).
# TODO(S3, Day 8–10): add CloudTrail + Config delivery statements here.
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  region      = data.aws_region.current.region
  partition   = data.aws_partition.current.partition
  bucket_name = "${var.name}-log-archive-${local.account_id}-${local.region}"
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

  # Required for VPC Flow Logs -> S3 with SSE-KMS. Without this statement the
  # flow log is created "successfully" but delivers nothing (silent failure).
  statement {
    sid = "AllowVpcFlowLogDelivery"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
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
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:*"]
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "${var.name} log archive encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.kms.json
  tags                    = var.tags
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name}-log-archive"
  target_key_id = aws_kms_key.this.key_id
}

# -----------------------------------------------------------------------------
# Bucket
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "this" {
  #checkov:skip=CKV_AWS_18:This bucket IS the access-log sink; logging it to itself loops
  #checkov:skip=CKV_AWS_144:Cross-region replication out of scope (single-region by design, plan §1.2)
  #checkov:skip=CKV2_AWS_62:Event notifications are added by the detection module when needed
  bucket        = local.bucket_name
  force_destroy = var.force_destroy

  # Object Lock can only be enabled at creation. It makes the archive
  # genuinely immutable, but it also makes `terraform destroy` fail until the
  # retention period passes — so it is OFF by default for the lab.
  object_lock_enabled = var.object_lock_retention_days > 0

  tags = var.tags
}

resource "aws_s3_bucket_object_lock_configuration" "this" {
  count  = var.object_lock_retention_days > 0 ? 1 : 0
  bucket = aws_s3_bucket.this.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.object_lock_retention_days
    }
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    id     = "tier-and-expire"
    status = "Enabled"
    filter {}

    transition {
      days          = var.glacier_transition_days
      storage_class = "GLACIER_IR"
    }
    expiration { days = var.expiration_days }
    noncurrent_version_expiration { noncurrent_days = 30 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

data "aws_iam_policy_document" "bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]
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

  # --- VPC Flow Logs delivery (AWS-documented statements) ---
  statement {
    sid       = "AWSLogDeliveryAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.this.arn]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:*"]
    }
  }

  statement {
    sid     = "AWSLogDeliveryWrite"
    actions = ["s3:PutObject"]
    # Not ".../AWSLogs/<account>/*" as in the AWS docs: with Hive-compatible
    # partitions (used for Athena) the key is "AWSLogs/aws-account-id=<id>/...",
    # which the docs pattern would NOT match -> silent delivery failure.
    # Account scoping is enforced by the aws:SourceAccount condition below.
    resources = ["${aws_s3_bucket.this.arn}/vpc-flow-logs/AWSLogs/*"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:*"]
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.bucket.json

  # BPA must exist first or a race can briefly evaluate the policy without it.
  depends_on = [aws_s3_bucket_public_access_block.this]
}
