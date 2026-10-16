###############################################################################
# WAF log bucket (F1, decision D8). WAF delivers to S3 only into a bucket whose
# name starts with "aws-waf-logs-", so it cannot use the main archive bucket.
# Same archive key (its AllowLogDelivery statement already trusts
# delivery.logs.amazonaws.com for this account), same hardening.
#
# Key layout written by WAF: AWSLogs/<account>/WAFLogs/<region|cloudfront>/<web-acl>/yyyy/MM/dd/HH/mm/
# The name is outside PB-03's "<name>-*" bucket prefix on purpose: SOAR never
# touches it.
###############################################################################

locals {
  waf_bucket_name = "aws-waf-logs-${var.name}-${local.account_id}"
}

resource "aws_s3_bucket" "waf" {
  #checkov:skip=CKV_AWS_18:Log sink: server access logs of a log bucket would loop; CloudTrail management events record its configuration changes
  #checkov:skip=CKV_AWS_144:Cross-region replication out of scope (single-region by design, plan §1.2)
  #checkov:skip=CKV2_AWS_62:No event-driven processing; logs are queried with Athena (waf_logs table)
  count         = var.enable_waf_logs ? 1 : 0
  bucket        = local.waf_bucket_name
  force_destroy = var.force_destroy
  tags          = var.tags
}

resource "aws_s3_bucket_versioning" "waf" {
  count  = var.enable_waf_logs ? 1 : 0
  bucket = aws_s3_bucket.waf[0].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "waf" {
  count  = var.enable_waf_logs ? 1 : 0
  bucket = aws_s3_bucket.waf[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "waf" {
  count                   = var.enable_waf_logs ? 1 : 0
  bucket                  = aws_s3_bucket.waf[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "waf" {
  count  = var.enable_waf_logs ? 1 : 0
  bucket = aws_s3_bucket.waf[0].id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_lifecycle_configuration" "waf" {
  count  = var.enable_waf_logs ? 1 : 0
  bucket = aws_s3_bucket.waf[0].id

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

# AWS-documented WAF -> S3 delivery statements, scoped to this account.
data "aws_iam_policy_document" "waf_bucket" {
  count = var.enable_waf_logs ? 1 : 0

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.waf[0].arn, "${aws_s3_bucket.waf[0].arn}/*"]
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

  statement {
    sid       = "AWSLogDeliveryAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.waf[0].arn]
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
    sid       = "AWSLogDeliveryWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.waf[0].arn}/AWSLogs/${local.account_id}/*"]
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

resource "aws_s3_bucket_policy" "waf" {
  count  = var.enable_waf_logs ? 1 : 0
  bucket = aws_s3_bucket.waf[0].id
  policy = data.aws_iam_policy_document.waf_bucket[0].json

  depends_on = [aws_s3_bucket_public_access_block.waf]
}
