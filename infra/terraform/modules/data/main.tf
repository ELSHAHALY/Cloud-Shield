###############################################################################
# Module: data — TB3 "AWS data plane (data at rest)"   Owner: S2
#
#   DynamoDB  documents  PK tenantId / SK docId     (tenant metadata)
#   DynamoDB  audit      PK tenantId / SK eventKey  (FR-4, append-only)
#   S3        documents  objects under <tenantId>/  (accessed via pre-signed URLs)
#   KMS       one CMK for all of the above
#
# Tenant isolation model (be precise about this in the viva):
#   The single task role can technically reach every tenant's items. Isolation
#   is enforced in the API from the Cognito JWT tenant claim, and every key is
#   tenant-prefixed so a missing check is visible in code review and in the
#   audit table. Per-request ABAC (STS session tags + dynamodb:LeadingKeys) is
#   the stronger design and is listed as a stretch goal in docs/adr/0002.
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  partition   = data.aws_partition.current.partition
  bucket_name = "${var.name}-documents-${local.account_id}"
}

# -----------------------------------------------------------------------------
# KMS
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "kms" {
  #checkov:skip=CKV_AWS_111:Key policy — Resource "*" means "this key"; access is granted to the task role via IAM below
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
}

resource "aws_kms_key" "this" {
  description             = "${var.name} tenant data (DynamoDB + S3 documents)"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.kms.json
  tags                    = var.tags
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name}-data"
  target_key_id = aws_kms_key.this.key_id
}

# -----------------------------------------------------------------------------
# DynamoDB
# -----------------------------------------------------------------------------
resource "aws_dynamodb_table" "documents" {
  name                        = "${var.name}-documents"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "tenantId"
  range_key                   = "docId"
  deletion_protection_enabled = var.table_deletion_protection

  attribute {
    name = "tenantId"
    type = "S"
  }
  attribute {
    name = "docId"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true # plan §3.3 NFR
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.this.arn
  }

  tags = var.tags
}

resource "aws_dynamodb_table" "audit" {
  name                        = "${var.name}-audit"
  stream_enabled              = true
  stream_view_type            = "NEW_AND_OLD_IMAGES" # tamper evidence: old image survives an overwrite
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "tenantId"
  range_key                   = "eventKey" # "<ISO-8601 UTC>#<requestId>" — sortable, unique
  deletion_protection_enabled = var.table_deletion_protection

  attribute {
    name = "tenantId"
    type = "S"
  }
  attribute {
    name = "eventKey"
    type = "S"
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
# S3 documents bucket
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "documents" {
  #checkov:skip=CKV_AWS_18:Server access logs cannot target the SSE-KMS log archive. Compensating control = CloudTrail S3 data events, which arrive with the detection module (NOT built yet — tracked in README gaps)
  #checkov:skip=CKV_AWS_144:Cross-region replication out of scope (single-region by design, plan §1.2)
  #checkov:skip=CKV2_AWS_62:No event-driven processing of uploads in scope
  bucket        = local.bucket_name
  force_destroy = var.documents_bucket_force_destroy
  tags          = var.tags
}

resource "aws_s3_bucket_versioning" "documents" {
  bucket = aws_s3_bucket.documents.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "documents" {
  bucket = aws_s3_bucket.documents.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "documents" {
  bucket                  = aws_s3_bucket.documents.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "documents" {
  bucket = aws_s3_bucket.documents.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_lifecycle_configuration" "documents" {
  bucket = aws_s3_bucket.documents.id
  rule {
    id     = "expire-noncurrent"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration { noncurrent_days = 30 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

data "aws_iam_policy_document" "documents_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.documents.arn, "${aws_s3_bucket.documents.arn}/*"]
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

  # If a writer explicitly names a KMS key, it must be this bucket's CMK.
  # Requests that name no key get the bucket default (this CMK) and are
  # allowed. NOTE: "StringNotEqualsIfExists" would be wrong here — IfExists
  # evaluates TRUE when the header is absent, which would deny every normal
  # upload, including pre-signed PUTs.
  statement {
    sid       = "DenyForeignKmsKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.documents.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = ["false"] # header present…
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.this.arn] # …and names some other key
    }
  }

  # SSE-S3 (AES256) would still be encrypted, but not under the tenant-data
  # CMK (no key policy, no CloudTrail key-usage trail). Deny it explicitly.
  statement {
    sid       = "DenyNonKmsEncryptionHeader"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.documents.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["false"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  # Caps pre-signed URL lifetime server-side, whatever the app asks for.
  statement {
    sid       = "DenyLongLivedPresignedUrls"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["${aws_s3_bucket.documents.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "NumericGreaterThan"
      variable = "s3:signatureAge"
      values   = [tostring(var.presigned_url_max_seconds * 1000)]
    }
  }
}

resource "aws_s3_bucket_policy" "documents" {
  bucket     = aws_s3_bucket.documents.id
  policy     = data.aws_iam_policy_document.documents_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.documents]
}

# -----------------------------------------------------------------------------
# Data-plane access for the app task role
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "app" {
  statement {
    sid = "DocumentsTableCrud"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      "dynamodb:Query",
      "dynamodb:ConditionCheckItem",
    ]
    resources = [aws_dynamodb_table.documents.arn]
  }

  # Insert-only BY CONVENTION, not by IAM: no IAM condition key can force
  # attribute_not_exists on PutItem, so PutItem CAN overwrite an existing
  # event. Controls: (1) no UpdateItem/DeleteItem here; (2) the app MUST send
  # ConditionExpression "attribute_not_exists(eventKey)"; (3) the table
  # stream records every MODIFY/REMOVE for tamper detection (detection
  # module alarms on it); (4) PITR allows recovery.
  statement {
    sid       = "AuditAppendOnly"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.audit.arn]
  }
  statement {
    sid       = "AuditRead"
    actions   = ["dynamodb:Query", "dynamodb:GetItem"]
    resources = [aws_dynamodb_table.audit.arn]
  }

  statement {
    sid       = "DocumentObjects"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.documents.arn}/*"]
  }

  statement {
    sid       = "UseDataKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.this.arn]
  }
}

resource "aws_iam_role_policy" "app" {
  name   = "data-plane"
  role   = var.app_task_role_name
  policy = data.aws_iam_policy_document.app.json
}
