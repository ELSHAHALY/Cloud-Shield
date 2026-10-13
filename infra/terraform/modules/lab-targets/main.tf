###############################################################################
# Module: lab-targets — in-scope targets for the scenario B / C simulations
# (plan §7, decision D2). Created only when the environment sets
# enable_lab_targets = true. Owner: S3 (@ahklsfg).
#
#   honeytoken user  no policies (it can do nothing), capped by the SOAR target
#                    boundary so PB-02 may revoke its sessions (audit A2).
#                    NO access key here: a key in Terraform state would be a
#                    real secret at rest. The simulation creates a key at run
#                    time and deletes it in cleanup.
#   lab bucket       Block Public Access ON at rest. Only the scenario C
#                    simulation turns it off, for a bounded window, and always
#                    restores it. No public policy, no data exposed.
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  bucket_name = "${var.name}-lab-exposure-${data.aws_caller_identity.current.account_id}"
}

resource "aws_iam_user" "honeytoken" {
  #checkov:skip=CKV_AWS_273:Deliberate IAM user: scenario B models a leaked long-term access key (T1552.001), which SSO cannot represent
  name                 = "${var.name}-honeytoken"
  path                 = "/cloudshield/lab/"
  permissions_boundary = var.soar_target_boundary_arn
  force_destroy        = true # the sim's runtime keys and PB-02's inline revoke policy must not block teardown
  tags                 = merge(var.tags, var.soar_scope_tag, { Purpose = "scenario-b-honeytoken" })
}

resource "aws_s3_bucket" "lab" {
  #checkov:skip=CKV_AWS_18:Object-level access is recorded by CloudTrail S3 data events (modules/detection data_event_bucket_arns)
  #checkov:skip=CKV_AWS_144:Cross-region replication out of scope for a lab target
  #checkov:skip=CKV2_AWS_62:No event-driven processing on the lab bucket
  #checkov:skip=CKV_AWS_145:SSE-S3 is sufficient for a bucket that holds only a synthetic canary object
  bucket        = local.bucket_name
  force_destroy = true
  tags          = merge(var.tags, var.soar_scope_tag, { Purpose = "scenario-c-exposure" })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lab" {
  bucket = aws_s3_bucket.lab.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "lab" {
  bucket = aws_s3_bucket.lab.id
  versioning_configuration { status = "Enabled" }
}

# ON at rest. The scenario C simulation flips it off and back; PB-03 restores
# it on the resulting GuardDuty Policy:S3 finding. Changes made outside
# Terraform here are expected: the next apply simply re-asserts true.
resource "aws_s3_bucket_public_access_block" "lab" {
  bucket                  = aws_s3_bucket.lab.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "lab" {
  bucket = aws_s3_bucket.lab.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_lifecycle_configuration" "lab" {
  bucket = aws_s3_bucket.lab.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration { days = 30 }
    noncurrent_version_expiration { noncurrent_days = 7 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

data "aws_iam_policy_document" "lab" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.lab.arn, "${aws_s3_bucket.lab.arn}/*"]
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

resource "aws_s3_bucket_policy" "lab" {
  bucket     = aws_s3_bucket.lab.id
  policy     = data.aws_iam_policy_document.lab.json
  depends_on = [aws_s3_bucket_public_access_block.lab]
}

# A synthetic canary object, so scenario C data-event queries have something
# to show. Contains no real data.
resource "aws_s3_object" "canary" {
  bucket       = aws_s3_bucket.lab.id
  key          = "canary/README.txt"
  content      = "CloudShield lab canary object. Synthetic, contains no real data.\n"
  content_type = "text/plain"
}
