###############################################################################
# SPA origin: private bucket, readable only by THIS distribution through OAC.
###############################################################################

resource "aws_s3_bucket" "spa" {
  #checkov:skip=CKV_AWS_18:Same as the evidence bucket: server access logs are replaced by CloudTrail S3 data events + WAF logs of every viewer request (handoff gap 16)
  #checkov:skip=CKV_AWS_144:Cross-region replication out of scope (single-region by design, plan §1.2); the SPA is a rebuildable artefact
  #checkov:skip=CKV2_AWS_62:No event-driven processing of SPA assets
  bucket        = "${var.name}-spa-${local.account_id}"
  force_destroy = var.spa_force_destroy
  tags          = var.tags
}

resource "aws_s3_bucket_versioning" "spa" {
  bucket = aws_s3_bucket.spa.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "spa" {
  bucket = aws_s3_bucket.spa.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.edge.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "spa" {
  bucket                  = aws_s3_bucket.spa.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "spa" {
  bucket = aws_s3_bucket.spa.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_lifecycle_configuration" "spa" {
  bucket = aws_s3_bucket.spa.id
  rule {
    id     = "expire-old-builds"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration { noncurrent_days = 30 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

data "aws_iam_policy_document" "spa_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.spa.arn, "${aws_s3_bucket.spa.arn}/*"]
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
    sid       = "AllowCloudFrontOacRead"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.spa.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.this.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "spa" {
  bucket     = aws_s3_bucket.spa.id
  policy     = data.aws_iam_policy_document.spa_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.spa]
}

resource "aws_cloudfront_origin_access_control" "spa" {
  name                              = "${var.name}-spa"
  description                       = "CloudFront -> SPA bucket (SigV4, always signed)"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# SPA deep links (D10): a path with no file extension is a client-side route
# and gets /index.html. Only on the default (SPA) behaviour, so /api/* errors
# and WAF blocks are never rewritten — unlike custom_error_response (F11).
resource "aws_cloudfront_function" "spa_rewrite" {
  name    = "${var.name}-spa-rewrite"
  runtime = "cloudfront-js-2.0"
  comment = "Rewrite extension-less SPA routes to /index.html"
  publish = true
  code    = <<-JS
    function handler(event) {
      var request = event.request;
      var uri = request.uri;
      var lastSegment = uri.substring(uri.lastIndexOf('/') + 1);
      if (lastSegment.indexOf('.') === -1) {
        request.uri = '/index.html';
      }
      return request;
    }
  JS
}
