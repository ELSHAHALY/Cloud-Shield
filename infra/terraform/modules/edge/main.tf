###############################################################################
# Module: edge — TB1 internet edge (S1)
#
#   viewer --> CloudFront (+ CloudFront-scope WAF: PB-05 block list, IP
#              reputation, rate limit, common + known-bad-input rules)
#                |-- /*      --> private SPA bucket (OAC, SSE-KMS)
#                '-- /api/*  --> REST API (REGIONAL WAF: origin-verify header,
#                                known-bad-inputs, SQLi) --VPC Link--> NLB
#
#   main.tf  identity lookups, edge KMS key (+ separate key policy)
#   spa.tf   SPA bucket, OAC, SPA-rewrite CloudFront Function (D10)
#   waf.tf   origin-verify secret, PB-05 IP sets, both web ACLs, WAF logging
#   api.tf   REST API, VPC Link, Cognito authorizer, stage, logs (enable_api)
#   cdn.tf   response-headers policy (ZAP headers + CSP), distribution
#
# Region: a CLOUDFRONT-scope web ACL and its IP sets exist only in us-east-1
# (F2). Builder step 0 found that `terraform validate` cannot run standalone
# on a module that declares configuration_aliases, and CI validates every
# module directory on its own (F17). So this module uses the F17 fallback:
# no provider alias, and a precondition that the provider region is
# us-east-1 (plan §1.2: single region). Every edge resource therefore lives
# in us-east-1.
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  partition  = data.aws_partition.current.partition

  required_region = "us-east-1"
  region_ok       = local.region == local.required_region
  region_error    = "modules/edge must run with a us-east-1 provider: CLOUDFRONT-scope WAF web ACLs and IP sets exist only there (F2, F17 fallback)."
}

# -----------------------------------------------------------------------------
# Edge KMS key: SPA bucket objects + the API Gateway log groups.
# The policy is a separate aws_kms_key_policy because it names the
# distribution, which (through the SPA bucket) depends on the key.
# -----------------------------------------------------------------------------
resource "aws_kms_key" "edge" {
  description             = "${var.name} edge (SPA bucket, API Gateway logs)"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  tags                    = var.tags
}

resource "aws_kms_alias" "edge" {
  name          = "alias/${var.name}-edge"
  target_key_id = aws_kms_key.edge.key_id
}

data "aws_iam_policy_document" "edge_kms" {
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

  # OAC reads SSE-KMS objects: only on behalf of THIS distribution.
  statement {
    sid       = "AllowCloudFrontDecryptForThisDistribution"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
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

  statement {
    sid = "CloudWatchLogsForEdgeLogGroupsOnly"
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
        "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/${var.name}/edge/*",
        "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:API-Gateway-Execution-Logs_*",
      ]
    }
  }
}

resource "aws_kms_key_policy" "edge" {
  key_id = aws_kms_key.edge.id
  policy = data.aws_iam_policy_document.edge_kms.json
}
