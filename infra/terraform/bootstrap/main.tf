###############################################################################
# CloudShield — bootstrap (run ONCE per AWS account, by a human, from a laptop)
#
# Creates the things every other Terraform root depends on, so it cannot itself
# use a remote backend (chicken-and-egg). Its state stays LOCAL — commit nothing
# from .terraform/ or *.tfstate; keep the local state file somewhere safe (or
# migrate it into the bucket afterwards — see README.md in this folder).
#
#   1. Remote-state bucket (S3 + SSE-KMS + native S3 lockfile, no DynamoDB)
#   2. GitHub Actions OIDC identity provider + a READ-ONLY "plan" role
#   3. AWS Budgets alarm (risk R3 in the plan: cost overrun)
#   4. Account guardrail: EBS encryption by default (substitutes for an SCP in
#      the single-account model — see docs/adr/0001-single-account-first.md)
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id   = data.aws_caller_identity.current.account_id
  region       = data.aws_region.current.region
  state_bucket = "${var.project_name}-tfstate-${local.account_id}-${local.region}"
}

# -----------------------------------------------------------------------------
# 1. Remote state
# -----------------------------------------------------------------------------
resource "aws_kms_key" "tfstate" {
  description             = "${var.project_name} Terraform state encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.tfstate_kms.json
}

data "aws_iam_policy_document" "tfstate_kms" {
  #checkov:skip=CKV_AWS_111:Key policy — Resource "*" means "this key"; access is constrained by principal + conditions
  #checkov:skip=CKV_AWS_356:Key policy — Resource "*" is the only valid value inside a KMS key policy
  #checkov:skip=CKV_AWS_109:Root kms:* is the AWS default key-policy baseline; prevents an unmanageable key
  # Account root retains administrative control (standard AWS key policy
  # baseline); IAM policies then decide who may actually use the key.
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_kms_alias" "tfstate" {
  name          = "alias/${var.project_name}-tfstate"
  target_key_id = aws_kms_key.tfstate.key_id
}

resource "aws_s3_bucket" "tfstate" {
  #checkov:skip=CKV_AWS_144:Cross-region replication out of scope (single-region by design, plan §1.2)
  #checkov:skip=CKV_AWS_18:Access logging deferred until the log archive exists; CloudTrail data events cover it
  #checkov:skip=CKV2_AWS_62:Event notifications not needed for a state bucket
  bucket = local.state_bucket
  # Deliberately NOT force_destroy: losing state = losing track of live infra.
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.tfstate.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    id     = "expire-old-state-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration { noncurrent_days = 90 }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

data "aws_iam_policy_document" "tfstate_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.tfstate.arn,
      "${aws_s3_bucket.tfstate.arn}/*",
    ]
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

resource "aws_s3_bucket_policy" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  policy = data.aws_iam_policy_document.tfstate_bucket.json
}

# -----------------------------------------------------------------------------
# 2. GitHub OIDC — no long-lived CI keys anywhere (plan §5, identity trade-off)
# -----------------------------------------------------------------------------
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # AWS no longer validates these for GitHub's IdP, but older tooling expects
  # the field to be populated; values are GitHub's published intermediates.
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
  ]
}

data "aws_iam_policy_document" "gha_plan_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    # Only this repo, and only PR runs or the main branch. Forks cannot assume
    # it: GitHub does not issue OIDC tokens to fork PRs with secrets context.
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.github_repository}:pull_request",
        "repo:${var.github_repository}:ref:refs/heads/main",
      ]
    }
  }
}

resource "aws_iam_role" "gha_plan" {
  name                 = "${var.project_name}-gha-terraform-plan"
  description          = "Assumed by GitHub Actions to run terraform plan (read-only)"
  assume_role_policy   = data.aws_iam_policy_document.gha_plan_trust.json
  max_session_duration = 3600
}

# Trade-off: ReadOnlyAccess is broad (it can read most resource configs and
# S3 objects), but `terraform plan` must refresh every managed resource, and a
# hand-rolled list rots every time a module is added. Revisit once the module
# set is stable (Sprint 3) and replace with a generated least-privilege policy.
resource "aws_iam_role_policy_attachment" "gha_plan_readonly" {
  role       = aws_iam_role.gha_plan.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "gha_plan_state" {
  statement {
    sid       = "ListStateBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.tfstate.arn]
  }
  statement {
    sid       = "ReadState"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.tfstate.arn}/*"]
  }
  statement {
    # S3-native locking writes/deletes a <key>.tflock object during plan.
    sid       = "ManageLockfile"
    actions   = ["s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.tfstate.arn}/*.tflock"]
  }
  statement {
    sid       = "UseStateKey"
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.tfstate.arn]
  }
}

resource "aws_iam_role_policy" "gha_plan_state" {
  name   = "terraform-state-access"
  role   = aws_iam_role.gha_plan.id
  policy = data.aws_iam_policy_document.gha_plan_state.json
}

# NOTE: there is intentionally no "apply" role yet. Until the pipeline is
# enforcing (ENFORCE_GATES=true) and a GitHub Environment with required
# reviewers exists, applies are run by S1 locally. See README "Next steps".

# -----------------------------------------------------------------------------
# 3. Cost guardrail (R3)
# -----------------------------------------------------------------------------
resource "aws_budgets_budget" "monthly" {
  name         = "${var.project_name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  # 50% of the limit, actual spend  -> early warning ($50 at the default $100)
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 50
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.budget_alert_emails
  }
  # 100% of the limit, actual spend
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.budget_alert_emails
  }
  # Forecast to exceed the limit -> act before the money is spent
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = var.budget_alert_emails
  }
}

# -----------------------------------------------------------------------------
# 4. Account guardrails
# -----------------------------------------------------------------------------
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

# Deliberately NOT setting aws_s3_account_public_access_block here: attack
# scenario C (public S3 exposure, T1530) loosens a bucket's BPA on purpose, and
# an account-level block would silently override it and the scenario would
# never fire. Bucket-level BPA is set on every real bucket instead.
