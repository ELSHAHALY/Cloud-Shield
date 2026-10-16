###############################################################################
# CI image push role (gap 9 / F14, decision D7). Created only when the
# bootstrap OIDC provider ARN is passed in.
#
# GitHub Actions on the configured branch of the configured repository may
# push to THIS ECR repository and nothing else. It cannot deploy: ECS still
# runs only the digest set in var.container_image by a local S1 apply.
#
# The repository ARN is built as a string (same name as aws_ecr_repository.app)
# so the policy is fully known at plan time.
###############################################################################

locals {
  enable_ci_push     = var.github_oidc_provider_arn != null
  ecr_repository_arn = "arn:${local.partition}:ecr:${local.region}:${local.account_id}:repository/${var.name}/docs-api"
  ci_push_subject    = "repo:${var.github_repository}:ref:refs/heads/${var.ecr_push_branch}"
}

data "aws_iam_policy_document" "ci_push_trust" {
  count = local.enable_ci_push ? 1 : 0

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.github_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    # Exact match: one repository, one branch. Never StringLike: a wildcard
    # here would let any branch (or a pull_request run) push images.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [local.ci_push_subject]
    }
  }
}

resource "aws_iam_role" "ci_push" {
  count                = local.enable_ci_push ? 1 : 0
  name                 = "${var.name}-gha-ecr-push"
  description          = "GitHub Actions (${var.github_repository}@${var.ecr_push_branch}) pushes scanned images to ${var.name}/docs-api"
  assume_role_policy   = data.aws_iam_policy_document.ci_push_trust[0].json
  max_session_duration = 3600
  tags                 = var.tags
}

data "aws_iam_policy_document" "ci_push" {
  count = local.enable_ci_push ? 1 : 0

  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # GetAuthorizationToken does not support resource-level permissions
  }
  statement {
    sid = "PushThisRepoOnly"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
      "ecr:BatchGetImage",
      "ecr:DescribeImages",
      "ecr:DescribeImageScanFindings",
    ]
    resources = [local.ecr_repository_arn]
  }
}

resource "aws_iam_role_policy" "ci_push" {
  count  = local.enable_ci_push ? 1 : 0
  name   = "ecr-push"
  role   = aws_iam_role.ci_push[0].id
  policy = data.aws_iam_policy_document.ci_push[0].json
}
