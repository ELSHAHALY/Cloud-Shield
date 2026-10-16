# ECR push role content tests (decision D7). The REAL provider renders the
# trust and permission documents locally; both depend only on variables and
# the identity data sources, which are overridden during plan. Plan-only: no
# credentials, no API calls.

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "mock"
  secret_key                  = "mock"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

override_data {
  target          = data.aws_caller_identity.current
  override_during = plan
  values          = { account_id = "123456789012" }
}
override_data {
  target          = data.aws_region.current
  override_during = plan
  values          = { region = "us-east-1" }
}
override_data {
  target          = data.aws_partition.current
  override_during = plan
  values          = { partition = "aws" }
}

variables {
  name                      = "cs-test"
  vpc_id                    = "vpc-0aaaaaaaaaaaaaaaa"
  private_app_subnet_ids    = ["subnet-0aaaaaaaaaaaaaaaa", "subnet-0bbbbbbbbbbbbbbbb"]
  private_worker_subnet_ids = ["subnet-0cccccccccccccccc", "subnet-0dddddddddddddddd"]
  nlb_security_group_id     = "sg-0aaaaaaaaaaaaaaaa"
  app_security_group_id     = "sg-0bbbbbbbbbbbbbbbb"
  worker_security_group_id  = "sg-0cccccccccccccccc"
}

run "absent_by_default" {
  command = plan

  assert {
    condition     = length(aws_iam_role.ci_push) == 0 && length(aws_iam_role_policy.ci_push) == 0
    error_message = "No push role without the bootstrap OIDC provider ARN."
  }
}

run "trust_is_exactly_one_repo_and_branch" {
  command = plan

  variables {
    github_oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    github_repository        = "ELSHAHALY/Cloud-Shield"
  }

  assert {
    condition     = one(jsondecode(data.aws_iam_policy_document.ci_push_trust[0].json).Statement).Principal.Federated == "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    error_message = "Only the GitHub OIDC provider may assume the push role."
  }
  assert {
    condition     = one(jsondecode(data.aws_iam_policy_document.ci_push_trust[0].json).Statement).Condition.StringEquals["token.actions.githubusercontent.com:sub"] == "repo:ELSHAHALY/Cloud-Shield:ref:refs/heads/main"
    error_message = "The sub claim must StringEquals the exact main ref of this repository."
  }
  assert {
    condition     = one(jsondecode(data.aws_iam_policy_document.ci_push_trust[0].json).Statement).Condition.StringEquals["token.actions.githubusercontent.com:aud"] == "sts.amazonaws.com"
    error_message = "The aud claim must be sts.amazonaws.com."
  }
  assert {
    condition     = !can(one(jsondecode(data.aws_iam_policy_document.ci_push_trust[0].json).Statement).Condition.StringLike)
    error_message = "No StringLike (wildcard) condition is allowed in the push-role trust."
  }
}

run "push_only_to_this_repository" {
  command = plan

  variables {
    github_oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  }

  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.ci_push[0].json).Statement :
      s.Resource == "arn:aws:ecr:us-east-1:123456789012:repository/cs-test/docs-api"
      if s.Sid != "EcrAuth"
    ])
    error_message = "Push actions only on this module's repository ARN."
  }
  assert {
    condition = [
      for s in jsondecode(data.aws_iam_policy_document.ci_push[0].json).Statement : flatten([s.Action])
      if s.Resource == "*"
    ] == [["ecr:GetAuthorizationToken"]]
    error_message = "Only ecr:GetAuthorizationToken may be granted on *."
  }
  assert {
    condition = alltrue([
      for a in flatten([for s in jsondecode(data.aws_iam_policy_document.ci_push[0].json).Statement : flatten([s.Action])]) :
      !startswith(a, "ecr:Delete") && !startswith(a, "iam:") && a != "ecr:SetRepositoryPolicy" && a != "ecr:*" && a != "*"
    ])
    error_message = "No Delete*, SetRepositoryPolicy, iam:* or wildcard actions."
  }
  assert {
    condition     = aws_iam_role.ci_push[0].name == "cs-test-gha-ecr-push"
    error_message = "Role is <name>-gha-ecr-push."
  }
}

run "rejects_wildcard_repository" {
  command = plan

  variables {
    github_oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    github_repository        = "ELSHAHALY/*"
  }

  expect_failures = [var.github_repository]
}
