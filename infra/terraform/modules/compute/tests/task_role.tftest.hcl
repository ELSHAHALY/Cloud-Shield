# Task-role CONTENT tests (Phase E §9, D18). The REAL provider renders the
# policy documents locally (no API calls); identity lookups and every
# managed resource created without a container image are overridden, so
# `apply` never calls AWS (the modules/soar/tests/iam.tftest.hcl pattern:
# documents that depend on resources are deferred past plan). A new
# always-on resource without an override fails this test with an auth error,
# never by touching an account.

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
override_resource {
  target = aws_ecr_repository.app
  values = {
    arn            = "arn:aws:ecr:us-east-1:123456789012:repository/cs-test/docs-api"
    repository_url = "123456789012.dkr.ecr.us-east-1.amazonaws.com/cs-test/docs-api"
  }
}
override_resource {
  target = aws_ecr_lifecycle_policy.app
  values = {}
}
override_resource {
  target = aws_kms_key.this
  values = { arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000", key_id = "00000000-0000-0000-0000-000000000000" }
}
override_resource {
  target = aws_kms_alias.this
  values = {}
}
override_resource {
  target = aws_cloudwatch_log_group.app
  values = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/cs-test/compute/docs-api" }
}
override_resource {
  target = aws_cloudwatch_log_group.exec
  values = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/cs-test/compute/ecs-exec" }
}
override_resource {
  target = aws_ecs_cluster.this
  values = { arn = "arn:aws:ecs:us-east-1:123456789012:cluster/cs-test-cluster", id = "arn:aws:ecs:us-east-1:123456789012:cluster/cs-test-cluster" }
}
override_resource {
  target = aws_ecs_cluster_capacity_providers.this
  values = {}
}
override_resource {
  target = aws_iam_role.execution
  values = { arn = "arn:aws:iam::123456789012:role/cs-test-ecs-execution", id = "cs-test-ecs-execution" }
}
override_resource {
  target = aws_iam_role_policy.execution
  values = {}
}
override_resource {
  target = aws_iam_role.task
  values = { arn = "arn:aws:iam::123456789012:role/cs-test-app-task", id = "cs-test-app-task" }
}
override_resource {
  target = aws_iam_role_policy.task_exec
  values = {}
}
override_resource {
  target = aws_iam_role_policy.posture_read
  values = {}
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

run "posture_read_is_exactly_ecr_describe_on_own_repo" {
  command = apply

  assert {
    condition = jsonencode({
      for s in jsondecode(data.aws_iam_policy_document.posture_read.json).Statement :
      join(",", sort(flatten([s.Action]))) => flatten([s.Resource])
      }) == jsonencode({
      "ecr:DescribeImageScanFindings,ecr:DescribeImages" = ["arn:aws:ecr:us-east-1:123456789012:repository/cs-test/docs-api"]
    })
    error_message = "posture-read grants exactly ecr:DescribeImages + ecr:DescribeImageScanFindings on this repository only (D18)."
  }
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.posture_read.json).Statement :
      s.Effect == "Allow" && try(s.Condition, null) == null
    ])
    error_message = "posture-read is one plain Allow statement."
  }
  assert {
    condition     = aws_iam_role_policy.posture_read.name == "posture-read" && aws_iam_role_policy.posture_read.role == "cs-test-app-task"
    error_message = "The posture-read policy is attached to the task role."
  }
}

run "task_role_never_gets_ecr_writes" {
  command = apply

  assert {
    condition = !anytrue(flatten([
      for doc in [data.aws_iam_policy_document.posture_read.json, data.aws_iam_policy_document.task_exec.json] : [
        for s in jsondecode(doc).Statement : [
          for a in flatten([s.Action]) :
          startswith(a, "ecr:Put") || startswith(a, "ecr:Batch") || startswith(a, "ecr:Delete") || a == "ecr:*" || a == "ecr:GetAuthorizationToken"
        ]
      ]
    ]))
    error_message = "The task role may only describe its own image, never pull, push or delete."
  }
}
