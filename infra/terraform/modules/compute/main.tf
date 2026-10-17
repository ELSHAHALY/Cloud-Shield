###############################################################################
# Module: compute — ECR (TB4 supply chain), ECS cluster (TB2), shared IAM/KMS
# Owner: S1. The report-worker (worker.tf) is consulted with S3.
#
# Always created (no code dependency, near-zero idle cost):
#   KMS key, ECR repo, ECS cluster, log groups, task execution + task roles
# Gated by var.container_image != null   -> service.tf (NLB, task def, service)
# Gated by var.enable_report_worker      -> worker.tf  (EC2 forensic target)
# Gated by var.github_oidc_provider_arn  -> ci-push.tf (GitHub Actions ECR push role)
###############################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id     = data.aws_caller_identity.current.account_id
  region         = data.aws_region.current.region
  partition      = data.aws_partition.current.partition
  enable_service = var.container_image != null
}

# -----------------------------------------------------------------------------
# KMS — one key for ECR, CloudWatch log groups and ECS Exec sessions
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

  statement {
    sid = "CloudWatchLogsForThisModuleOnly"
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
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/${var.name}/compute/*"]
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "${var.name} compute (ECR, logs, ECS Exec)"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.kms.json
  tags                    = var.tags
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name}-compute"
  target_key_id = aws_kms_key.this.key_id
}

# -----------------------------------------------------------------------------
# ECR (TB4) — immutable tags + scan on push. CI pushes by digest only.
# -----------------------------------------------------------------------------
resource "aws_ecr_repository" "app" {
  name                 = "${var.name}/docs-api"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = var.ecr_force_delete

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.this.arn
  }

  tags = var.tags
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after 7 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep the 20 most recent images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 20
        }
        action = { type = "expire" }
      },
    ]
  })
}

# -----------------------------------------------------------------------------
# Log groups (KMS-encrypted)
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "app" {
  #checkov:skip=CKV_AWS_338:30-day retention is a deliberate lab cost choice; security-relevant logs are archived to S3
  name              = "/${var.name}/compute/docs-api"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
  tags              = var.tags
}

# ECS Exec session transcripts — the volatile-capture evidence for PB-04.
resource "aws_cloudwatch_log_group" "exec" {
  #checkov:skip=CKV_AWS_338:30-day retention is a deliberate lab cost choice; evidence is copied to the SOAR evidence bucket
  name              = "/${var.name}/compute/ecs-exec"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
  tags              = var.tags
}

# -----------------------------------------------------------------------------
# ECS cluster
# -----------------------------------------------------------------------------
resource "aws_ecs_cluster" "this" {
  name = "${var.name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  configuration {
    execute_command_configuration {
      kms_key_id = aws_kms_key.this.arn
      logging    = "OVERRIDE"

      log_configuration {
        cloud_watch_encryption_enabled = true
        cloud_watch_log_group_name     = aws_cloudwatch_log_group.exec.name
      }
    }
  }

  tags = var.tags
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = aws_ecs_cluster.this.name
  capacity_providers = ["FARGATE"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

# -----------------------------------------------------------------------------
# IAM — task execution role (pull image, write logs). Scoped to this repo and
# these log groups instead of the broad AmazonECSTaskExecutionRolePolicy.
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "ecs_tasks_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    # Confused-deputy protection: only ECS acting for THIS account.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:ecs:${local.region}:${local.account_id}:*"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_trust.json
  tags               = var.tags
}

data "aws_iam_policy_document" "execution" {
  statement {
    sid       = "EcrAuth"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # GetAuthorizationToken does not support resource-level permissions
  }
  # Plus, when given, the GuardDuty-owned repository of the Runtime Monitoring
  # sidecar (F20): without it, tasks fail to start once the agent is injected.
  statement {
    sid = "PullThisRepoOnly"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = concat([aws_ecr_repository.app.arn], var.guardduty_agent_ecr_repository_arns)
  }
  statement {
    sid       = "DecryptImageLayers"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.this.arn]
  }
  statement {
    sid       = "WriteAppLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.app.arn}:*"]
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "pull-and-log"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}

# -----------------------------------------------------------------------------
# IAM — task role (what the app itself may do). This module grants only ECS
# Exec; modules/data attaches the data-plane permissions (TB3 owner decides
# who touches the data).
# -----------------------------------------------------------------------------
resource "aws_iam_role" "task" {
  name               = "${var.name}-app-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_trust.json
  tags               = var.tags
}

data "aws_iam_policy_document" "task_exec" {
  statement {
    sid = "EcsExecChannel"
    actions = [
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"] # ssmmessages has no resource-level permissions
  }
  statement {
    sid       = "EcsExecSessionEncryption"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.this.arn]
  }
  statement {
    sid       = "EcsExecTranscripts"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.exec.arn}:*"]
  }
  statement {
    sid       = "EcsExecDescribeGroups"
    actions   = ["logs:DescribeLogGroups"]
    resources = ["*"] # DescribeLogGroups does not support resource-level permissions
  }
}

resource "aws_iam_role_policy" "task_exec" {
  name   = "ecs-exec"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task_exec.json
}

# -----------------------------------------------------------------------------
# IAM — posture read (Phase E D18): the app reports the ECR basic-scan result
# of its own running digest. Read-only, on this repository only; ECR has no
# finer resource than the repository. No KMS grant: the scan findings API
# returns metadata, not image layers [inferred: verify on apply, §16 #8].
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "posture_read" {
  statement {
    sid       = "OwnImageScanFindings"
    actions   = ["ecr:DescribeImages", "ecr:DescribeImageScanFindings"]
    resources = [aws_ecr_repository.app.arn]
  }
}

resource "aws_iam_role_policy" "posture_read" {
  name   = "posture-read"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.posture_read.json
}
