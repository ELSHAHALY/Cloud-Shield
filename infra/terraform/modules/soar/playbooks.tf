###############################################################################
# Playbook Lambdas — created only when var.playbook_package is set.
#
# One role PER function (not one shared SOAR role): a bug or compromise in
# PB-03 cannot revoke IAM keys, and PB-02 cannot touch EC2. Every mutating
# permission is conditioned on the SOAR scope tag, so IAM enforces the same
# rule as the safety guard — defence in depth if the guard code is wrong.
#
# Handler contract (S3 implements under soar/): see soar/README.md.
###############################################################################

locals {
  playbooks = merge(local.enable_playbooks ? {
    "soar-safety-guard" = {
      handler = "safety_guard.handler.lambda_handler"
      timeout = 10
      policy  = data.aws_iam_policy_document.safety_guard.json
    }
    "soar-pb01-ec2-isolate" = {
      handler = "playbooks.pb01_ec2_isolate.lambda_handler"
      timeout = 30
      policy  = data.aws_iam_policy_document.pb01.json
    }
    "soar-pb02-iam-key-revoke" = {
      handler = "playbooks.pb02_iam_key_revoke.lambda_handler"
      timeout = 20
      policy  = data.aws_iam_policy_document.pb02.json
    }
    "soar-pb03-s3-restore-bpa" = {
      handler = "playbooks.pb03_s3_restore_bpa.lambda_handler"
      timeout = 30 # pre-state reads + restore + verify retries; evidence is a separate step
      policy  = data.aws_iam_policy_document.pb03.json
    }
    } : {}, local.enable_pb04 ? {
    "soar-pb04-ecs-task-contain" = {
      handler = "playbooks.pb04_ecs_task_contain.lambda_handler"
      timeout = 55 # StopTask + redeploy + ~45 s of verification polling (F21)
      policy  = one(data.aws_iam_policy_document.pb04[*].json)
    }
    } : {}, local.enable_pb05 ? {
    "soar-pb05-waf-ip-block" = {
      handler = "playbooks.pb05_waf_ip_block.lambda_handler"
      timeout = 20
      policy  = one(data.aws_iam_policy_document.pb05[*].json)
    }
  } : {})

  lambda_env = {
    DRY_RUN_PARAM        = aws_ssm_parameter.dry_run.name
    SCOPE_TAG_PARAM      = aws_ssm_parameter.scope_tag.name
    SCOPE_TAG_KEY        = local.scope_tag_key
    SCOPE_TAG_VALUE      = local.scope_tag_value
    INCIDENTS_TABLE      = aws_dynamodb_table.incidents.name
    EVIDENCE_BUCKET      = aws_s3_bucket.evidence.bucket
    QUARANTINE_SG_ID     = var.quarantine_security_group_id
    QUARANTINE_NACL_IDS  = join(",", var.quarantine_network_acl_ids)
    QUARANTINE_NACL_RULE = tostring(var.quarantine_nacl_rule_number)
    REVOCABLE_ROLE_ARNS  = join(",", var.revocable_role_arns)
    BUCKET_NAME_PREFIX   = "${var.name}-"
    ECS_CLUSTER_ARN      = local.enable_pb04 ? var.ecs_cluster_arn : ""
    ECS_SERVICE_NAMES    = local.enable_pb04 ? join(",", var.ecs_service_names) : ""
    BLOCK_IP_SET_ARNS    = local.enable_pb05 ? join(",", var.block_ip_set_arns) : ""
    BLOCK_IP_SET_MAX     = tostring(var.pb05_ip_set_max)
    BLOCK_TTL_HOURS      = tostring(var.pb05_block_ttl_hours)
    WAF_REGION           = local.enable_pb05 ? local.region : ""
    NEVER_BLOCK_PARAM    = local.enable_pb05 ? local.never_block_param_name : ""
    EDGE_EVENT_SOURCE    = local.enable_pb05 ? local.edge_event_source : ""
    # PB-05 corroboration (audit A1): the rate rule whose managed keys must
    # contain the address at block time.
    WAF_WEB_ACL_NAME   = local.enable_pb05 ? var.waf_web_acl.name : ""
    WAF_WEB_ACL_ID     = local.enable_pb05 ? var.waf_web_acl.id : ""
    WAF_RATE_RULE_NAME = local.enable_pb05 ? var.waf_rate_rule_name : ""
  }

  scope_condition_key = "aws:ResourceTag/${local.scope_tag_key}"

  quarantine_nacl_arns = [
    for id in var.quarantine_network_acl_ids :
    "arn:${local.partition}:ec2:${local.region}:${local.account_id}:network-acl/${id}"
  ]

  # PB-04: ARNs are built from names (plan-time strings, F4/D6).
  ecs_task_arns = local.enable_pb04 ? [
    "arn:${local.partition}:ecs:${local.region}:${local.account_id}:task/${var.ecs_cluster_name}/*"
  ] : []
  ecs_service_arns = local.enable_pb04 ? [
    for s in var.ecs_service_names :
    "arn:${local.partition}:ecs:${local.region}:${local.account_id}:service/${var.ecs_cluster_name}/${s}"
  ] : []
}

# -----------------------------------------------------------------------------
# Per-playbook permissions
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "safety_guard" {
  statement {
    sid       = "ReadSwitches"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.dry_run.arn, aws_ssm_parameter.scope_tag.arn]
  }
  # PB-04 rule 3: the LIVE task's tags, cluster and group, in our cluster only.
  dynamic "statement" {
    for_each = local.enable_pb04 ? [1] : []
    content {
      sid       = "ReadEcsTaskInScopeCluster"
      actions   = ["ecs:DescribeTasks"]
      resources = local.ecs_task_arns
      condition {
        test     = "ArnEquals"
        variable = "ecs:cluster"
        values   = [var.ecs_cluster_arn]
      }
    }
  }
  # PB-05 rule 4: the never-block list, read on every call.
  dynamic "statement" {
    for_each = local.enable_pb05 ? [1] : []
    content {
      sid       = "ReadNeverBlockList"
      actions   = ["ssm:GetParameter"]
      resources = [one(aws_ssm_parameter.never_block[*].arn)]
    }
  }
  statement {
    sid = "ReadTargetTags"
    # Describe/List calls have no resource-level permissions in EC2.
    actions   = ["ec2:DescribeInstances", "ec2:DescribeVolumes", "ec2:DescribeTags"]
    resources = ["*"]
  }
  statement {
    sid       = "ReadIamUserTags"
    actions   = ["iam:ListUserTags"]
    resources = ["arn:${local.partition}:iam::${local.account_id}:user/*"]
  }
  statement {
    sid       = "ReadProjectBucketTags"
    actions   = ["s3:GetBucketTagging"]
    resources = ["arn:${local.partition}:s3:::${var.name}-*"]
  }
}

data "aws_iam_policy_document" "pb01" {
  statement {
    sid = "Describe"
    # These Describe calls and the ASG membership lookup have no resource-level permissions.
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeVolumes",
      "ec2:DescribeSnapshots",
      "ec2:DescribeNetworkAcls",
      "autoscaling:DescribeAutoScalingInstances",
    ]
    resources = ["*"]
  }
  # DescribeInstanceAttribute IS resource-level (instance), so it is scoped.
  statement {
    sid       = "ReadInScopeInstanceAttributes"
    actions   = ["ec2:DescribeInstanceAttribute"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = local.scope_condition_key
      values   = [local.scope_tag_value]
    }
  }
  # Instance profile -> role, to find whose sessions to revoke.
  statement {
    sid       = "ResolveInstanceRole"
    actions   = ["iam:GetInstanceProfile"]
    resources = ["arn:${local.partition}:iam::${local.account_id}:instance-profile/${var.name}-*"]
  }
  # Stateless quarantine (ADR-0003): deny entries on the worker-tier NACL only.
  # CreateNetworkAclEntry can't overwrite an existing rule number (Replace* is
  # not granted), so this can only ADD rules — never loosen the allow at 100.
  # IAM has no condition key for the rule's action or number, so a compromised
  # PB-01 could plant an ALLOW below the quarantine rule; the code refuses to
  # report CONTAINED while any entry precedes the deny (audit A6).
  dynamic "statement" {
    for_each = length(var.quarantine_network_acl_ids) > 0 ? [1] : []
    content {
      sid       = "QuarantineNaclEntriesOnly"
      actions   = ["ec2:CreateNetworkAclEntry"]
      resources = local.quarantine_nacl_arns
    }
  }
  # SG swap + protection: the instance must carry the scope tag. Accepted risk
  # (audit A6): ModifyInstanceAttribute has no per-attribute condition key, so
  # this also covers attributes PB-01 never sets (e.g. userData) on in-scope
  # instances — today only the report-worker.
  statement {
    sid       = "IsolateInScopeInstance"
    actions   = ["ec2:ModifyInstanceAttribute"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = local.scope_condition_key
      values   = [local.scope_tag_value]
    }
  }
  # …and the only group it may be moved onto is the quarantine SG.
  statement {
    sid       = "OnlyOntoQuarantineSg"
    actions   = ["ec2:ModifyInstanceAttribute"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account_id}:security-group/${var.quarantine_security_group_id}"]
  }
  statement {
    sid       = "SnapshotInScopeVolume"
    actions   = ["ec2:CreateSnapshot"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account_id}:volume/*"]
    condition {
      test     = "StringEquals"
      variable = local.scope_condition_key
      values   = [local.scope_tag_value]
    }
  }
  statement {
    sid       = "CreateSnapshotResource"
    actions   = ["ec2:CreateSnapshot"]
    resources = ["arn:${local.partition}:ec2:${local.region}::snapshot/*"]
  }
  statement {
    sid       = "TagSnapshotsAtCreationOnly"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:${local.partition}:ec2:${local.region}::snapshot/*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateSnapshot"]
    }
  }
  statement {
    sid       = "WriteEvidence"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/incidents/*"]
  }
  dynamic "statement" {
    for_each = length(var.revocable_role_arns) > 0 ? [1] : []
    content {
      # Read-back of the revoke policy: verification, not trust.
      sid       = "VerifyRoleSessionRevoke"
      actions   = ["iam:GetRolePolicy"]
      resources = var.revocable_role_arns
    }
  }
  dynamic "statement" {
    for_each = length(var.revocable_role_arns) > 0 ? [1] : []
    content {
      # "Revoke active sessions" = attach an inline deny on tokens issued
      # before now (the console's "Revoke active sessions" does the same).
      sid       = "RevokeInstanceRoleSessions"
      actions   = ["iam:PutRolePolicy"]
      resources = var.revocable_role_arns
      # Only roles capped by the SOAR target boundary: whatever document a
      # (compromised) playbook writes, the role can never exceed it.
      condition {
        test     = "StringEquals"
        variable = "iam:PermissionsBoundary"
        values   = [aws_iam_policy.target_boundary.arn]
      }
    }
  }
}

data "aws_iam_policy_document" "pb02" {
  statement {
    sid = "InspectKeys"
    # ListUserTags: the scope re-check in code; GetUserPolicy: revoke read-back.
    actions   = ["iam:ListAccessKeys", "iam:ListUserTags", "iam:GetUserPolicy"]
    resources = ["arn:${local.partition}:iam::${local.account_id}:user/*"]
  }
  statement {
    sid       = "DeactivateKeyOfInScopeUser"
    actions   = ["iam:UpdateAccessKey"]
    resources = ["arn:${local.partition}:iam::${local.account_id}:user/*"]
    condition {
      test     = "StringEquals"
      variable = local.scope_condition_key
      values   = [local.scope_tag_value]
    }
  }
  statement {
    sid       = "RevokeSessionsOfInScopeBoundedUser"
    actions   = ["iam:PutUserPolicy"]
    resources = ["arn:${local.partition}:iam::${local.account_id}:user/*"]
    condition {
      test     = "StringEquals"
      variable = local.scope_condition_key
      values   = [local.scope_tag_value]
    }
    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [aws_iam_policy.target_boundary.arn]
    }
  }
}

data "aws_iam_policy_document" "pb03" {
  statement {
    sid = "RestoreBpaOnProjectBuckets"
    actions = [
      "s3:GetBucketPublicAccessBlock",
      "s3:PutBucketPublicAccessBlock",
      "s3:GetBucketTagging",
      # Pre-restore evidence: the exposure as it was, before BPA overrides it.
      "s3:GetBucketPolicy",
      "s3:GetBucketPolicyStatus",
      "s3:GetBucketAcl",
    ]
    # S3 bucket-level actions don't reliably support aws:ResourceTag, so the
    # name prefix is the IAM boundary; the guard AND PB-03 check the tag in code.
    resources = ["arn:${local.partition}:s3:::${var.name}-*"]
  }
  statement {
    sid       = "WriteEvidence"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/incidents/*"]
  }
}

# PB-04 (plan §4.1). IAM never grants RunTask, DeleteService, PassRole or
# ExecuteCommand, nor UpdateService on any service outside the allow-list.
# UpdateService cannot be narrowed to forceNewDeployment by IAM; the code only
# ever sends that, and needs no iam:PassRole because the task definition is
# unchanged (F22).
data "aws_iam_policy_document" "pb04" {
  count = local.enable_pb04 ? 1 : 0

  statement {
    sid       = "ReadTask"
    actions   = ["ecs:DescribeTasks"]
    resources = local.ecs_task_arns
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [var.ecs_cluster_arn]
    }
  }
  statement {
    sid       = "StopInScopeTask"
    actions   = ["ecs:StopTask"]
    resources = local.ecs_task_arns
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [var.ecs_cluster_arn]
    }
    condition {
      test     = "StringEquals"
      variable = local.scope_condition_key
      values   = [local.scope_tag_value]
    }
  }
  # Ownership proof (audit A4): ListTasks(cluster, serviceName) must contain
  # the task. The Service Authorization Reference lists ListTasks against the
  # container-instance resource type with the ecs:cluster condition key
  # [inferred: not verifiable offline]; Fargate tasks have no container
  # instance, so the resource is "*" and the ecs:cluster condition scopes it.
  statement {
    sid       = "ListServiceTasks"
    actions   = ["ecs:ListTasks"]
    resources = ["*"]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [var.ecs_cluster_arn]
    }
  }
  statement {
    sid       = "ReadService"
    actions   = ["ecs:DescribeServices"]
    resources = local.ecs_service_arns
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [var.ecs_cluster_arn]
    }
  }
  statement {
    sid       = "RedeployInScopeService"
    actions   = ["ecs:UpdateService"]
    resources = local.ecs_service_arns
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [var.ecs_cluster_arn]
    }
    condition {
      test     = "StringEquals"
      variable = local.scope_condition_key
      values   = [local.scope_tag_value]
    }
  }
  statement {
    sid       = "ReadTaskDefinition"
    actions   = ["ecs:DescribeTaskDefinition"]
    resources = ["*"] # no resource-level permissions for this action (F22)
  }
  statement {
    sid       = "WriteEvidence"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/incidents/*"]
  }
}

# PB-05 (plan §4.2): read and append to exactly the two block lists. No
# UpdateWebACL, Delete* or CreateIPSet anywhere. Audit A1 adds two reads PB-05
# does itself, from sources the caller cannot write: the rate rule's managed
# keys on the CloudFront ACL (corroboration) and the never-block list.
data "aws_iam_policy_document" "pb05" {
  count = local.enable_pb05 ? 1 : 0

  statement {
    sid       = "AppendToBlockLists"
    actions   = ["wafv2:GetIPSet", "wafv2:UpdateIPSet"]
    resources = var.block_ip_set_arns
  }
  statement {
    sid       = "CorroborateWithRateRule"
    actions   = ["wafv2:GetRateBasedStatementManagedKeys"]
    resources = [var.waf_web_acl.arn]
  }
  statement {
    sid       = "ReadNeverBlockList"
    actions   = ["ssm:GetParameter"]
    resources = [one(aws_ssm_parameter.never_block[*].arn)]
  }
}

# Shared by every playbook: incident row updates, own logs, tracing, KMS.
data "aws_iam_policy_document" "playbook_common" {
  for_each = local.playbooks

  statement {
    sid       = "IncidentRow"
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.incidents.arn]
  }
  statement {
    sid       = "ReadDryRun"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.dry_run.arn]
  }
  statement {
    sid       = "OwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda[each.key].arn}:*"]
  }
  statement {
    sid       = "Tracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"] # X-Ray has no resource-level permissions for these
  }
  statement {
    sid       = "SoarKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.this.arn]
  }
}

# -----------------------------------------------------------------------------
# Roles, logs, functions
# -----------------------------------------------------------------------------
# No aws:SourceAccount condition here: Lambda does not populate it when
# assuming an execution role, and adding it makes the role unassumable.
# The confused-deputy risk does not apply — attaching this role to a function
# requires iam:PassRole inside this account.
data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "playbook" {
  for_each           = local.playbooks
  name               = "${var.name}-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "playbook_specific" {
  for_each = local.playbooks
  name     = "playbook"
  role     = aws_iam_role.playbook[each.key].id
  policy   = each.value.policy
}

resource "aws_iam_role_policy" "playbook_common" {
  for_each = local.playbooks
  name     = "common"
  role     = aws_iam_role.playbook[each.key].id
  policy   = data.aws_iam_policy_document.playbook_common[each.key].json
}

resource "aws_cloudwatch_log_group" "lambda" {
  #checkov:skip=CKV_AWS_338:30-day retention is a deliberate lab cost choice; incident records live in DynamoDB (PITR) and the evidence bucket
  for_each          = local.playbooks
  name              = "/aws/lambda/${var.name}-${each.key}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
  tags              = var.tags
}

resource "aws_lambda_function" "playbook" {
  #checkov:skip=CKV_AWS_116:Invoked synchronously by Step Functions, which owns retries and the FAILED state — a DLQ would never receive anything
  #checkov:skip=CKV_AWS_117:Playbooks only call AWS control-plane APIs; a VPC attachment would add a NAT dependency to the containment path
  #checkov:skip=CKV_AWS_272:Code signing deferred; the package comes from the gated CI pipeline (stretch goal: AWS Signer profile)
  #checkov:skip=CKV_AWS_115:Reserved concurrency is a variable; default -1 because new accounts (limit 10) reject any reservation — set 5 once the quota allows
  for_each      = local.playbooks
  function_name = "${var.name}-${each.key}"
  role          = aws_iam_role.playbook[each.key].arn
  runtime       = "python3.13"
  architectures = ["arm64"]
  handler       = each.value.handler
  timeout       = each.value.timeout
  memory_size   = 256
  kms_key_arn   = aws_kms_key.this.arn

  s3_bucket         = var.playbook_package.s3_bucket
  s3_key            = var.playbook_package.s3_key
  s3_object_version = var.playbook_package.s3_object_version

  reserved_concurrent_executions = var.lambda_reserved_concurrency

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = local.lambda_env
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.playbook_common,
    aws_iam_role_policy.playbook_specific,
  ]

  tags = var.tags
}
