###############################################################################
# Step Functions "cs-ir-router" (plan §6.2–6.5) — created only with playbooks.
#
#   RecordDetected ─► SafetyGuard ─► GuardDecision ─┬─ allowed==true ─► RouteByResource
#                                                   └─ anything else ─► RecordBlocked ─► Notify   (fail closed)
#        InstanceCredentialExfiltration* + AccessKey
#                                   / Instance ─► PB01Isolate ─┐
#        AccessKey (IAM user)                       ─► PB02Revoke  ─┼─► IsDryRun
#        S3Bucket + Policy:S3/Bucket*               ─► PB03Restore ─┤
#        ECSCluster + *:Runtime/*      (enable_pb04) ─► PB04Contain ─┤
#        source cloudshield.edge + IPAddress (pb05) ─► PB05Block   ─┘
#   IsDryRun ─┬─ not explicitly false ─► MarkWouldContain ─► Notify          (fail closed)
#             └─ false ─► CheckContained ─┬─ contained==true ─► MarkContained ─► (PB01Snapshot | PB03Evidence | PB04Evidence) ─► Notify
#                                         └─ otherwise ─► RecordFailed ─► Notify
#        other     ─► NoPlaybook ─► Notify
#   any failure    ─► RecordFailed ─► Notify
#
# MTTC = containedAt (state entered time of MarkContained) − eventTime
#        (EventBridge `time`). Evidence capture runs AFTER CONTAINED, so the
#        snapshot never counts against the 60 s target. Eradication and
#        recovery are human (state machine ends at CONTAINED, plan §6.4).
###############################################################################

locals {
  fn = { for k, f in aws_lambda_function.playbook : k => f.arn }

  lambda_retry = [{
    ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
    IntervalSeconds = 1
    MaxAttempts     = 2
    BackoffRate     = 2
  }]

  catch_to_failed = [{
    ErrorEquals = ["States.ALL"]
    ResultPath  = "$.error"
    Next        = "RecordFailed"
  }]

  incident_key = { incidentId = { "S.$" = "$.detail.id" } }

  # RouteByResource choices: concat() of conditional lists, so the graph stays
  # valid with PB-04 / PB-05 off (plan §4.3). Every type-based choice also
  # requires the matching resourceType (audit A5): the guard vets the target
  # Finding resolves from that same pair, so the router can never act on a
  # target the guard did not check. The exact ordered table is pinned by
  # tests/route_choices.json (soar.tftest.hcl and soar/tests/test_sims.py).
  # resourceType is always present here: RecordDetected reads it first.
  route_choices = concat(
    [
      # Scenario A: stolen instance-role credentials. GuardDuty reports these
      # with resourceType "AccessKey", but the response is PB-01 (isolate
      # the instance + revoke the ROLE's sessions), not PB-02 (IAM users).
      # PB-01 derives the instance id from accessKeyDetails.principalId.
      {
        And = [
          { Variable = "$.detail.type", StringMatches = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration*" },
          { Variable = "$.detail.resource.resourceType", StringEquals = "AccessKey" },
        ]
        Next = "PB01Isolate"
      },
      { Variable = "$.detail.resource.resourceType", StringEquals = "Instance", Next = "PB01Isolate" },
      { Variable = "$.detail.resource.resourceType", StringEquals = "AccessKey", Next = "PB02Revoke" },
      # Scenario C: only public-exposure findings. Block Public Access does
      # not stop Exfiltration:S3/* or Impact:S3/* by an authenticated
      # principal, so those go to an analyst instead (audit A1).
      {
        And = [
          { Variable = "$.detail.resource.resourceType", StringEquals = "S3Bucket" },
          { Variable = "$.detail.type", StringMatches = "Policy:S3/Bucket*" },
        ]
        Next = "PB03Restore"
      },
    ],
    # Scenario D: GuardDuty Runtime Monitoring on an ECS task. Only >= High
    # findings reach the router (D19: no always_route entry for Runtime).
    local.enable_pb04 ? [{
      And = [
        { Variable = "$.detail.resource.resourceType", StringEquals = "ECSCluster" },
        { Variable = "$.detail.type", StringMatches = "*:Runtime/*" },
      ]
      Next = "PB04Contain"
    }] : [],
    # Scenario E: only edge events (the dedicated bus) naming an IP. GuardDuty
    # never has source cloudshield.edge, so it can never reach PB-05. IsPresent
    # first: a Choice on a missing path raises an uncatchable States.Runtime.
    local.enable_pb05 ? [{
      And = [
        { Variable = "$.source", IsPresent = true },
        { Variable = "$.source", StringEquals = local.edge_event_source },
        { Variable = "$.detail.resource.resourceType", StringEquals = "IPAddress" },
      ]
      Next = "PB05Block"
    }] : [],
  )

  evidence_choices = concat(
    [
      { Variable = "$.detail.resource.resourceType", StringEquals = "Instance", Next = "PB01Snapshot" },
      {
        And = [
          { Variable = "$.detail.type", StringMatches = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration*" },
          { Variable = "$.detail.resource.resourceType", StringEquals = "AccessKey" },
        ]
        Next = "PB01Snapshot"
      },
      { Variable = "$.detail.resource.resourceType", StringEquals = "S3Bucket", Next = "PB03Evidence" },
    ],
    local.enable_pb04 ? [
      { Variable = "$.detail.resource.resourceType", StringEquals = "ECSCluster", Next = "PB04Evidence" },
    ] : [],
  )

  # Built as JSON strings so the "off" branch ("{}") needs no matching type.
  pb04_states = local.enable_pb04 ? jsonencode({
    PB04Contain = {
      Type     = "Task"
      Resource = "arn:${local.partition}:states:::lambda:invoke"
      Parameters = {
        FunctionName = lookup(local.fn, "soar-pb04-ecs-task-contain", null)
        Payload      = { action = "contain", "event.$" = "$" }
      }
      ResultSelector = { "result.$" = "$.Payload" }
      ResultPath     = "$.containment"
      Retry          = local.lambda_retry
      Catch          = local.catch_to_failed
      Next           = "IsDryRun"
    }
    # After CONTAINED: the task pre-state (captured by PB04Contain before
    # StopTask) becomes hashed evidence. Outside the MTTC window; a failure
    # here does not un-contain the incident.
    PB04Evidence = {
      Type     = "Task"
      Resource = "arn:${local.partition}:states:::lambda:invoke"
      Parameters = {
        FunctionName = lookup(local.fn, "soar-pb04-ecs-task-contain", null)
        Payload      = { action = "evidence", "event.$" = "$" }
      }
      ResultSelector = { "result.$" = "$.Payload" }
      ResultPath     = "$.evidence"
      Retry          = local.lambda_retry
      Catch = [{
        ErrorEquals = ["States.ALL"]
        ResultPath  = "$.evidenceError"
        Next        = "Notify"
      }]
      Next = "Notify"
    }
  }) : "{}"

  pb05_states = local.enable_pb05 ? jsonencode({
    PB05Block = {
      Type     = "Task"
      Resource = "arn:${local.partition}:states:::lambda:invoke"
      Parameters = {
        FunctionName = lookup(local.fn, "soar-pb05-waf-ip-block", null)
        Payload      = { action = "block", "event.$" = "$" }
      }
      ResultSelector = { "result.$" = "$.Payload" }
      ResultPath     = "$.containment"
      Retry          = local.lambda_retry
      Catch          = local.catch_to_failed
      Next           = "IsDryRun"
    }
  }) : "{}"

  definition = local.enable_playbooks ? {
    Comment = "CloudShield IR router — automation stops at CONTAINED"
    StartAt = "RecordDetected"
    States = merge({
      RecordDetected = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::dynamodb:updateItem"
        Parameters = {
          TableName = aws_dynamodb_table.incidents.name
          Key       = local.incident_key
          # eventTime = THIS run's EventBridge time (its MTTC start).
          # firstEventTime / findingCreatedAt keep the first sighting for audit.
          UpdateExpression = join(", ", [
            "SET #s = :detected, findingType = :ft, severity = :sev, resourceType = :rt",
            "eventTime = :et, firstEventTime = if_not_exists(firstEventTime, :et)",
            "findingCreatedAt = if_not_exists(findingCreatedAt, :fc)",
            "sfnStartedAt = :st, executionArn = :ex",
            "attempts = if_not_exists(attempts, :zero) + :one",
          ])
          # Run when the finding is new, or when a previous run FAILED or was a
          # dry run (GuardDuty re-delivers ongoing attacks under the same id, so
          # turning dry-run off must take effect on a live incident). Anything
          # already CONTAINED / BLOCKED / in progress is a duplicate.
          ConditionExpression      = "attribute_not_exists(incidentId) OR #s IN (:failed, :wouldContain)"
          ExpressionAttributeNames = { "#s" = "status" }
          ExpressionAttributeValues = {
            ":detected"     = { S = "DETECTED" }
            ":failed"       = { S = "FAILED" }
            ":wouldContain" = { S = "WOULD_CONTAIN_DRY_RUN" }
            ":ft"           = { "S.$" = "$.detail.type" }
            ":sev"          = { "N.$" = "States.Format('{}', $.detail.severity)" }
            ":rt"           = { "S.$" = "$.detail.resource.resourceType" }
            ":et"           = { "S.$" = "$.time" } # MTTC clock starts here
            ":fc"           = { "S.$" = "$.detail.createdAt" }
            ":st"           = { "S.$" = "$$.Execution.StartTime" }
            ":ex"           = { "S.$" = "$$.Execution.Id" }
            ":zero"         = { N = "0" }
            ":one"          = { N = "1" }
          }
        }
        ResultPath = null
        Catch = [
          { ErrorEquals = ["DynamoDB.ConditionalCheckFailedException"], ResultPath = null, Next = "DuplicateFinding" },
          { ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "RecordFailed" },
        ]
        Next = "SafetyGuard"
      }

      DuplicateFinding = { Type = "Succeed" }

      SafetyGuard = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = local.fn["soar-safety-guard"]
          "Payload.$"  = "$"
        }
        ResultSelector = { "decision.$" = "$.Payload" }
        ResultPath     = "$.guard"
        Retry          = local.lambda_retry
        Catch          = local.catch_to_failed
        Next           = "GuardDecision"
      }

      # FAIL CLOSED: only a present, boolean `allowed == true` proceeds.
      # "false" as a string, null, or a missing field -> RecordBlocked.
      # (A Choice on a missing path would raise States.Runtime, which cannot
      # be caught; IsPresent short-circuits that.)
      GuardDecision = {
        Type = "Choice"
        Choices = [{
          And = [
            { Variable = "$.guard.decision.allowed", IsPresent = true },
            { Variable = "$.guard.decision.allowed", IsBoolean = true },
            { Variable = "$.guard.decision.allowed", BooleanEquals = true },
          ]
          Next = "RouteByResource"
        }]
        Default = "RecordBlocked"
      }

      # Reachable ONLY from GuardDecision (allowed == true). Choices above.
      RouteByResource = {
        Type    = "Choice"
        Choices = local.route_choices
        Default = "NoPlaybook"
      }

      PB01Isolate = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = local.fn["soar-pb01-ec2-isolate"]
          Payload      = { action = "isolate", "event.$" = "$" }
        }
        ResultSelector = { "result.$" = "$.Payload" }
        ResultPath     = "$.containment"
        Retry          = local.lambda_retry
        Catch          = local.catch_to_failed
        Next           = "IsDryRun"
      }

      PB02Revoke = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = local.fn["soar-pb02-iam-key-revoke"]
          Payload      = { action = "revoke", "event.$" = "$" }
        }
        ResultSelector = { "result.$" = "$.Payload" }
        ResultPath     = "$.containment"
        Retry          = local.lambda_retry
        Catch          = local.catch_to_failed
        Next           = "IsDryRun"
      }

      PB03Restore = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = local.fn["soar-pb03-s3-restore-bpa"]
          Payload      = { action = "restore", "event.$" = "$" }
        }
        ResultSelector = { "result.$" = "$.Payload" }
        ResultPath     = "$.containment"
        Retry          = local.lambda_retry
        Catch          = local.catch_to_failed
        Next           = "IsDryRun"
      }

      # FAIL CLOSED: only an explicit boolean dry_run == false counts as a
      # real run; anything else is recorded as a dry run (never as CONTAINED).
      IsDryRun = {
        Type = "Choice"
        Choices = [{
          And = [
            { Variable = "$.guard.decision.dry_run", IsPresent = true },
            { Variable = "$.guard.decision.dry_run", IsBoolean = true },
            { Variable = "$.guard.decision.dry_run", BooleanEquals = false },
          ]
          Next = "CheckContained"
        }]
        Default = "MarkWouldContain"
      }

      # A playbook that returns without raising is NOT proof of containment.
      # It must return {"contained": true}; otherwise the incident is FAILED,
      # so neither CONTAINED nor the MTTC figure can be recorded falsely.
      CheckContained = {
        Type = "Choice"
        Choices = [{
          And = [
            { Variable = "$.containment.result.contained", IsPresent = true },
            { Variable = "$.containment.result.contained", IsBoolean = true },
            { Variable = "$.containment.result.contained", BooleanEquals = true },
          ]
          Next = "MarkContained"
        }]
        Default = "PlaybookDidNotContain"
      }

      PlaybookDidNotContain = {
        Type       = "Pass"
        Result     = { Error = "PlaybookDidNotContain", Cause = "Playbook returned without contained=true" }
        ResultPath = "$.error"
        Next       = "RecordFailed"
      }

      MarkContained = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::dynamodb:updateItem"
        Parameters = {
          TableName                = aws_dynamodb_table.incidents.name
          Key                      = local.incident_key
          UpdateExpression         = "SET #s = :s, containedAt = :t"
          ExpressionAttributeNames = { "#s" = "status" }
          ExpressionAttributeValues = {
            ":s" = { S = "CONTAINED" }
            ":t" = { "S.$" = "$$.State.EnteredTime" } # MTTC clock stops here
          }
        }
        ResultPath = null
        Catch      = local.catch_to_failed
        Next       = "NeedsEvidence"
      }

      NeedsEvidence = {
        Type    = "Choice"
        Choices = local.evidence_choices
        Default = "Notify"
      }

      # After CONTAINED: forensic EBS snapshot + SHA-256 manifest. A failure
      # here does not un-contain the incident; it is recorded and notified.
      PB01Snapshot = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = local.fn["soar-pb01-ec2-isolate"]
          Payload      = { action = "snapshot", "event.$" = "$" }
        }
        ResultSelector = { "result.$" = "$.Payload" }
        ResultPath     = "$.evidence"
        Retry          = local.lambda_retry
        Catch = [{
          ErrorEquals = ["States.ALL"]
          ResultPath  = "$.evidenceError"
          Next        = "Notify"
        }]
        Next = "Notify"
      }

      # After CONTAINED: store the bucket's pre-restore state (captured by
      # PB03Restore, carried in $.containment.result.prestate) as hashed
      # evidence. Outside the MTTC window; a failure doesn't un-contain.
      PB03Evidence = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::lambda:invoke"
        Parameters = {
          FunctionName = local.fn["soar-pb03-s3-restore-bpa"]
          Payload      = { action = "evidence", "event.$" = "$" }
        }
        ResultSelector = { "result.$" = "$.Payload" }
        ResultPath     = "$.evidence"
        Retry          = local.lambda_retry
        Catch = [{
          ErrorEquals = ["States.ALL"]
          ResultPath  = "$.evidenceError"
          Next        = "Notify"
        }]
        Next = "Notify"
      }

      MarkWouldContain = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::dynamodb:updateItem"
        Parameters = {
          TableName                = aws_dynamodb_table.incidents.name
          Key                      = local.incident_key
          UpdateExpression         = "SET #s = :s, wouldContainAt = :t"
          ExpressionAttributeNames = { "#s" = "status" }
          ExpressionAttributeValues = {
            ":s" = { S = "WOULD_CONTAIN_DRY_RUN" }
            ":t" = { "S.$" = "$$.State.EnteredTime" }
          }
        }
        ResultPath = null
        Catch      = local.catch_to_failed
        Next       = "Notify"
      }

      RecordBlocked = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::dynamodb:updateItem"
        Parameters = {
          TableName                = aws_dynamodb_table.incidents.name
          Key                      = local.incident_key
          UpdateExpression         = "SET #s = :s, guardReason = :r"
          ExpressionAttributeNames = { "#s" = "status" }
          ExpressionAttributeValues = {
            ":s" = { S = "BLOCKED_BY_GUARD" }
            ":r" = { "S.$" = "States.JsonToString($.guard.decision)" }
          }
        }
        ResultPath = null
        Catch      = local.catch_to_failed
        Next       = "Notify"
      }

      NoPlaybook = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::dynamodb:updateItem"
        Parameters = {
          TableName                 = aws_dynamodb_table.incidents.name
          Key                       = local.incident_key
          UpdateExpression          = "SET #s = :s"
          ExpressionAttributeNames  = { "#s" = "status" }
          ExpressionAttributeValues = { ":s" = { S = "NO_PLAYBOOK_ANALYST_REVIEW" } }
        }
        ResultPath = null
        Catch      = local.catch_to_failed
        Next       = "Notify"
      }

      # Terminal error path. Its own failure must not loop back into itself.
      RecordFailed = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::dynamodb:updateItem"
        Parameters = {
          TableName                = aws_dynamodb_table.incidents.name
          Key                      = local.incident_key
          UpdateExpression         = "SET #s = :s, failure = :e"
          ExpressionAttributeNames = { "#s" = "status" }
          ExpressionAttributeValues = {
            ":s" = { S = "FAILED" }
            ":e" = { "S.$" = "States.JsonToString($.error)" }
          }
        }
        ResultPath = null
        Catch = [{
          ErrorEquals = ["States.ALL"]
          ResultPath  = "$.recordError"
          Next        = "Notify"
        }]
        Next = "Notify"
      }

      Notify = {
        Type     = "Task"
        Resource = "arn:${local.partition}:states:::sns:publish"
        Parameters = {
          TopicArn    = aws_sns_topic.incidents.arn
          Subject     = "CloudShield SOAR incident"
          "Message.$" = "States.Format('Incident {} | {} | resource {} | see table ${aws_dynamodb_table.incidents.name}', $.detail.id, $.detail.type, $.detail.resource.resourceType)"
        }
        ResultPath = null
        End        = true
      }
    }, jsondecode(local.pb04_states), jsondecode(local.pb05_states))
  } : null
}

# -----------------------------------------------------------------------------
# State machine role — exactly the four integrations above, nothing else.
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "sfn_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "sfn" {
  count              = local.enable_playbooks ? 1 : 0
  name               = "${var.name}-soar-cs-ir-router"
  assume_role_policy = data.aws_iam_policy_document.sfn_trust.json
  tags               = var.tags
}

data "aws_iam_policy_document" "sfn" {
  count = local.enable_playbooks ? 1 : 0

  statement {
    sid       = "InvokePlaybooks"
    actions   = ["lambda:InvokeFunction"]
    resources = values(local.fn)
  }
  statement {
    sid       = "IncidentRows"
    actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.incidents.arn]
  }
  statement {
    sid       = "NotifyAnalyst"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.incidents.arn]
  }
  statement {
    sid       = "SoarKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.this.arn]
  }
  statement {
    # Step Functions log delivery uses the CloudWatch Logs vended-delivery
    # APIs, which do not support resource-level permissions.
    sid = "LogDelivery"
    actions = [
      "logs:CreateLogDelivery",
      "logs:GetLogDelivery",
      "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries",
      "logs:PutResourcePolicy",
      "logs:DescribeResourcePolicies",
      "logs:DescribeLogGroups",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "Tracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "sfn" {
  count  = local.enable_playbooks ? 1 : 0
  name   = "cs-ir-router"
  role   = aws_iam_role.sfn[0].id
  policy = data.aws_iam_policy_document.sfn[0].json
}

resource "aws_cloudwatch_log_group" "sfn" {
  #checkov:skip=CKV_AWS_338:30-day retention is a deliberate lab cost choice; the incidents table is the durable record
  count             = local.enable_playbooks ? 1 : 0
  name              = "/${var.name}/soar/cs-ir-router"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
  tags              = var.tags
}

resource "aws_sfn_state_machine" "router" {
  count    = local.enable_playbooks ? 1 : 0
  name     = "${var.name}-cs-ir-router"
  type     = "STANDARD" # exactly-once, full execution history = audit trail
  role_arn = aws_iam_role.sfn[0].arn

  definition = jsonencode(local.definition)

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn[0].arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  tracing_configuration {
    enabled = true
  }

  encryption_configuration {
    type                              = "CUSTOMER_MANAGED_KMS_KEY"
    kms_key_id                        = aws_kms_key.this.arn
    kms_data_key_reuse_period_seconds = 300
  }

  depends_on = [aws_iam_role_policy.sfn]
  tags       = var.tags
}

# -----------------------------------------------------------------------------
# EventBridge -> state machine (replaces the SNS-only baseline target)
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "events_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "events" {
  count              = local.enable_playbooks ? 1 : 0
  name               = "${var.name}-soar-events-to-sfn"
  assume_role_policy = data.aws_iam_policy_document.events_trust.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "events" {
  count = local.enable_playbooks ? 1 : 0
  name  = "start-cs-ir-router"
  role  = aws_iam_role.events[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "StartRouterOnly"
        Effect   = "Allow"
        Action   = "states:StartExecution"
        Resource = aws_sfn_state_machine.router[0].arn
      },
      {
        # The state machine is CMK-encrypted; the caller of StartExecution
        # must be able to encrypt the execution input with that key.
        Sid      = "EncryptExecutionInput"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.this.arn
      },
    ]
  })
}

resource "aws_cloudwatch_event_target" "sfn" {
  count     = local.enable_playbooks ? 1 : 0
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "cs-ir-router"
  arn       = aws_sfn_state_machine.router[0].arn
  role_arn  = aws_iam_role.events[0].arn
}
