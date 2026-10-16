# Phase E (plan §9, D13, D16): CONTENT tests of the docs-api SOC read policy
# and the decoy publisher wiring. Same pattern as iam.tftest.hcl: the REAL
# provider renders the policy documents locally (no API calls); identity
# lookups and every managed resource are overridden, so `apply` never calls
# AWS and needs no credentials.
#
# Mutation checks (run by hand when app-integration.tf changes):
#   1. delete the events:source condition in PublishDecoy -> "decoy_publish_needs_both_flags_and_both_conditions" fails;
#   2. widen EvidenceRead to "${bucket}/*"                  -> "soc_read_is_exactly_the_specified_grants" fails.

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
  target = data.aws_caller_identity.current
  values = { account_id = "123456789012" }
}
override_data {
  target = data.aws_region.current
  values = { region = "us-east-1" }
}
override_data {
  target = data.aws_partition.current
  values = { partition = "aws" }
}
# Every managed resource is overridden, so `apply` never calls AWS: only the
# data sources are evaluated for real. (Data sources that depend on resources
# with pending changes are deferred past plan, hence apply, not plan.) A new
# resource added to the module without an override here fails this test with
# an auth error, never by touching an account.
override_resource {
  target = aws_cloudwatch_event_rule.guardduty
  values = { arn = "arn:aws:events:us-east-1:123456789012:rule/cs-test-soar-guardduty" }
}
override_resource {
  target = aws_cloudwatch_event_target.sfn
  values = {}
}
override_resource {
  target = aws_cloudwatch_event_target.sns
  values = {}
}
override_resource {
  target = aws_cloudwatch_log_group.lambda
  values = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/cs-test-soar" }
}
override_resource {
  target = aws_cloudwatch_log_group.sfn
  values = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/cs-test/soar/cs-ir-router" }
}
override_resource {
  target = aws_dynamodb_table.incidents
  values = { arn = "arn:aws:dynamodb:us-east-1:123456789012:table/cs-test-soar-incidents" }
}
override_resource {
  target = aws_iam_policy.target_boundary
  values = { arn = "arn:aws:iam::123456789012:policy/cs-test-soar-target-boundary" }
}
override_resource {
  target = aws_iam_role.events
  values = { arn = "arn:aws:iam::123456789012:role/cs-test-soar-events-to-sfn" }
}
override_resource {
  target = aws_iam_role.playbook
  values = { arn = "arn:aws:iam::123456789012:role/cs-test-soar" }
}
override_resource {
  target = aws_iam_role.sfn
  values = { arn = "arn:aws:iam::123456789012:role/cs-test-soar-cs-ir-router" }
}
override_resource {
  target = aws_iam_role_policy.events
  values = {}
}
override_resource {
  target = aws_iam_role_policy.playbook_common
  values = {}
}
override_resource {
  target = aws_iam_role_policy.playbook_specific
  values = {}
}
override_resource {
  target = aws_iam_role_policy.sfn
  values = {}
}
override_resource {
  target = aws_kms_alias.this
  values = {}
}
override_resource {
  target = aws_kms_key.this
  values = { arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000" }
}
override_resource {
  target = aws_lambda_function.playbook
  values = { arn = "arn:aws:lambda:us-east-1:123456789012:function:cs-test-soar" }
}
override_resource {
  target = aws_s3_bucket.evidence
  values = { arn = "arn:aws:s3:::cs-test-soar-evidence-123456789012" }
}
override_resource {
  target = aws_s3_bucket_lifecycle_configuration.evidence
  values = {}
}
override_resource {
  target = aws_s3_bucket_object_lock_configuration.evidence
  values = {}
}
override_resource {
  target = aws_s3_bucket_ownership_controls.evidence
  values = {}
}
override_resource {
  target = aws_s3_bucket_policy.evidence
  values = {}
}
override_resource {
  target = aws_s3_bucket_public_access_block.evidence
  values = {}
}
override_resource {
  target = aws_s3_bucket_server_side_encryption_configuration.evidence
  values = {}
}
override_resource {
  target = aws_s3_bucket_versioning.evidence
  values = {}
}
override_resource {
  target = aws_sfn_state_machine.router
  values = { arn = "arn:aws:states:us-east-1:123456789012:stateMachine:cs-test-cs-ir-router" }
}
override_resource {
  target = aws_sns_topic.incidents
  values = { arn = "arn:aws:sns:us-east-1:123456789012:cs-test-soar-incidents" }
}
override_resource {
  target = aws_sns_topic_policy.incidents
  values = {}
}
override_resource {
  target = aws_sns_topic_subscription.email
  values = {}
}
override_resource {
  target = aws_ssm_parameter.dry_run
  values = { arn = "arn:aws:ssm:us-east-1:123456789012:parameter/cs-test/soar/dry_run" }
}
override_resource {
  target = aws_ssm_parameter.scope_tag
  values = { arn = "arn:aws:ssm:us-east-1:123456789012:parameter/cs-test/soar/scope_tag" }
}

# Phase D (PB-04 / PB-05): every new managed resource, overridden too.
override_resource {
  target = aws_cloudwatch_event_bus.edge
  values = { arn = "arn:aws:events:us-east-1:123456789012:event-bus/cs-test-soar-edge", name = "cs-test-soar-edge" }
}
override_resource {
  target = aws_cloudwatch_event_bus_policy.edge
  values = {}
}
override_resource {
  target = aws_ssm_parameter.never_block
  values = { arn = "arn:aws:ssm:us-east-1:123456789012:parameter/cs-test/soar/pb05_never_block" }
}
override_resource {
  target = aws_cloudwatch_event_rule.edge
  values = { arn = "arn:aws:events:us-east-1:123456789012:rule/cs-test-soar-edge/cs-test-soar-edge-to-router" }
}
override_resource {
  target = aws_cloudwatch_event_target.edge
  values = {}
}
override_resource {
  target = aws_iam_role.harvester
  values = { arn = "arn:aws:iam::123456789012:role/cs-test-soar-pb05-harvester", id = "cs-test-soar-pb05-harvester" }
}
override_resource {
  target = aws_iam_role_policy.harvester
  values = {}
}
override_resource {
  target = aws_iam_role_policy.harvester_runtime
  values = {}
}
override_resource {
  target = aws_cloudwatch_log_group.harvester
  values = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/cs-test-soar-pb05-harvester" }
}
override_resource {
  target = aws_lambda_function.harvester
  values = { arn = "arn:aws:lambda:us-east-1:123456789012:function:cs-test-soar-pb05-harvester", function_name = "cs-test-soar-pb05-harvester" }
}
override_resource {
  target = aws_cloudwatch_metric_alarm.rate_limited
  values = { arn = "arn:aws:cloudwatch:us-east-1:123456789012:alarm:cs-test-soar-pb05-rate-limited" }
}
override_resource {
  target = aws_cloudwatch_event_rule.harvest
  values = { arn = "arn:aws:events:us-east-1:123456789012:rule/cs-test-soar-pb05-harvest" }
}
override_resource {
  target = aws_cloudwatch_event_target.harvest
  values = {}
}
override_resource {
  target = aws_lambda_permission.harvest
  values = {}
}
override_resource {
  target = aws_cloudwatch_event_rule.harvest_schedule
  values = { arn = "arn:aws:events:us-east-1:123456789012:rule/cs-test-soar-pb05-harvest-schedule" }
}
override_resource {
  target = aws_cloudwatch_event_target.harvest_schedule
  values = {}
}
override_resource {
  target = aws_lambda_permission.harvest_schedule
  values = {}
}

# Audit A2 (persistence table + auto-expiry sweeper): overridden too.
override_resource {
  target = aws_dynamodb_table.harvest_state
  values = { arn = "arn:aws:dynamodb:us-east-1:123456789012:table/cs-test-soar-pb05-harvest-state", name = "cs-test-soar-pb05-harvest-state" }
}
override_resource {
  target = aws_iam_role.sweeper
  values = { arn = "arn:aws:iam::123456789012:role/cs-test-soar-pb05-sweeper", id = "cs-test-soar-pb05-sweeper" }
}
override_resource {
  target = aws_iam_role_policy.sweeper
  values = {}
}
override_resource {
  target = aws_cloudwatch_log_group.sweeper
  values = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/cs-test-soar-pb05-sweeper" }
}
override_resource {
  target = aws_lambda_function.sweeper
  values = { arn = "arn:aws:lambda:us-east-1:123456789012:function:cs-test-soar-pb05-sweeper", function_name = "cs-test-soar-pb05-sweeper" }
}
override_resource {
  target = aws_cloudwatch_event_rule.sweep
  values = { arn = "arn:aws:events:us-east-1:123456789012:rule/cs-test-soar-pb05-sweep" }
}
override_resource {
  target = aws_cloudwatch_event_target.sweep
  values = {}
}
override_resource {
  target = aws_lambda_permission.sweep
  values = {}
}

# Phase D stage 2c (ChatOps notifier): every new managed resource, overridden.
override_resource {
  target = aws_iam_role.notifier
  values = { arn = "arn:aws:iam::123456789012:role/cs-test-soar-notifier", id = "cs-test-soar-notifier" }
}
override_resource {
  target = aws_iam_role_policy.notifier
  values = {}
}
override_resource {
  target = aws_cloudwatch_log_group.notifier
  values = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/cs-test-soar-notifier" }
}
override_resource {
  target = aws_lambda_function.notifier
  values = { arn = "arn:aws:lambda:us-east-1:123456789012:function:cs-test-soar-notifier", function_name = "cs-test-soar-notifier" }
}
override_resource {
  target = aws_sns_topic_subscription.notifier
  values = {}
}
override_resource {
  target = aws_lambda_permission.notifier
  values = {}
}

# Phase E: the app integration policy.
override_resource {
  target = aws_iam_role_policy.app_soc_read
  values = {}
}

variables {
  name                         = "cs-test"
  quarantine_security_group_id = "sg-0aaaaaaaaaaaaaaaa"
  quarantine_network_acl_ids   = ["acl-0bbbbbbbbbbbbbbbb"]
  revocable_role_arns          = ["arn:aws:iam::123456789012:role/cs-test-report-worker"]
  playbook_package = {
    s3_bucket = "artifacts-bucket"
    s3_key    = "soar/playbooks.zip"
  }

  enable_pb05 = true
  block_ip_set_arns = [
    "arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v4/11111111-1111-1111-1111-111111111111",
    "arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v6/22222222-2222-2222-2222-222222222222",
  ]
  waf_web_acl = {
    name = "cs-test-cloudfront"
    id   = "33333333-3333-3333-3333-333333333333"
    arn  = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/cs-test-cloudfront/33333333-3333-3333-3333-333333333333"
  }
  nat_public_ip = "198.51.100.10"

  app_task_role_name = "cs-test-app-task"
  app_task_role_arn  = "arn:aws:iam::123456789012:role/cs-test-app-task"
}

run "absent_by_default" {
  command = apply

  variables {
    app_task_role_name = null
    app_task_role_arn  = null
  }

  assert {
    condition     = length(aws_iam_role_policy.app_soc_read) == 0 && length(data.aws_iam_policy_document.app_soc_read) == 0
    error_message = "No SOC read policy without enable_app_integration."
  }
  assert {
    condition     = output.app_environment.EDGE_BUS_NAME == "" && output.app_environment.DECOY_PUBLISH_ENABLED == "false"
    error_message = "Without app_publishes_decoy the app gets no bus name and publishing is off (F13)."
  }
  assert {
    condition = jsonencode(sort(flatten([one([
      for s in jsondecode(data.aws_iam_policy_document.edge_bus[0].json).Statement : s
      if s.Effect == "Deny"
    ]).Condition.ArnNotEquals["aws:PrincipalArn"]]))) == jsonencode(["arn:aws:iam::123456789012:role/cs-test-soar-pb05-harvester"])
    error_message = "Without app_publishes_decoy the bus Deny exception list is the harvester only."
  }
}

run "soc_read_is_exactly_the_specified_grants" {
  command = apply

  variables {
    enable_app_integration = true
  }

  assert {
    condition = jsonencode({
      for s in jsondecode(data.aws_iam_policy_document.app_soc_read[0].json).Statement :
      join(",", sort(flatten([s.Action]))) => sort(flatten([s.Resource]))
      }) == jsonencode({
      "dynamodb:GetItem"                                                             = ["arn:aws:dynamodb:us-east-1:123456789012:table/cs-test-soar-incidents"]
      "dynamodb:Query"                                                               = ["arn:aws:dynamodb:us-east-1:123456789012:table/cs-test-soar-incidents/index/status-eventTime"]
      "s3:GetObject,s3:GetObjectLegalHold,s3:GetObjectRetention,s3:GetObjectVersion" = ["arn:aws:s3:::cs-test-soar-evidence-123456789012/incidents/*"]
      "s3:GetBucketObjectLockConfiguration"                                          = ["arn:aws:s3:::cs-test-soar-evidence-123456789012"]
      "kms:Decrypt"                                                                  = ["arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"]
      "ssm:GetParameter"                                                             = ["arn:aws:ssm:us-east-1:123456789012:parameter/cs-test/soar/dry_run"]
    })
    error_message = "SOC read: GetItem on the table, Query on the status-eventTime index only, evidence reads under incidents/, the lock config, kms:Decrypt and the dry-run parameter. Nothing else (no PutEvents without app_publishes_decoy)."
  }
  assert {
    condition = !anytrue(flatten([
      for s in jsondecode(data.aws_iam_policy_document.app_soc_read[0].json).Statement : [
        for a in flatten([s.Action]) :
        contains(["dynamodb:Scan", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem", "s3:PutObject", "s3:ListBucket", "s3:ListBucketVersions"], a) || startswith(a, "s3:Delete") || startswith(a, "kms:GenerateDataKey") || strcontains(a, "*")
      ]
    ]))
    error_message = "The app may never Scan, write incidents, write or list evidence, or generate SOAR data keys."
  }
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.app_soc_read[0].json).Statement :
      s.Effect == "Allow" && try(s.Condition, null) == null
    ])
    error_message = "Without the publisher flag every statement is a plain Allow."
  }
  assert {
    condition     = aws_iam_role_policy.app_soc_read[0].role == "cs-test-app-task" && aws_iam_role_policy.app_soc_read[0].name == "soar-soc-read"
    error_message = "The policy is attached to the app task role."
  }
  assert {
    condition = jsonencode(output.app_environment) == jsonencode({
      AWS_ACCOUNT_ID         = "123456789012"
      DECOY_PUBLISH_ENABLED  = "false"
      EDGE_BUS_NAME          = ""
      EDGE_EVENT_SOURCE      = "cloudshield.edge"
      EVIDENCE_BUCKET        = "cs-test-soar-evidence-123456789012"
      INCIDENTS_STATUS_INDEX = "status-eventTime"
      INCIDENTS_TABLE        = "cs-test-soar-incidents"
      SOAR_DRY_RUN_PARAM     = "/cs-test/soar/dry_run"
      SOAR_PLAYBOOKS_ENABLED = "true"
    })
    error_message = "app_environment carries exactly the SOC settings."
  }
  assert {
    condition = (
      output.app_environment.INCIDENTS_TABLE == aws_dynamodb_table.incidents.name &&
      output.app_environment.EVIDENCE_BUCKET == aws_s3_bucket.evidence.bucket &&
      output.app_environment.SOAR_DRY_RUN_PARAM == aws_ssm_parameter.dry_run.name &&
      one([for g in aws_dynamodb_table.incidents.global_secondary_index : g.name]) == output.app_environment.INCIDENTS_STATUS_INDEX
    )
    error_message = "The name-built app_environment matches the real resource names (F35 drift guard)."
  }
}

run "decoy_publish_needs_both_flags_and_both_conditions" {
  command = apply

  variables {
    enable_app_integration = true
    app_publishes_decoy    = true
  }

  assert {
    condition = jsonencode(one([
      for s in jsondecode(data.aws_iam_policy_document.app_soc_read[0].json).Statement : s
      if contains(flatten([s.Action]), "events:PutEvents")
      ])) == jsonencode({
      Action    = "events:PutEvents"
      Condition = { StringEquals = { "events:detail-type" = "CloudShield Edge Finding", "events:source" = "cloudshield.edge" } }
      Effect    = "Allow"
      Resource  = "arn:aws:events:us-east-1:123456789012:event-bus/cs-test-soar-edge"
      Sid       = "PublishDecoy"
    })
    error_message = "PutEvents only on the edge bus, pinned to source cloudshield.edge AND detail-type CloudShield Edge Finding (F14)."
  }
  assert {
    condition = jsonencode(sort(flatten([one([
      for s in jsondecode(data.aws_iam_policy_document.edge_bus[0].json).Statement : s
      if s.Effect == "Deny"
      ]).Condition.ArnNotEquals["aws:PrincipalArn"]]))) == jsonencode([
      "arn:aws:iam::123456789012:role/cs-test-app-task",
      "arn:aws:iam::123456789012:role/cs-test-soar-pb05-harvester",
      ]) && jsonencode(sort(flatten([one([
        for s in jsondecode(data.aws_iam_policy_document.edge_bus[0].json).Statement : s
        if s.Effect == "Allow"
      ]).Principal.AWS]))) == jsonencode([
      "arn:aws:iam::123456789012:role/cs-test-app-task",
      "arn:aws:iam::123456789012:role/cs-test-soar-pb05-harvester",
    ])
    error_message = "With app_publishes_decoy the task role is in BOTH the Allow principals and the Deny exception list."
  }
  assert {
    condition     = output.app_environment.EDGE_BUS_NAME == "cs-test-soar-edge" && output.app_environment.DECOY_PUBLISH_ENABLED == "true"
    error_message = "The app gets the bus name and the publish switch."
  }
}

run "decoy_flag_is_inert_without_pb05" {
  command = apply

  variables {
    enable_app_integration = true
    app_publishes_decoy    = true
    enable_pb05            = false
    block_ip_set_arns      = []
    waf_web_acl            = null
  }

  assert {
    condition = !anytrue(flatten([
      for s in jsondecode(data.aws_iam_policy_document.app_soc_read[0].json).Statement : contains(flatten([s.Action]), "events:PutEvents")
    ]))
    error_message = "No PutEvents grant without the edge bus."
  }
  assert {
    condition     = output.app_environment.EDGE_BUS_NAME == "" && output.app_environment.DECOY_PUBLISH_ENABLED == "false"
    error_message = "No bus name and publishing off without PB-05 (F13: audit-only)."
  }
}

run "rejects_decoy_without_integration" {
  command = plan

  variables {
    app_publishes_decoy = true
  }

  expect_failures = [var.app_publishes_decoy]
}

run "rejects_integration_without_role_name" {
  command = plan

  variables {
    enable_app_integration = true
    app_task_role_name     = null
  }

  expect_failures = [var.app_task_role_name]
}

run "rejects_decoy_without_role_arn" {
  command = plan

  variables {
    enable_app_integration = true
    app_publishes_decoy    = true
    app_task_role_arn      = null
  }

  expect_failures = [var.app_task_role_arn]
}

run "rejects_non_role_arn" {
  command = plan

  variables {
    app_task_role_arn = "arn:aws:iam::123456789012:user/someone"
  }

  expect_failures = [var.app_task_role_arn]
}
