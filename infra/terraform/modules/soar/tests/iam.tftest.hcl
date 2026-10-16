# IAM content tests (audit A10). soar.tftest.hcl mocks the provider, which
# also mocks every aws_iam_policy_document, so it can never see what a policy
# says. Here the REAL provider renders the documents locally (they make no API
# calls); identity lookups and all managed resources are overridden. No
# credentials are needed.

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

variables {
  name                         = "cs-test"
  quarantine_security_group_id = "sg-0aaaaaaaaaaaaaaaa"
  quarantine_network_acl_ids   = ["acl-0bbbbbbbbbbbbbbbb"]
  revocable_role_arns          = ["arn:aws:iam::123456789012:role/cs-test-report-worker"]
  playbook_package = {
    s3_bucket = "artifacts-bucket"
    s3_key    = "soar/playbooks.zip"
  }

  enable_pb04       = true
  ecs_cluster_name  = "cs-test-cluster"
  ecs_cluster_arn   = "arn:aws:ecs:us-east-1:123456789012:cluster/cs-test-cluster"
  ecs_service_names = ["docs-api"]

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
  nat_public_ip         = "198.51.100.10"
  pb05_publisher_arns   = ["arn:aws:iam::123456789012:role/cs-test-docs-api-task"]
  pb05_harvest_schedule = "rate(5 minutes)"

  chatops_webhook_param_name = "/cs-test/soar/chatops_webhook"
}

run "pb01_nacl_permission_is_one_acl_and_add_only" {
  command = apply

  assert {
    condition = one([
      for s in jsondecode(data.aws_iam_policy_document.pb01.json).Statement : s
      if contains(flatten([s.Action]), "ec2:CreateNetworkAclEntry")
    ]).Resource == "arn:aws:ec2:us-east-1:123456789012:network-acl/acl-0bbbbbbbbbbbbbbbb"
    error_message = "PB-01 may add NACL entries only on the worker-tier NACL it is given."
  }
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.pb01.json).Statement :
      !anytrue([for a in flatten([s.Action]) : contains(["ec2:ReplaceNetworkAclEntry", "ec2:DeleteNetworkAclEntry", "ec2:ReplaceNetworkAclAssociation"], a)])
    ])
    error_message = "PB-01 must never be able to loosen or remove NACL entries."
  }
}

run "pb01_mutations_are_conditioned" {
  command = apply

  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.pb01.json).Statement :
      try(s.Condition.StringEquals["aws:ResourceTag/cloudshield:soar-scope"], null) == "in-scope"
      if contains(flatten([s.Action]), "ec2:ModifyInstanceAttribute") && can(regex(":instance/", jsonencode(s.Resource)))
    ])
    error_message = "ModifyInstanceAttribute on instances must require the SOAR scope tag."
  }
  assert {
    condition = one([
      for s in jsondecode(data.aws_iam_policy_document.pb01.json).Statement : s
      if contains(flatten([s.Action]), "iam:PutRolePolicy")
    ]).Condition.StringEquals["iam:PermissionsBoundary"] == "arn:aws:iam::123456789012:policy/cs-test-soar-target-boundary"
    error_message = "Session revocation may only write to roles capped by the SOAR target boundary (M10)."
  }
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.pb01.json).Statement :
      s.Resource != "*" if contains(flatten([s.Action]), "ec2:DescribeInstanceAttribute")
    ])
    error_message = "DescribeInstanceAttribute is resource-level and must be scoped (CKV_AWS_356)."
  }
}

run "evidence_writes_limited_to_incidents_prefix" {
  command = apply

  assert {
    condition = alltrue(flatten([
      for doc in [data.aws_iam_policy_document.pb01.json, data.aws_iam_policy_document.pb03.json, data.aws_iam_policy_document.pb04[0].json] : [
        for s in jsondecode(doc).Statement :
        s.Resource == "arn:aws:s3:::cs-test-soar-evidence-123456789012/incidents/*"
        if contains(flatten([s.Action]), "s3:PutObject")
      ]
    ]))
    error_message = "Playbooks may write evidence only under incidents/."
  }
}

run "pb02_session_revoke_requires_boundary_and_tag" {
  command = apply

  assert {
    condition = alltrue([
      for k, v in one([
        for s in jsondecode(data.aws_iam_policy_document.pb02.json).Statement : s
        if contains(flatten([s.Action]), "iam:PutUserPolicy")
      ]).Condition.StringEquals : contains(["iam:PermissionsBoundary", "aws:ResourceTag/cloudshield:soar-scope"], k)
    ])
    error_message = "PutUserPolicy must be conditioned on the boundary and the scope tag."
  }
}

run "router_sends_only_exposure_findings_to_pb03" {
  command = apply

  assert {
    condition = anytrue([
      for c in jsondecode(aws_sfn_state_machine.router[0].definition).States.RouteByResource.Choices :
      c.Next == "PB03Restore" && anytrue([for a in try(c.And, []) : try(a.StringMatches, "") == "Policy:S3/Bucket*"])
    ])
    error_message = "Only Policy:S3/Bucket* findings may reach PB-03 (audit A1)."
  }
  assert {
    condition     = jsondecode(aws_sfn_state_machine.router[0].definition).States.PB03Evidence.Parameters.Payload.action == "evidence"
    error_message = "PB-03 evidence must run as its own step after CONTAINED, outside the MTTC window (audit A4)."
  }
  assert {
    condition     = jsondecode(aws_sfn_state_machine.router[0].definition).States.MarkContained.Next == "NeedsEvidence"
    error_message = "Evidence capture must come after MarkContained (the MTTC stop)."
  }
}

# =============================================================================
# Phase D (plan §7): PB-04, PB-05, harvester, edge bus, guard additions.
# =============================================================================
run "pb04_ecs_mutations_scoped_to_cluster_and_tag" {
  command = apply

  # StopTask / UpdateService: only task|service ARNs in OUR cluster, with the
  # ecs:cluster condition AND the scope tag.
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.pb04[0].json).Statement :
      alltrue([for r in flatten([s.Resource]) : can(regex("^arn:aws:ecs:us-east-1:123456789012:(task/cs-test-cluster/\\*|service/cs-test-cluster/docs-api)$", r))]) &&
      try(s.Condition.ArnEquals["ecs:cluster"], null) == "arn:aws:ecs:us-east-1:123456789012:cluster/cs-test-cluster" &&
      try(s.Condition.StringEquals["aws:ResourceTag/cloudshield:soar-scope"], null) == "in-scope"
      if anytrue([for a in flatten([s.Action]) : contains(["ecs:StopTask", "ecs:UpdateService"], a)])
    ])
    error_message = "StopTask/UpdateService must be limited to the cluster's tasks/allowed services, with ecs:cluster and the scope tag."
  }
  assert {
    condition = length([
      for s in jsondecode(data.aws_iam_policy_document.pb04[0].json).Statement : s
      if anytrue([for a in flatten([s.Action]) : contains(["ecs:StopTask", "ecs:UpdateService"], a)])
    ]) == 2
    error_message = "Expected exactly the StopInScopeTask and RedeployInScopeService statements."
  }
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.pb04[0].json).Statement :
      flatten([s.Action]) == ["ecs:DescribeTaskDefinition"] || (flatten([s.Action]) == ["ecs:ListTasks"] && try(s.Condition.ArnEquals["ecs:cluster"], null) == "arn:aws:ecs:us-east-1:123456789012:cluster/cs-test-cluster")
      if contains(flatten([s.Resource]), "*")
    ])
    error_message = "Only DescribeTaskDefinition (no resource-level support) and ListTasks (scoped by ecs:cluster) may use Resource \"*\"."
  }
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.pb04[0].json).Statement :
      try(s.Condition.ArnEquals["ecs:cluster"], null) == "arn:aws:ecs:us-east-1:123456789012:cluster/cs-test-cluster"
      if anytrue([for a in flatten([s.Action]) : contains(["ecs:DescribeTasks", "ecs:DescribeServices", "ecs:ListTasks"], a)])
    ])
    error_message = "ECS reads (incl. the ListTasks ownership proof, audit A4) must carry the ecs:cluster condition."
  }
  assert {
    condition = length([
      for s in jsondecode(data.aws_iam_policy_document.pb04[0].json).Statement : s
      if contains(flatten([s.Action]), "ecs:ListTasks")
    ]) == 1
    error_message = "PB-04 proves task ownership with ecs:ListTasks (audit A4)."
  }
  assert {
    condition = !anytrue(flatten([
      for s in jsondecode(data.aws_iam_policy_document.pb04[0].json).Statement : [
        for a in flatten([s.Action]) :
        contains(["ecs:RunTask", "ecs:StartTask", "ecs:DeleteService", "ecs:ExecuteCommand", "ecs:RegisterTaskDefinition", "iam:PassRole"], a) || strcontains(a, "*")
      ]
    ]))
    error_message = "PB-04 must never get RunTask, DeleteService, ExecuteCommand, PassRole or a wildcard action."
  }
}

run "pb05_only_appends_to_the_two_ip_sets" {
  command = apply

  # Audit A1: besides the two IP sets, exactly the corroboration read on the
  # CloudFront ACL and the never-block parameter. Nothing else new.
  assert {
    condition = jsonencode({
      for s in jsondecode(data.aws_iam_policy_document.pb05[0].json).Statement :
      join(",", sort(flatten([s.Action]))) => sort(flatten([s.Resource]))
      }) == jsonencode({
      "wafv2:GetIPSet,wafv2:UpdateIPSet"       = ["arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v4/11111111-1111-1111-1111-111111111111", "arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v6/22222222-2222-2222-2222-222222222222"]
      "wafv2:GetRateBasedStatementManagedKeys" = ["arn:aws:wafv2:us-east-1:123456789012:global/webacl/cs-test-cloudfront/33333333-3333-3333-3333-333333333333"]
      "ssm:GetParameter"                       = ["arn:aws:ssm:us-east-1:123456789012:parameter/cs-test/soar/pb05_never_block"]
    })
    error_message = "PB-05 gets Get/UpdateIPSet on the two sets, GetRateBasedStatementManagedKeys on the CloudFront ACL and GetParameter on the never-block list, nothing else."
  }
  assert {
    condition = !anytrue(flatten([
      for doc in [
        data.aws_iam_policy_document.pb05[0].json,
        data.aws_iam_policy_document.harvester[0].json,
        data.aws_iam_policy_document.sweeper[0].json,
        data.aws_iam_policy_document.pb04[0].json,
        data.aws_iam_policy_document.safety_guard.json,
        ] : [
        for s in jsondecode(doc).Statement : [
          for a in flatten([s.Action]) :
          contains(["wafv2:UpdateWebACL", "wafv2:CreateIPSet"], a) || startswith(a, "wafv2:Delete") || a == "wafv2:*"
        ]
      ]
    ]))
    error_message = "No role may UpdateWebACL, CreateIPSet or Delete* in WAF."
  }
}

run "harvester_reads_keys_and_publishes_only" {
  command = apply

  assert {
    condition = jsonencode({
      for s in jsondecode(data.aws_iam_policy_document.harvester[0].json).Statement :
      join(",", sort(flatten([s.Action]))) => sort(flatten([s.Resource]))
      }) == jsonencode({
      "wafv2:GetRateBasedStatementManagedKeys" = ["arn:aws:wafv2:us-east-1:123456789012:global/webacl/cs-test-cloudfront/33333333-3333-3333-3333-333333333333"]
      "events:PutEvents"                       = ["arn:aws:events:us-east-1:123456789012:event-bus/cs-test-soar-edge"]
      "dynamodb:GetItem,dynamodb:PutItem"      = ["arn:aws:dynamodb:us-east-1:123456789012:table/cs-test-soar-pb05-harvest-state"]
      "kms:Decrypt"                            = ["arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"]
    })
    error_message = "The harvester gets exactly the managed keys on the ACL, PutEvents on the edge bus, Get/PutItem on its sighting table and kms:Decrypt on the SOAR key."
  }
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.harvester_runtime[0].json).Statement :
      alltrue([for a in flatten([s.Action]) : startswith(a, "logs:") || startswith(a, "xray:")])
    ])
    error_message = "The harvester's runtime policy is logs + tracing only."
  }
}

run "edge_bus_denies_every_other_publisher" {
  command = apply

  assert {
    condition = one([
      for s in jsondecode(data.aws_iam_policy_document.edge_bus[0].json).Statement : s
      if s.Effect == "Deny"
      ]).Principal == "*" && sort(flatten([one([
        for s in jsondecode(data.aws_iam_policy_document.edge_bus[0].json).Statement : s
        if s.Effect == "Deny"
      ]).Condition.ArnNotEquals["aws:PrincipalArn"]])) == sort([
      "arn:aws:iam::123456789012:role/cs-test-soar-pb05-harvester",
      "arn:aws:iam::123456789012:role/cs-test-docs-api-task",
    ])
    error_message = "The bus policy must Deny PutEvents to Principal * with ArnNotEquals aws:PrincipalArn == the publisher list (F24)."
  }
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.edge_bus[0].json).Statement :
      flatten([s.Action]) == ["events:PutEvents"] && flatten([s.Resource]) == ["arn:aws:events:us-east-1:123456789012:event-bus/cs-test-soar-edge"]
    ])
    error_message = "The bus policy covers PutEvents on this bus only."
  }
}

run "guard_reads_ecs_task_and_never_block_list" {
  command = apply

  assert {
    condition = one([
      for s in jsondecode(data.aws_iam_policy_document.safety_guard.json).Statement : s
      if contains(flatten([s.Action]), "ecs:DescribeTasks")
      ]).Resource == "arn:aws:ecs:us-east-1:123456789012:task/cs-test-cluster/*" && one([
      for s in jsondecode(data.aws_iam_policy_document.safety_guard.json).Statement : s
      if contains(flatten([s.Action]), "ecs:DescribeTasks")
    ]).Condition.ArnEquals["ecs:cluster"] == "arn:aws:ecs:us-east-1:123456789012:cluster/cs-test-cluster"
    error_message = "The guard may describe tasks in the SOAR cluster only."
  }
  assert {
    condition = contains(flatten([
      for s in jsondecode(data.aws_iam_policy_document.safety_guard.json).Statement : flatten([s.Resource])
      if contains(flatten([s.Action]), "ssm:GetParameter")
    ]), "arn:aws:ssm:us-east-1:123456789012:parameter/cs-test/soar/pb05_never_block")
    error_message = "The guard must be able to read the never-block list (rule 4)."
  }
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.safety_guard.json).Statement :
      alltrue([for a in flatten([s.Action]) : startswith(a, "ssm:Get") || startswith(a, "ec2:Describe") || startswith(a, "iam:List") || startswith(a, "s3:GetBucketTagging") || a == "ecs:DescribeTasks"])
    ])
    error_message = "The guard stays read-only."
  }
}

# Sweeper (audit A2): exactly Get/UpdateIPSet on the two sets, Scan/UpdateItem
# on the incidents table, decrypt with the SOAR key, and its own logs.
run "sweeper_policy_is_exactly_its_grants" {
  command = apply

  assert {
    condition = jsonencode({
      for s in jsondecode(data.aws_iam_policy_document.sweeper[0].json).Statement :
      join(",", sort(flatten([s.Action]))) => sort(flatten([s.Resource]))
      }) == jsonencode({
      "wafv2:GetIPSet,wafv2:UpdateIPSet"       = ["arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v4/11111111-1111-1111-1111-111111111111", "arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v6/22222222-2222-2222-2222-222222222222"]
      "dynamodb:Scan,dynamodb:UpdateItem"      = ["arn:aws:dynamodb:us-east-1:123456789012:table/cs-test-soar-incidents"]
      "kms:Decrypt"                            = ["arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"]
      "logs:CreateLogStream,logs:PutLogEvents" = ["arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/cs-test-soar-pb05-sweeper:*"]
    })
    error_message = "The sweeper role gets exactly the two IP sets, Scan/UpdateItem on the incidents table, kms:Decrypt and its own logs."
  }
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.sweeper[0].json).Statement :
      s.Effect == "Allow" && try(s.Condition, null) == null
    ])
    error_message = "The sweeper policy is four plain Allow statements."
  }
}

# Notifier (plan §5.1): exactly the parameter, GetItem on the table, decrypt
# with the SOAR key, and its own logs. Nothing else, no wildcards.
run "notifier_policy_is_exactly_its_grants" {
  command = apply

  assert {
    condition = {
      for s in jsondecode(data.aws_iam_policy_document.notifier[0].json).Statement :
      join(",", sort(flatten([s.Action]))) => flatten([s.Resource])
      } == {
      "ssm:GetParameter"                       = ["arn:aws:ssm:us-east-1:123456789012:parameter/cs-test/soar/chatops_webhook"]
      "dynamodb:GetItem"                       = ["arn:aws:dynamodb:us-east-1:123456789012:table/cs-test-soar-incidents"]
      "kms:Decrypt"                            = ["arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"]
      "logs:CreateLogStream,logs:PutLogEvents" = ["arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/cs-test-soar-notifier:*"]
    }
    error_message = "The notifier role gets exactly ssm:GetParameter on its parameter, dynamodb:GetItem on the incidents table, kms:Decrypt on the SOAR key and its own logs."
  }
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.notifier[0].json).Statement :
      s.Effect == "Allow" && try(s.Condition, null) == null
    ])
    error_message = "The notifier policy is four plain Allow statements."
  }
}
