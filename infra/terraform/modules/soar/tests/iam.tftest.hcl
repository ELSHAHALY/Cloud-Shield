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

variables {
  name                         = "cs-test"
  quarantine_security_group_id = "sg-0aaaaaaaaaaaaaaaa"
  quarantine_network_acl_ids   = ["acl-0bbbbbbbbbbbbbbbb"]
  revocable_role_arns          = ["arn:aws:iam::123456789012:role/cs-test-report-worker"]
  playbook_package = {
    s3_bucket = "artifacts-bucket"
    s3_key    = "soar/playbooks.zip"
  }
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
      for doc in [data.aws_iam_policy_document.pb01.json, data.aws_iam_policy_document.pb03.json] : [
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
