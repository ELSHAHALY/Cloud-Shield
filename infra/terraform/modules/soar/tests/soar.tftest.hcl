# terraform test — runs offline with a mocked AWS provider (no credentials).
#   terraform -chdir=infra/terraform/modules/soar init -backend=false
#   terraform -chdir=infra/terraform/modules/soar test

mock_provider "aws" {
  # The mock fills computed attributes with random strings, which the provider
  # then rejects wherever it validates JSON policies or ARNs. Pin realistic
  # values for every data source the module reads and every ARN it references.
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }
  mock_data "aws_region" {
    defaults = {
      region = "us-east-1"
    }
  }
  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }
  mock_resource "aws_cloudwatch_event_rule" {
    defaults = {
      arn = "arn:aws:events:us-east-1:123456789012:rule/mock"
    }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-east-1:123456789012:log-group:mock"
    }
  }
  mock_resource "aws_dynamodb_table" {
    defaults = {
      arn = "arn:aws:dynamodb:us-east-1:123456789012:table/mock"
    }
  }
  mock_resource "aws_iam_policy" {
    defaults = {
      arn = "arn:aws:iam::123456789012:policy/mock"
    }
  }
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/mock"
    }
  }
  mock_resource "aws_kms_key" {
    defaults = {
      arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    }
  }
  mock_resource "aws_lambda_function" {
    defaults = {
      arn = "arn:aws:lambda:us-east-1:123456789012:function:mock"
    }
  }
  mock_resource "aws_s3_bucket" {
    defaults = {
      arn = "arn:aws:s3:::mock"
    }
  }
  mock_resource "aws_sfn_state_machine" {
    defaults = {
      arn = "arn:aws:states:us-east-1:123456789012:stateMachine:mock"
    }
  }
  mock_resource "aws_sns_topic" {
    defaults = {
      arn = "arn:aws:sns:us-east-1:123456789012:mock"
    }
  }
  mock_resource "aws_ssm_parameter" {
    defaults = {
      arn = "arn:aws:ssm:us-east-1:123456789012:parameter/mock"
    }
  }
}

variables {
  name                         = "cs-test"
  quarantine_security_group_id = "sg-0aaaaaaaaaaaaaaaa"
}

run "defaults_are_safe" {
  command = apply

  assert {
    condition     = nonsensitive(aws_ssm_parameter.dry_run.value) == "true"
    error_message = "SOAR must default to dry-run."
  }
  assert {
    condition     = length(aws_lambda_function.playbook) == 0
    error_message = "No Lambdas may exist until a playbook package is supplied."
  }
  assert {
    condition     = length(aws_sfn_state_machine.router) == 0
    error_message = "cs-ir-router must not exist until playbooks are enabled."
  }
  assert {
    condition     = length(aws_cloudwatch_event_target.sns) == 1 && length(aws_cloudwatch_event_target.sfn) == 0
    error_message = "Baseline: GuardDuty findings must go to SNS only."
  }
  assert {
    condition     = aws_dynamodb_table.incidents.point_in_time_recovery[0].enabled
    error_message = "Incidents table needs PITR."
  }
  assert {
    condition     = aws_s3_bucket_public_access_block.evidence.restrict_public_buckets
    error_message = "Evidence bucket must block public access."
  }
}

run "playbooks_enabled_wires_router" {
  command = apply

  variables {
    playbook_package = {
      s3_bucket = "artifacts-bucket"
      s3_key    = "soar/playbooks.zip"
    }
  }

  assert {
    condition     = length(aws_lambda_function.playbook) == 4
    error_message = "Expected safety guard + PB-01/02/03."
  }
  assert {
    condition     = jsondecode(aws_sfn_state_machine.router[0].definition).States.GuardDecision.Default == "RecordBlocked"
    error_message = "Safety guard must FAIL CLOSED: anything but allowed==true is blocked."
  }
  assert {
    condition     = jsondecode(aws_sfn_state_machine.router[0].definition).States.IsDryRun.Default == "MarkWouldContain"
    error_message = "Dry-run check must FAIL CLOSED: only an explicit dry_run==false may act."
  }
  assert {
    condition     = jsondecode(aws_sfn_state_machine.router[0].definition).States.CheckContained.Default == "PlaybookDidNotContain"
    error_message = "CONTAINED (and MTTC) may only be recorded when the playbook proves containment."
  }
  assert {
    condition     = jsondecode(aws_sfn_state_machine.router[0].definition).States.RouteByResource.Choices[0].Next == "PB01Isolate"
    error_message = "Instance credential exfiltration (scenario A) must route to PB-01 before the generic AccessKey route."
  }
  assert {
    condition     = length(aws_sfn_state_machine.router) == 1 && length(aws_cloudwatch_event_target.sfn) == 1
    error_message = "EventBridge must target cs-ir-router when playbooks are enabled."
  }
  assert {
    condition     = length(aws_cloudwatch_event_target.sns) == 0
    error_message = "SNS baseline target must be removed when the router takes over (no double paging)."
  }
  assert {
    condition     = jsondecode(aws_sfn_state_machine.router[0].definition).StartAt == "RecordDetected"
    error_message = "The router must record the incident (and the MTTC start time) first."
  }
  assert {
    condition     = jsondecode(aws_sfn_state_machine.router[0].definition).States.SafetyGuard.Next == "GuardDecision"
    error_message = "Every playbook must sit behind the safety guard."
  }
  assert {
    condition     = jsondecode(aws_sfn_state_machine.router[0].definition).States.RecordDetected.Parameters.ExpressionAttributeValues[":et"]["S.$"] == "$.time"
    error_message = "MTTC must start from the EventBridge event time (decision 8 Oct)."
  }
}

run "scenario_findings_bypass_severity_threshold" {
  command = apply

  assert {
    condition     = anytrue([for t in jsondecode(aws_cloudwatch_event_rule.guardduty.event_pattern).detail["$or"][1].type : t == "Recon:EC2/Portscan"])
    error_message = "Medium-severity Recon:EC2/Portscan (scenario A) must still reach SOAR."
  }
  assert {
    condition     = aws_iam_policy.target_boundary.name == "cs-test-soar-target-boundary"
    error_message = "The SOAR target permissions boundary must always exist."
  }
}

run "rejects_out_of_range_severity" {
  command = plan

  variables {
    min_severity = 11
  }

  expect_failures = [var.min_severity]
}

run "pb01_nacl_quarantine_is_scoped" {
  command = plan

  variables {
    playbook_package = {
      s3_bucket = "artifacts-bucket"
      s3_key    = "soar/playbooks.zip"
    }
    quarantine_network_acl_ids = ["acl-0bbbbbbbbbbbbbbbb"]
  }

  assert {
    condition     = local.quarantine_nacl_arns == ["arn:aws:ec2:us-east-1:123456789012:network-acl/acl-0bbbbbbbbbbbbbbbb"]
    error_message = "PB-01 may add NACL entries only to the worker-tier NACL it is given."
  }
  assert {
    condition     = aws_lambda_function.playbook["soar-pb01-ec2-isolate"].environment[0].variables.QUARANTINE_NACL_IDS == "acl-0bbbbbbbbbbbbbbbb"
    error_message = "PB-01 must receive the NACL allow-list it is permitted to touch."
  }
}

run "rejects_nacl_rule_at_or_above_allow" {
  command = plan

  variables {
    quarantine_nacl_rule_number = 100
  }

  expect_failures = [var.quarantine_nacl_rule_number]
}
