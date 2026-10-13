# terraform test — runs offline with a mocked AWS provider (no credentials).
#   terraform -chdir=infra/terraform/modules/soar init -backend=false
#   terraform -chdir=infra/terraform/modules/soar test

mock_provider "aws" {}

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
