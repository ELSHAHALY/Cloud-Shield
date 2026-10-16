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
  mock_resource "aws_cloudwatch_event_bus" {
    defaults = {
      arn = "arn:aws:events:us-east-1:123456789012:event-bus/mock"
    }
  }
  mock_resource "aws_cloudwatch_metric_alarm" {
    defaults = {
      arn = "arn:aws:cloudwatch:us-east-1:123456789012:alarm:mock"
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

# =============================================================================
# Phase D: PB-04 / PB-05 (plan §4.3, §7)
# =============================================================================
run "pb04_pb05_absent_by_default" {
  command = apply

  variables {
    playbook_package = {
      s3_bucket = "artifacts-bucket"
      s3_key    = "soar/playbooks.zip"
    }
  }

  assert {
    condition     = length(aws_lambda_function.playbook) == 4 && !contains(keys(aws_lambda_function.playbook), "soar-pb04-ecs-task-contain") && !contains(keys(aws_lambda_function.playbook), "soar-pb05-waf-ip-block")
    error_message = "PB-04 and PB-05 must not exist unless enabled."
  }
  assert {
    condition     = length(aws_cloudwatch_event_bus.edge) == 0 && length(aws_lambda_function.harvester) == 0 && length(aws_ssm_parameter.never_block) == 0 && length(aws_cloudwatch_metric_alarm.rate_limited) == 0
    error_message = "The edge bus, harvester, never-block list and alarm must not exist unless PB-05 is enabled."
  }
  assert {
    condition     = length(jsondecode(aws_sfn_state_machine.router[0].definition).States.RouteByResource.Choices) == 4 && !can(jsondecode(aws_sfn_state_machine.router[0].definition).States.PB04Contain) && !can(jsondecode(aws_sfn_state_machine.router[0].definition).States.PB05Block)
    error_message = "With both off, the router graph must be the Phase C graph."
  }
  # Audit A6: the exact ordered choices, conditions included, are the shared
  # table (tests/route_choices.json, also evaluated by soar/tests/test_sims.py)
  # minus the PB-04 / PB-05 entries.
  assert {
    condition     = [for c in jsondecode(aws_sfn_state_machine.router[0].definition).States.RouteByResource.Choices : c.Next] == ["PB01Isolate", "PB01Isolate", "PB02Revoke", "PB03Restore"]
    error_message = "RouteByResource order with PB-04/PB-05 off must be PB01 (exfiltration), PB01 (instance), PB02, PB03."
  }
  assert {
    condition     = jsonencode(jsondecode(aws_sfn_state_machine.router[0].definition).States.RouteByResource.Choices) == jsonencode([for c in jsondecode(file("${path.module}/tests/route_choices.json")) : c if !contains(["PB04Contain", "PB05Block"], c.Next)])
    error_message = "RouteByResource must equal tests/route_choices.json without the PB-04/PB-05 choices."
  }
  assert {
    condition     = length(aws_lambda_function.sweeper) == 0 && length(aws_dynamodb_table.harvest_state) == 0 && length(aws_cloudwatch_event_rule.sweep) == 0
    error_message = "No sweeper or sighting table unless PB-05 is enabled."
  }
  assert {
    condition     = aws_lambda_function.playbook["soar-safety-guard"].environment[0].variables.EDGE_EVENT_SOURCE == "" && aws_lambda_function.playbook["soar-safety-guard"].environment[0].variables.ECS_CLUSTER_ARN == ""
    error_message = "Feature off must reach the code as empty settings, so the guard refuses ECS and IP targets."
  }
}

run "flags_without_package_create_nothing" {
  command = apply

  variables {
    enable_pb04       = true
    ecs_cluster_name  = "cs-test-cluster"
    ecs_cluster_arn   = "arn:aws:ecs:us-east-1:123456789012:cluster/cs-test-cluster"
    ecs_service_names = ["docs-api"]
    enable_pb05       = true
    block_ip_set_arns = ["arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v4/11111111-1111-1111-1111-111111111111", "arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v6/22222222-2222-2222-2222-222222222222"]
    waf_web_acl       = { name = "cs-test-cloudfront", id = "33333333-3333-3333-3333-333333333333", arn = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/cs-test-cloudfront/33333333-3333-3333-3333-333333333333" }
    nat_public_ip     = "198.51.100.10"
  }

  assert {
    condition     = length(aws_lambda_function.playbook) == 0 && length(aws_cloudwatch_event_bus.edge) == 0 && length(aws_lambda_function.harvester) == 0 && length(aws_lambda_function.sweeper) == 0 && length(aws_dynamodb_table.harvest_state) == 0
    error_message = "PB-04/PB-05 flags need the playbook package too."
  }
}

run "pb04_pb05_enabled" {
  command = apply

  variables {
    playbook_package = {
      s3_bucket = "artifacts-bucket"
      s3_key    = "soar/playbooks.zip"
    }
    enable_pb04            = true
    ecs_cluster_name       = "cs-test-cluster"
    ecs_cluster_arn        = "arn:aws:ecs:us-east-1:123456789012:cluster/cs-test-cluster"
    ecs_service_names      = ["docs-api"]
    enable_pb05            = true
    block_ip_set_arns      = ["arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v4/11111111-1111-1111-1111-111111111111", "arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v6/22222222-2222-2222-2222-222222222222"]
    waf_web_acl            = { name = "cs-test-cloudfront", id = "33333333-3333-3333-3333-333333333333", arn = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/cs-test-cloudfront/33333333-3333-3333-3333-333333333333" }
    nat_public_ip          = "198.51.100.10"
    pb05_never_block_cidrs = ["203.0.113.0/24"]
  }

  assert {
    condition     = length(aws_lambda_function.playbook) == 6 && aws_lambda_function.playbook["soar-pb04-ecs-task-contain"].timeout == 55 && aws_lambda_function.playbook["soar-pb05-waf-ip-block"].timeout == 20
    error_message = "Expected guard + PB-01..05, with PB-04 at 55 s and PB-05 at 20 s."
  }
  assert {
    condition     = aws_lambda_function.playbook["soar-pb04-ecs-task-contain"].handler == "playbooks.pb04_ecs_task_contain.lambda_handler" && aws_lambda_function.playbook["soar-pb05-waf-ip-block"].handler == "playbooks.pb05_waf_ip_block.lambda_handler" && aws_lambda_function.harvester[0].handler == "playbooks.pb05_waf_ip_block.harvest_handler"
    error_message = "Handler paths must match the soar/ package."
  }
  assert {
    condition = (
      aws_lambda_function.playbook["soar-safety-guard"].environment[0].variables.ECS_CLUSTER_ARN == "arn:aws:ecs:us-east-1:123456789012:cluster/cs-test-cluster" &&
      aws_lambda_function.playbook["soar-safety-guard"].environment[0].variables.ECS_SERVICE_NAMES == "docs-api" &&
      aws_lambda_function.playbook["soar-safety-guard"].environment[0].variables.EDGE_EVENT_SOURCE == "cloudshield.edge" &&
      aws_lambda_function.playbook["soar-safety-guard"].environment[0].variables.NEVER_BLOCK_PARAM == "/cs-test/soar/pb05_never_block" &&
      aws_lambda_function.playbook["soar-pb05-waf-ip-block"].environment[0].variables.WAF_REGION == "us-east-1" &&
      aws_lambda_function.playbook["soar-pb05-waf-ip-block"].environment[0].variables.BLOCK_IP_SET_MAX == "1000" &&
      aws_lambda_function.playbook["soar-pb05-waf-ip-block"].environment[0].variables.BLOCK_TTL_HOURS == "24" &&
      aws_lambda_function.playbook["soar-pb05-waf-ip-block"].environment[0].variables.NEVER_BLOCK_PARAM == "/cs-test/soar/pb05_never_block" &&
      aws_lambda_function.playbook["soar-pb05-waf-ip-block"].environment[0].variables.WAF_WEB_ACL_NAME == "cs-test-cloudfront" &&
      aws_lambda_function.playbook["soar-pb05-waf-ip-block"].environment[0].variables.WAF_WEB_ACL_ID == "33333333-3333-3333-3333-333333333333" &&
      aws_lambda_function.playbook["soar-pb05-waf-ip-block"].environment[0].variables.WAF_RATE_RULE_NAME == "SoarApiRateLimit"
    )
    error_message = "The Phase D settings must reach the functions."
  }
  assert {
    condition     = aws_ssm_parameter.never_block[0].value == "198.51.100.10/32,203.0.113.0/24" && aws_ssm_parameter.never_block[0].type == "String"
    error_message = "The never-block list must hold the NAT EIP /32 plus the operator CIDRs."
  }
  assert {
    condition     = aws_cloudwatch_event_bus.edge[0].name == "cs-test-soar-edge"
    error_message = "PB-05 events need their own bus."
  }
  assert {
    condition     = jsonencode(jsondecode(aws_cloudwatch_event_rule.edge[0].event_pattern)) == jsonencode({ source = ["cloudshield.edge"], detail = { type = [{ prefix = "CloudShield:IPAddress/" }], resource = { resourceType = ["IPAddress"] } } }) && aws_cloudwatch_event_rule.edge[0].event_bus_name == "cs-test-soar-edge"
    error_message = "Only CloudShield:IPAddress/* edge events naming an IPAddress, on the dedicated bus, may start the router (audit A5)."
  }
  assert {
    condition     = aws_cloudwatch_event_target.edge[0].arn == aws_sfn_state_machine.router[0].arn && aws_cloudwatch_event_target.edge[0].event_bus_name == "cs-test-soar-edge"
    error_message = "The edge rule must target cs-ir-router."
  }
  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.harvest[0].event_pattern).detail.state.value == ["ALARM"] && aws_lambda_permission.harvest[0].source_arn == aws_cloudwatch_event_rule.harvest[0].arn
    error_message = "The harvester runs on the transition to ALARM, invokable only by that rule."
  }
  assert {
    condition     = aws_cloudwatch_metric_alarm.rate_limited[0].dimensions == tomap({ WebACL = "cs-test-cloudfront", Rule = "SoarApiRateLimit" }) && aws_cloudwatch_metric_alarm.rate_limited[0].namespace == "AWS/WAFV2"
    error_message = "The alarm must watch the /api/* PB-05 rate rule, never the site-wide one (audit A2)."
  }
  assert {
    condition     = aws_cloudwatch_event_rule.harvest_schedule[0].schedule_expression == "rate(5 minutes)" && aws_lambda_permission.harvest_schedule[0].source_arn == aws_cloudwatch_event_rule.harvest_schedule[0].arn
    error_message = "The periodic harvest is ON by default with PB-05 (audit A2: it provides the second consecutive sighting)."
  }
  assert {
    condition = (
      aws_lambda_function.harvester[0].environment[0].variables.EDGE_BUS_NAME == "cs-test-soar-edge" &&
      aws_lambda_function.harvester[0].environment[0].variables.WAF_WEB_ACL_ID == "33333333-3333-3333-3333-333333333333" &&
      aws_lambda_function.harvester[0].environment[0].variables.WAF_RATE_RULE_NAME == "SoarApiRateLimit" &&
      aws_lambda_function.harvester[0].environment[0].variables.HARVEST_STATE_TABLE == "cs-test-soar-pb05-harvest-state" &&
      aws_lambda_function.harvester[0].environment[0].variables.HARVEST_MIN_GAP_SECONDS == "60" &&
      aws_lambda_function.harvester[0].environment[0].variables.HARVEST_MAX_GAP_SECONDS == "660"
    )
    error_message = "The harvester reads the PB-05 rule and keeps its persistence state in the dedicated table."
  }
  assert {
    condition = (
      aws_dynamodb_table.harvest_state[0].billing_mode == "PAY_PER_REQUEST" &&
      aws_dynamodb_table.harvest_state[0].hash_key == "ipAddress" &&
      aws_dynamodb_table.harvest_state[0].ttl[0].enabled && aws_dynamodb_table.harvest_state[0].ttl[0].attribute_name == "expiresAt" &&
      aws_dynamodb_table.harvest_state[0].server_side_encryption[0].enabled && aws_dynamodb_table.harvest_state[0].server_side_encryption[0].kms_key_arn == aws_kms_key.this.arn
    )
    error_message = "Sighting table: on-demand, TTL on expiresAt, SSE with the SOAR key."
  }
  # ---- sweeper (audit A2)
  assert {
    condition = (
      aws_lambda_function.sweeper[0].handler == "playbooks.pb05_unblock_sweeper.lambda_handler" &&
      aws_lambda_function.sweeper[0].environment[0].variables == tomap({
        INCIDENTS_TABLE   = "cs-test-soar-incidents"
        BLOCK_IP_SET_ARNS = "arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v4/11111111-1111-1111-1111-111111111111,arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-test-soar-blocked-ips-v6/22222222-2222-2222-2222-222222222222"
        WAF_REGION        = "us-east-1"
      })
    )
    error_message = "The sweeper gets exactly the incidents table, the two IP sets and the WAF region."
  }
  assert {
    condition     = aws_cloudwatch_event_rule.sweep[0].schedule_expression == "rate(15 minutes)" && aws_cloudwatch_event_target.sweep[0].arn == aws_lambda_function.sweeper[0].arn && aws_lambda_permission.sweep[0].source_arn == aws_cloudwatch_event_rule.sweep[0].arn && aws_lambda_permission.sweep[0].principal == "events.amazonaws.com"
    error_message = "The sweeper runs every 15 minutes, invokable only by its schedule."
  }
  assert {
    condition     = aws_cloudwatch_log_group.sweeper[0].name == "/aws/lambda/cs-test-soar-pb05-sweeper" && aws_cloudwatch_log_group.sweeper[0].kms_key_id == aws_kms_key.this.arn
    error_message = "The sweeper logs go to its own KMS-encrypted group."
  }
  assert {
    condition     = !contains(keys(aws_lambda_function.playbook), "soar-pb05-sweeper")
    error_message = "The sweeper is not a playbook: it must not get the playbook roles or environment."
  }
  # ---- router graph (audit A6): exact order and conditions = the shared table
  assert {
    condition     = [for c in jsondecode(aws_sfn_state_machine.router[0].definition).States.RouteByResource.Choices : c.Next] == ["PB01Isolate", "PB01Isolate", "PB02Revoke", "PB03Restore", "PB04Contain", "PB05Block"]
    error_message = "RouteByResource order must be PB01 (exfiltration), PB01 (instance), PB02, PB03, PB04, PB05."
  }
  assert {
    condition     = jsonencode(jsondecode(aws_sfn_state_machine.router[0].definition).States.RouteByResource.Choices) == jsonencode(jsondecode(file("${path.module}/tests/route_choices.json")))
    error_message = "RouteByResource must equal tests/route_choices.json exactly (the table test_sims.py evaluates _route against)."
  }
  assert {
    condition = alltrue([
      for c in jsondecode(aws_sfn_state_machine.router[0].definition).States.RouteByResource.Choices :
      anytrue([for a in try(c.And, [c]) : try(a.Variable, "") == "$.detail.resource.resourceType" && can(a.StringEquals)])
    ])
    error_message = "Every RouteByResource choice must require a resourceType (audit A5)."
  }
  assert {
    condition = anytrue([
      for c in jsondecode(aws_sfn_state_machine.router[0].definition).States.RouteByResource.Choices :
      c.Next == "PB04Contain" && anytrue([for a in try(c.And, []) : try(a.StringEquals, "") == "ECSCluster"]) && anytrue([for a in try(c.And, []) : try(a.StringMatches, "") == "*:Runtime/*"])
    ])
    error_message = "ECSCluster + *:Runtime/* findings must route to PB04Contain."
  }
  assert {
    condition = anytrue([
      for c in jsondecode(aws_sfn_state_machine.router[0].definition).States.RouteByResource.Choices :
      c.Next == "PB05Block" && anytrue([for a in try(c.And, []) : try(a.Variable, "") == "$.source" && try(a.StringEquals, "") == "cloudshield.edge"]) && anytrue([for a in try(c.And, []) : try(a.StringEquals, "") == "IPAddress"])
    ])
    error_message = "Only source == cloudshield.edge with resourceType IPAddress may reach PB05Block."
  }
  assert {
    condition = alltrue([
      for k, s in jsondecode(aws_sfn_state_machine.router[0].definition).States :
      !strcontains(jsonencode(s), "\"PB04Contain\"") && !strcontains(jsonencode(s), "\"PB05Block\"")
      if k != "RouteByResource"
    ])
    error_message = "PB04Contain and PB05Block must be reachable only from RouteByResource."
  }
  assert {
    condition = alltrue([
      for k, s in jsondecode(aws_sfn_state_machine.router[0].definition).States :
      !strcontains(jsonencode(s), "\"Next\":\"RouteByResource\"") if k != "GuardDecision"
    ])
    error_message = "RouteByResource (and so every playbook) must be reachable only after GuardDecision."
  }
  assert {
    condition = alltrue([
      for k, s in jsondecode(aws_sfn_state_machine.router[0].definition).States :
      !strcontains(jsonencode(s), "\"Next\":\"MarkContained\"") if k != "CheckContained"
    ])
    error_message = "CONTAINED must be reachable only via CheckContained."
  }
  assert {
    condition     = jsondecode(aws_sfn_state_machine.router[0].definition).States.PB04Contain.Next == "IsDryRun" && jsondecode(aws_sfn_state_machine.router[0].definition).States.PB05Block.Next == "IsDryRun" && jsondecode(aws_sfn_state_machine.router[0].definition).States.PB04Contain.Catch[0].Next == "RecordFailed" && jsondecode(aws_sfn_state_machine.router[0].definition).States.PB05Block.Catch[0].Next == "RecordFailed"
    error_message = "PB-04/PB-05 must go through the fail-closed IsDryRun and fail to RecordFailed."
  }
  assert {
    condition     = jsondecode(aws_sfn_state_machine.router[0].definition).States.PB04Contain.Parameters.Payload.action == "contain" && jsondecode(aws_sfn_state_machine.router[0].definition).States.PB05Block.Parameters.Payload.action == "block"
    error_message = "Wrong playbook actions."
  }
  assert {
    condition = anytrue([
      for c in jsondecode(aws_sfn_state_machine.router[0].definition).States.NeedsEvidence.Choices :
      c.Next == "PB04Evidence" && c.StringEquals == "ECSCluster"
    ]) && jsondecode(aws_sfn_state_machine.router[0].definition).States.PB04Evidence.Parameters.Payload.action == "evidence" && jsondecode(aws_sfn_state_machine.router[0].definition).States.PB04Evidence.Catch[0].Next == "Notify"
    error_message = "ECS evidence must run after CONTAINED (NeedsEvidence -> PB04Evidence), and its failure must not un-contain."
  }
  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.guardduty.event_pattern) == { source = ["aws.guardduty"], "detail-type" = ["GuardDuty Finding"], detail = { "$or" = [{ severity = [{ numeric = [">=", 7] }] }, { type = ["Recon:EC2/Portscan", { prefix = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration" }, { prefix = "Policy:S3/" }] }] } }
    error_message = "The GuardDuty rule must be unchanged: Runtime findings only at >= min_severity (D19)."
  }
}

run "pb05_harvest_schedule_can_be_turned_off" {
  command = apply

  variables {
    playbook_package = {
      s3_bucket = "artifacts-bucket"
      s3_key    = "soar/playbooks.zip"
    }
    enable_pb05            = true
    block_ip_set_arns      = ["arn:aws:wafv2:us-east-1:123456789012:global/ipset/a/11111111-1111-1111-1111-111111111111", "arn:aws:wafv2:us-east-1:123456789012:global/ipset/b/22222222-2222-2222-2222-222222222222"]
    waf_web_acl            = { name = "cs-test-cloudfront", id = "33333333-3333-3333-3333-333333333333", arn = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/cs-test-cloudfront/33333333-3333-3333-3333-333333333333" }
    pb05_never_block_cidrs = ["203.0.113.7/32"]
    pb05_harvest_schedule  = null
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.harvest_schedule) == 0 && length(aws_lambda_permission.harvest_schedule) == 0
    error_message = "pb05_harvest_schedule = null turns the periodic harvest off."
  }
  assert {
    condition     = length(aws_lambda_function.sweeper) == 1
    error_message = "The sweeper exists whenever PB-05 does."
  }
  assert {
    condition     = jsonencode(jsondecode(aws_sfn_state_machine.router[0].definition).States.RouteByResource.Choices) == jsonencode([for c in jsondecode(file("${path.module}/tests/route_choices.json")) : c if c.Next != "PB04Contain"])
    error_message = "With PB-05 alone, RouteByResource must equal the shared table without the PB-04 choice."
  }
  assert {
    condition     = aws_ssm_parameter.never_block[0].value == "203.0.113.7/32"
    error_message = "Without a NAT IP the list holds the operator CIDRs only."
  }
  assert {
    condition     = length(aws_lambda_function.playbook) == 5 && !contains(keys(aws_lambda_function.playbook), "soar-pb04-ecs-task-contain")
    error_message = "PB-05 alone must not create PB-04."
  }
}

run "pb05_requires_us_east_1" {
  command = plan

  override_data {
    target = data.aws_region.current
    values = { region = "eu-west-1" }
  }

  variables {
    playbook_package = {
      s3_bucket = "artifacts-bucket"
      s3_key    = "soar/playbooks.zip"
    }
    enable_pb05       = true
    block_ip_set_arns = ["arn:aws:wafv2:us-east-1:123456789012:global/ipset/a/11111111-1111-1111-1111-111111111111", "arn:aws:wafv2:us-east-1:123456789012:global/ipset/b/22222222-2222-2222-2222-222222222222"]
    waf_web_acl       = { name = "cs-test-cloudfront", id = "33333333-3333-3333-3333-333333333333", arn = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/cs-test-cloudfront/33333333-3333-3333-3333-333333333333" }
    nat_public_ip     = "198.51.100.10"
  }

  expect_failures = [aws_cloudwatch_event_bus.edge]
}

run "pb05_requires_a_never_block_list" {
  command = plan

  variables {
    playbook_package = {
      s3_bucket = "artifacts-bucket"
      s3_key    = "soar/playbooks.zip"
    }
    enable_pb05       = true
    block_ip_set_arns = ["arn:aws:wafv2:us-east-1:123456789012:global/ipset/a/11111111-1111-1111-1111-111111111111", "arn:aws:wafv2:us-east-1:123456789012:global/ipset/b/22222222-2222-2222-2222-222222222222"]
    waf_web_acl       = { name = "cs-test-cloudfront", id = "33333333-3333-3333-3333-333333333333", arn = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/cs-test-cloudfront/33333333-3333-3333-3333-333333333333" }
  }

  expect_failures = [aws_ssm_parameter.never_block]
}

run "pb04_requires_cluster_and_services" {
  command = plan

  variables {
    enable_pb04 = true
  }

  expect_failures = [var.ecs_cluster_name, var.ecs_cluster_arn, var.ecs_service_names]
}

run "pb05_requires_ip_sets_and_acl" {
  command = plan

  variables {
    enable_pb05 = true
  }

  expect_failures = [var.block_ip_set_arns, var.waf_web_acl]
}

run "rejects_bad_pb05_inputs" {
  command = plan

  variables {
    pb05_block_ttl_hours         = 0
    pb05_ip_set_max              = 10000
    pb05_never_block_cidrs       = ["not-a-cidr"]
    nat_public_ip                = "nat"
    pb05_publisher_arns          = ["arn:aws:iam::123456789012:user/alice"]
    pb05_harvest_schedule        = "every 5 minutes"
    pb05_sweep_schedule          = "every 15 minutes"
    pb05_harvest_min_gap_seconds = 3601
  }

  expect_failures = [
    var.pb05_block_ttl_hours,
    var.pb05_ip_set_max,
    var.pb05_never_block_cidrs,
    var.nat_public_ip,
    var.pb05_publisher_arns,
    var.pb05_harvest_schedule,
    var.pb05_sweep_schedule,
    var.pb05_harvest_min_gap_seconds,
  ]
}

run "rejects_harvest_gaps_out_of_order" {
  command = plan

  variables {
    pb05_harvest_min_gap_seconds = 600
    pb05_harvest_max_gap_seconds = 300
  }

  expect_failures = [var.pb05_harvest_max_gap_seconds]
}

# =============================================================================
# Phase D: ChatOps notifier (plan §5.1, §7)
# =============================================================================
run "notifier_absent_by_default" {
  command = apply

  variables {
    playbook_package = {
      s3_bucket = "artifacts-bucket"
      s3_key    = "soar/playbooks.zip"
    }
  }

  assert {
    condition     = length(aws_lambda_function.notifier) == 0 && length(aws_sns_topic_subscription.notifier) == 0 && length(aws_lambda_permission.notifier) == 0 && length(aws_iam_role.notifier) == 0
    error_message = "No notifier unless chatops_webhook_param_name is set."
  }
  assert {
    condition     = output.notifier_function_name == null
    error_message = "notifier_function_name must be null when the notifier is off."
  }
}

run "notifier_needs_the_package" {
  command = apply

  variables {
    chatops_webhook_param_name = "/cs-test/soar/chatops_webhook"
  }

  assert {
    condition     = length(aws_lambda_function.notifier) == 0 && length(aws_sns_topic_subscription.notifier) == 0
    error_message = "The notifier ships in the playbook zip: no package, no notifier."
  }
}

run "notifier_enabled" {
  command = apply

  variables {
    playbook_package = {
      s3_bucket = "artifacts-bucket"
      s3_key    = "soar/playbooks.zip"
    }
    chatops_webhook_param_name = "/cs-test/soar/chatops_webhook"
  }

  assert {
    condition     = aws_lambda_function.notifier[0].handler == "notifier.handler.lambda_handler" && aws_lambda_function.notifier[0].function_name == "cs-test-soar-notifier"
    error_message = "The notifier handler path must match the soar/ package."
  }
  assert {
    condition = aws_lambda_function.notifier[0].environment[0].variables == tomap({
      INCIDENTS_TABLE       = "cs-test-soar-incidents"
      CHATOPS_WEBHOOK_PARAM = "/cs-test/soar/chatops_webhook"
      CHATOPS_ALLOWED_HOSTS = "hooks.slack.com,discord.com"
    })
    error_message = "The notifier gets the parameter NAME and the allow-list, never the URL."
  }
  assert {
    condition     = aws_sns_topic_subscription.notifier[0].protocol == "lambda" && aws_sns_topic_subscription.notifier[0].topic_arn == aws_sns_topic.incidents.arn && aws_sns_topic_subscription.notifier[0].endpoint == aws_lambda_function.notifier[0].arn
    error_message = "The notifier must be subscribed to the incidents topic."
  }
  assert {
    condition     = aws_lambda_permission.notifier[0].principal == "sns.amazonaws.com" && aws_lambda_permission.notifier[0].source_arn == aws_sns_topic.incidents.arn
    error_message = "Only the incidents topic may invoke the notifier."
  }
  assert {
    condition     = length(aws_lambda_function.playbook) == 4 && !contains(keys(aws_lambda_function.playbook), "soar-notifier")
    error_message = "The notifier is not a playbook: it must not get the playbook roles or environment."
  }
  assert {
    condition     = aws_cloudwatch_log_group.notifier[0].name == "/aws/lambda/cs-test-soar-notifier" && aws_cloudwatch_log_group.notifier[0].kms_key_id == aws_kms_key.this.arn
    error_message = "The notifier logs go to its own KMS-encrypted group."
  }
  assert {
    condition     = output.notifier_function_name == "cs-test-soar-notifier"
    error_message = "notifier_function_name must be output."
  }
}

run "rejects_bad_chatops_inputs" {
  command = plan

  variables {
    chatops_webhook_param_name = "chatops_webhook"
    chatops_allowed_hosts      = ["https://hooks.slack.com/services"]
  }

  expect_failures = [var.chatops_webhook_param_name, var.chatops_allowed_hosts]
}

run "rejects_empty_or_wildcard_hosts" {
  command = plan

  variables {
    chatops_allowed_hosts = ["*.slack.com"]
  }

  expect_failures = [var.chatops_allowed_hosts]
}
