# terraform test — offline, mocked AWS provider (no credentials).

mock_provider "aws" {
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
  mock_resource "aws_kms_key" {
    defaults = {
      arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    }
  }
  mock_resource "aws_s3_bucket" {
    defaults = {
      arn = "arn:aws:s3:::mock"
    }
  }
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/mock"
    }
  }
  mock_resource "aws_cloudtrail" {
    defaults = {
      arn = "arn:aws:cloudtrail:us-east-1:123456789012:trail/mock"
    }
  }
  mock_resource "aws_cloudwatch_event_rule" {
    defaults = {
      arn = "arn:aws:events:us-east-1:123456789012:rule/mock"
    }
  }
}

variables {
  name                    = "cs-test"
  log_archive_bucket_name = "cs-test-log-archive-123456789012-us-east-1"
  log_archive_bucket_arn  = "arn:aws:s3:::cs-test-log-archive-123456789012-us-east-1"
  log_archive_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111"
  cloudtrail_trail_name   = "cs-test-trail"
  data_event_bucket_arns = [
    "arn:aws:s3:::cs-test-soar-evidence-123456789012",
    "arn:aws:s3:::cs-test-documents",
  ]
}

run "defaults_core_on_paid_extras_off" {
  command = apply

  assert {
    condition     = length(aws_guardduty_detector.this) == 1 && length(aws_guardduty_publishing_destination.log_archive) == 1
    error_message = "GuardDuty detector and its findings export are on by default."
  }
  assert {
    condition     = aws_guardduty_detector_feature.toggle["S3_DATA_EVENTS"].status == "DISABLED" && aws_guardduty_detector_feature.toggle["EBS_MALWARE_PROTECTION"].status == "DISABLED" && aws_guardduty_detector_feature.runtime_monitoring[0].status == "DISABLED"
    error_message = "Paid GuardDuty protections must default off (decision D3)."
  }
  assert {
    condition     = length(aws_securityhub_account.this) == 0
    error_message = "Security Hub must default off (decision D3)."
  }
  assert {
    condition     = aws_config_configuration_recorder.this[0].recording_group[0].all_supported == false && aws_config_configuration_recorder.this[0].recording_group[0].resource_types == toset(["AWS::S3::Bucket"])
    error_message = "Config must record S3 buckets only (cost bound)."
  }
  assert {
    condition     = toset([aws_config_config_rule.s3_public_read[0].source[0].source_identifier, aws_config_config_rule.s3_public_write[0].source[0].source_identifier]) == toset(["S3_BUCKET_PUBLIC_READ_PROHIBITED", "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"])
    error_message = "Both S3 public-access managed rules are required."
  }
  assert {
    condition     = length(aws_cloudwatch_event_rule.config_noncompliant) == 0
    error_message = "No Config notification rule unless notify_config_noncompliant."
  }
}

run "athena_cost_cap_and_encryption_are_enforced" {
  command = apply

  assert {
    condition     = aws_athena_workgroup.forensics.name == "cs-test-cs-forensics"
    error_message = "Workgroup is <name>-cs-forensics."
  }
  assert {
    condition     = aws_athena_workgroup.forensics.configuration[0].enforce_workgroup_configuration == true
    error_message = "Workgroup settings must be ENFORCED, or a client can lift the scan cap."
  }
  assert {
    condition     = aws_athena_workgroup.forensics.configuration[0].bytes_scanned_cutoff_per_query == 1073741824
    error_message = "Per-query scan cap must default to 1 GiB (plan §6.1)."
  }
  assert {
    condition     = aws_athena_workgroup.forensics.configuration[0].result_configuration[0].encryption_configuration[0].encryption_option == "SSE_KMS"
    error_message = "Query results (log excerpts) must be KMS-encrypted."
  }
  assert {
    condition     = aws_s3_bucket_public_access_block.athena_results.restrict_public_buckets && aws_s3_bucket_public_access_block.athena_results.block_public_policy
    error_message = "Results bucket must block public access."
  }
}

run "trail_records_data_events_for_exactly_the_given_buckets" {
  command = apply

  assert {
    condition     = aws_cloudtrail.this[0].is_multi_region_trail && aws_cloudtrail.this[0].enable_log_file_validation && aws_cloudtrail.this[0].include_global_service_events
    error_message = "Multi-region, global events and digest validation are required."
  }
  assert {
    condition = toset(flatten([
      for sel in aws_cloudtrail.this[0].advanced_event_selector :
      [for f in sel.field_selector : f.starts_with if f.field == "resources.ARN"]
      if sel.name == "S3 data events on sensitive buckets"
      ])) == toset([
      "arn:aws:s3:::cs-test-soar-evidence-123456789012/",
      "arn:aws:s3:::cs-test-documents/",
    ])
    error_message = "Data events must cover exactly the given buckets, each with a trailing '/' (no prefix collisions)."
  }
  assert {
    condition     = aws_cloudtrail.this[0].s3_key_prefix == "cloudtrail" && aws_cloudtrail.this[0].kms_key_id == var.log_archive_kms_key_arn
    error_message = "Trail delivers under cloudtrail/ with the log-archive CMK (the prefix log-archive's policy allows)."
  }
}

run "catalog_and_saved_queries" {
  command = apply

  assert {
    condition     = aws_glue_catalog_database.forensics.name == "cs_test_forensics"
    error_message = "Glue database names use underscores."
  }
  assert {
    condition     = alltrue([for t in [aws_glue_catalog_table.cloudtrail, aws_glue_catalog_table.vpc_flow_logs, aws_glue_catalog_table.guardduty_findings] : t.parameters["projection.enabled"] == "true"])
    error_message = "Every table uses partition projection (no crawlers, no MSCK REPAIR)."
  }
  assert {
    condition     = strcontains(aws_glue_catalog_table.vpc_flow_logs.parameters["storage.location.template"], "/vpc-flow-logs/AWSLogs/aws-account-id=123456789012/aws-service=vpcflowlogs/aws-region=us-east-1/year=$${year}/month=$${month}/day=$${day}/hour=$${hour}")
    error_message = "Flow-log template must match the Hive layout modules/network writes."
  }
  assert {
    condition     = [for c in aws_glue_catalog_table.vpc_flow_logs.storage_descriptor[0].columns : c.name] == ["version", "account_id", "interface_id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol", "packets", "bytes", "start", "end", "action", "log_status", "vpc_id", "subnet_id", "instance_id", "tcp_flags", "type", "pkt_srcaddr", "pkt_dstaddr", "flow_direction", "traffic_path"]
    error_message = "Flow-log columns must follow modules/network flow_log_format, in order."
  }
  assert {
    condition     = length(aws_athena_named_query.hunt) == length(fileset("${path.module}/../../../../detection/athena-queries", "*.sql")) && length(aws_athena_named_query.hunt) >= 3
    error_message = "Every detection/athena-queries/*.sql must be a saved query (FR-8)."
  }
}

run "security_hub_standards_when_enabled" {
  command = plan

  variables {
    enable_security_hub = true
    securityhub_cis     = true
    securityhub_pci_dss = true
  }

  assert {
    condition     = length(aws_securityhub_standards_subscription.cis) == 1 && length(aws_securityhub_standards_subscription.pci_dss) == 1
    error_message = "CIS and PCI DSS subscriptions follow their flags."
  }
  assert {
    condition     = aws_securityhub_account.this[0].enable_default_standards == false
    error_message = "Only the chosen standards: no default ones."
  }
}

run "existing_detector_is_not_recreated" {
  command = plan

  variables {
    manage_guardduty_detector = false
  }

  assert {
    condition     = length(aws_guardduty_detector.this) == 0 && length(aws_guardduty_publishing_destination.log_archive) == 0 && length(aws_guardduty_detector_feature.toggle) == 0
    error_message = "With manage_guardduty_detector = false nothing GuardDuty-related is created."
  }
}

run "config_notification_when_enabled" {
  command = apply

  variables {
    notify_config_noncompliant = true
    notify_sns_topic_arn       = "arn:aws:sns:us-east-1:123456789012:cs-test-soar-incidents"
  }

  assert {
    condition     = aws_cloudwatch_event_rule.config_noncompliant[0].name == "cs-test-soar-config-noncompliant" && aws_cloudwatch_event_target.config_noncompliant[0].arn == "arn:aws:sns:us-east-1:123456789012:cs-test-soar-incidents"
    error_message = "The rule name must match what modules/soar allows (extra_notify_rule_names)."
  }
  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.config_noncompliant[0].event_pattern).detail.newEvaluationResult.complianceType == ["NON_COMPLIANT"]
    error_message = "Only NON_COMPLIANT results notify."
  }
}

run "rejects_object_arns_in_data_event_list" {
  command = plan

  variables {
    data_event_bucket_arns = ["arn:aws:s3:::cs-test-documents/*"]
  }

  expect_failures = [var.data_event_bucket_arns]
}

run "rejects_scan_cap_below_athena_minimum" {
  command = plan

  variables {
    athena_bytes_scanned_cutoff = 1024
  }

  expect_failures = [var.athena_bytes_scanned_cutoff]
}
