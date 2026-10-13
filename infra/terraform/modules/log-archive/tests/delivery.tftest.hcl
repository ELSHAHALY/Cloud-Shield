# Delivery-policy content tests. The REAL provider renders the policy
# documents locally; every managed resource is overridden, so `apply` never
# calls AWS and no credentials are needed (pattern: modules/soar/tests/iam.tftest.hcl).

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

override_resource {
  target = aws_s3_bucket.this
  values = { arn = "arn:aws:s3:::cs-test-log-archive-123456789012-us-east-1", bucket = "cs-test-log-archive-123456789012-us-east-1" }
}
override_resource {
  target = aws_kms_key.this
  values = { arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000" }
}
override_resource {
  target = aws_kms_alias.this
}
override_resource {
  target = aws_s3_bucket_object_lock_configuration.this
}
override_resource {
  target = aws_s3_bucket_versioning.this
}
override_resource {
  target = aws_s3_bucket_server_side_encryption_configuration.this
}
override_resource {
  target = aws_s3_bucket_public_access_block.this
}
override_resource {
  target = aws_s3_bucket_ownership_controls.this
}
override_resource {
  target = aws_s3_bucket_lifecycle_configuration.this
}
override_resource {
  target = aws_s3_bucket_policy.this
}

variables {
  name = "cs-test"
}

run "flow_logs_only_by_default" {
  command = apply

  assert {
    condition = toset([for s in jsondecode(data.aws_iam_policy_document.bucket_delivery.json).Statement : s.Sid]) == toset([
      "DenyInsecureTransport", "AWSLogDeliveryAclCheck", "AWSLogDeliveryWrite",
    ])
    error_message = "Without detection, only VPC Flow Logs may deliver."
  }
}

run "each_service_writes_only_under_its_prefix" {
  command = apply

  variables {
    cloudtrail_trail_name   = "cs-test-trail"
    enable_config_delivery  = true
    enable_guardduty_export = true
  }

  assert {
    condition = { for s in jsondecode(data.aws_iam_policy_document.bucket_delivery.json).Statement : s.Sid => s.Resource if s.Action == "s3:PutObject" } == {
      AWSLogDeliveryWrite     = "arn:aws:s3:::cs-test-log-archive-123456789012-us-east-1/vpc-flow-logs/AWSLogs/*"
      AWSCloudTrailWrite      = "arn:aws:s3:::cs-test-log-archive-123456789012-us-east-1/cloudtrail/AWSLogs/123456789012/*"
      AWSConfigBucketDelivery = "arn:aws:s3:::cs-test-log-archive-123456789012-us-east-1/config/AWSLogs/123456789012/Config/*"
      AllowGuardDutyPutObject = "arn:aws:s3:::cs-test-log-archive-123456789012-us-east-1/guardduty/*"
    }
    error_message = "Each delivering service may write only under its own prefix."
  }
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.bucket_delivery.json).Statement :
      try(s.Condition.StringEquals["aws:SourceArn"], "") == "arn:aws:cloudtrail:us-east-1:123456789012:trail/cs-test-trail"
      if startswith(s.Sid, "AWSCloudTrail")
    ])
    error_message = "CloudTrail statements must be scoped to this trail's ARN (confused deputy)."
  }
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.bucket_delivery.json).Statement :
      try(s.Condition.StringEquals["aws:SourceAccount"], "") == "123456789012"
      if startswith(s.Sid, "AWSConfig") || startswith(s.Sid, "AllowGuardDuty")
    ])
    error_message = "Config and GuardDuty statements must be scoped to this account."
  }
  assert {
    condition = one([
      for s in jsondecode(data.aws_iam_policy_document.kms_delivery.json).Statement : s
      if s.Sid == "AllowCloudTrailEncrypt"
    ]).Condition.StringLike["kms:EncryptionContext:aws:cloudtrail:arn"] == "arn:aws:cloudtrail:*:123456789012:trail/*"
    error_message = "CloudTrail may use the key only with this account's trail encryption context."
  }
}
