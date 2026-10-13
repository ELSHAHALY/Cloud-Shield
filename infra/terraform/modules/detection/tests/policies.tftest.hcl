# Policy-content tests (audit A5). The mock provider in detection.tftest.hcl
# renders every aws_iam_policy_document as empty, so it can't see the Config
# role / trust / Athena key policies. Here the REAL provider renders them
# locally (no API calls); only identity lookups are overridden, plan-only.

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
  target          = data.aws_caller_identity.current
  override_during = plan
  values          = { account_id = "123456789012" }
}
override_data {
  target          = data.aws_region.current
  override_during = plan
  values          = { region = "us-east-1" }
}
override_data {
  target          = data.aws_partition.current
  override_during = plan
  values          = { partition = "aws" }
}

variables {
  name                    = "cs-test"
  log_archive_bucket_name = "cs-test-log-archive-123456789012-us-east-1"
  log_archive_bucket_arn  = "arn:aws:s3:::cs-test-log-archive-123456789012-us-east-1"
  log_archive_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111"
  cloudtrail_trail_name   = "cs-test-trail"
}

run "config_trust_is_scoped_to_this_account" {
  command = plan

  assert {
    condition     = one(jsondecode(data.aws_iam_policy_document.config_trust.json).Statement).Principal.Service == "config.amazonaws.com"
    error_message = "Only AWS Config may assume the recorder role."
  }
  assert {
    condition     = one(jsondecode(data.aws_iam_policy_document.config_trust.json).Statement).Condition.StringEquals["aws:SourceAccount"] == "123456789012"
    error_message = "The Config trust must be scoped to this account (confused deputy)."
  }
}

run "config_delivery_role_is_least_privilege" {
  command = plan

  # Deliver only under this account's config/ prefix.
  assert {
    condition = one([
      for s in jsondecode(data.aws_iam_policy_document.config_delivery.json).Statement : s.Resource
      if contains(flatten([s.Action]), "s3:PutObject")
    ]) == "arn:aws:s3:::cs-test-log-archive-123456789012-us-east-1/config/AWSLogs/123456789012/Config/*"
    error_message = "Config may write only under its own prefix in the log archive."
  }
  # KMS use is limited to the log-archive key.
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.config_delivery.json).Statement :
      s.Resource == var.log_archive_kms_key_arn
      if length(setintersection(toset(flatten([s.Action])), toset(["kms:GenerateDataKey", "kms:Decrypt"]))) > 0
    ])
    error_message = "Config KMS access must be limited to the log-archive key."
  }
  # No wildcard actions anywhere in the delivery role.
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.config_delivery.json).Statement :
      !contains(flatten([s.Action]), "*") && !contains(flatten([s.Action]), "s3:*")
    ])
    error_message = "The Config delivery role must not grant wildcard actions."
  }
}

run "athena_key_policy_is_account_scoped" {
  command = plan

  assert {
    condition     = one(jsondecode(data.aws_iam_policy_document.athena_kms.json).Statement).Principal.AWS == "arn:aws:iam::123456789012:root"
    error_message = "The Athena results key must delegate only to this account's IAM."
  }
}
