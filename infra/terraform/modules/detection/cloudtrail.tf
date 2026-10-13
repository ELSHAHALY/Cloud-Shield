###############################################################################
# CloudTrail — the timeline source for every hunt query (FR-8).
#   * management events, all regions (global-service events land in us-east-1)
#   * S3 DATA events for exactly var.data_event_bucket_arns: who read or wrote
#     evidence / documents objects. This is the compensating control for the
#     missing server access logs (handoff gap 16).
# Delivered to the log archive under cloudtrail/, encrypted with its CMK; the
# bucket and key statements that allow it are in modules/log-archive.
###############################################################################

resource "aws_cloudtrail" "this" {
  #checkov:skip=CKV_AWS_252:No SNS per log file: findings come from GuardDuty/EventBridge, and Athena reads the files directly
  #checkov:skip=CKV2_AWS_10:No CloudWatch Logs copy: Athena over S3 is the analysis path (plan §6.1); a second copy doubles ingestion cost
  count = var.enable_cloudtrail ? 1 : 0
  name  = var.cloudtrail_trail_name

  s3_bucket_name = var.log_archive_bucket_name
  s3_key_prefix  = "cloudtrail"
  kms_key_id     = var.log_archive_kms_key_arn

  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true # digest files: tamper evidence for the timeline

  advanced_event_selector {
    name = "Management events"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  dynamic "advanced_event_selector" {
    for_each = length(var.data_event_bucket_arns) > 0 ? [1] : []
    content {
      name = "S3 data events on sensitive buckets"
      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }
      field_selector {
        field  = "resources.type"
        equals = ["AWS::S3::Object"]
      }
      # Trailing "/" so cloudshield-dev-docs never matches cloudshield-dev-docs-old.
      field_selector {
        field       = "resources.ARN"
        starts_with = [for arn in var.data_event_bucket_arns : "${arn}/"]
      }
    }
  }

  tags = var.tags
}
