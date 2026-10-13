# terraform test — offline, mocked AWS provider.

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
  mock_resource "aws_dynamodb_table" {
    defaults = {
      arn = "arn:aws:dynamodb:us-east-1:123456789012:table/mock"
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
}

variables {
  name               = "cs-test"
  app_task_role_name = "cs-test-app-task"
}

run "data_plane_baseline" {
  command = apply

  assert {
    condition     = aws_dynamodb_table.documents.point_in_time_recovery[0].enabled && aws_dynamodb_table.audit.point_in_time_recovery[0].enabled
    error_message = "Both tables need PITR (plan §3.3)."
  }
  assert {
    condition     = aws_dynamodb_table.documents.hash_key == "tenantId" && aws_dynamodb_table.audit.hash_key == "tenantId"
    error_message = "Every table must be partitioned by tenant."
  }
  assert {
    condition     = aws_s3_bucket_public_access_block.documents.block_public_policy && aws_s3_bucket_public_access_block.documents.restrict_public_buckets
    error_message = "Documents bucket must block public access."
  }
  assert {
    condition     = aws_s3_bucket_versioning.documents.versioning_configuration[0].status == "Enabled"
    error_message = "Documents bucket must be versioned."
  }
}

run "rejects_long_presigned_urls" {
  command = plan

  variables {
    presigned_url_max_seconds = 86400
  }

  expect_failures = [var.presigned_url_max_seconds]
}
