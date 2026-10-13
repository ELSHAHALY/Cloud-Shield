# terraform test — offline, mocked AWS provider.

mock_provider "aws" {}

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
