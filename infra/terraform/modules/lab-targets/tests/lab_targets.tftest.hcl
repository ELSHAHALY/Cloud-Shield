# terraform test — offline, mocked AWS provider.

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
  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }
  mock_resource "aws_s3_bucket" {
    defaults = {
      arn = "arn:aws:s3:::mock"
    }
  }
}

variables {
  name                     = "cs-test"
  soar_scope_tag           = { "cloudshield:soar-scope" = "in-scope" }
  soar_target_boundary_arn = "arn:aws:iam::123456789012:policy/cs-test-soar-target-boundary"
}

run "targets_are_in_scope_and_safe_at_rest" {
  command = apply

  assert {
    condition     = aws_iam_user.honeytoken.permissions_boundary == var.soar_target_boundary_arn
    error_message = "The honeytoken must carry the SOAR target boundary, or PB-02 can't revoke its sessions (audit A2)."
  }
  assert {
    condition     = aws_iam_user.honeytoken.tags["cloudshield:soar-scope"] == "in-scope" && aws_s3_bucket.lab.tags["cloudshield:soar-scope"] == "in-scope"
    error_message = "Both lab targets must carry the SOAR scope tag."
  }
  assert {
    condition     = startswith(aws_s3_bucket.lab.bucket, "cs-test-")
    error_message = "The lab bucket must sit inside the SOAR bucket-name prefix (PB-03's IAM boundary, gap 12)."
  }
  assert {
    condition     = aws_s3_bucket_public_access_block.lab.block_public_acls && aws_s3_bucket_public_access_block.lab.ignore_public_acls && aws_s3_bucket_public_access_block.lab.block_public_policy && aws_s3_bucket_public_access_block.lab.restrict_public_buckets
    error_message = "Block Public Access is ON at rest; only the simulation flips it, briefly."
  }
}
