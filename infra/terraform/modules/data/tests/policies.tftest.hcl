# IAM and bucket-policy CONTENT tests (Phase E §9). data.tftest.hcl mocks the
# provider, which also mocks every aws_iam_policy_document, so it can never
# see what a policy says. Here the REAL provider renders the documents
# locally (they make no API calls); identity lookups and every managed
# resource are overridden, so no credentials are needed and nothing touches
# an account. A new managed resource without an override below fails this
# test with an auth error, never by calling AWS.
#
# Mutation check (run by hand when this file changes): widen DocumentObjects
# back to "${bucket}/*" in main.tf and confirm "app_document_objects_only_under_tenants"
# fails.

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
  target = data.aws_partition.current
  values = { partition = "aws" }
}

override_resource {
  target = aws_kms_key.this
  values = { arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000", key_id = "00000000-0000-0000-0000-000000000000" }
}
override_resource {
  target = aws_kms_alias.this
  values = {}
}
override_resource {
  target = aws_dynamodb_table.documents
  values = { arn = "arn:aws:dynamodb:us-east-1:123456789012:table/cs-test-documents" }
}
override_resource {
  target = aws_dynamodb_table.audit
  values = { arn = "arn:aws:dynamodb:us-east-1:123456789012:table/cs-test-audit" }
}
override_resource {
  target = aws_s3_bucket.documents
  values = { arn = "arn:aws:s3:::cs-test-documents-123456789012", id = "cs-test-documents-123456789012", bucket = "cs-test-documents-123456789012" }
}
override_resource {
  target = aws_s3_bucket_versioning.documents
  values = {}
}
override_resource {
  target = aws_s3_bucket_server_side_encryption_configuration.documents
  values = {}
}
override_resource {
  target = aws_s3_bucket_public_access_block.documents
  values = {}
}
override_resource {
  target = aws_s3_bucket_ownership_controls.documents
  values = {}
}
override_resource {
  target = aws_s3_bucket_lifecycle_configuration.documents
  values = {}
}
override_resource {
  target = aws_s3_bucket_policy.documents
  values = {}
}
override_resource {
  target = aws_iam_role_policy.app
  values = {}
}

variables {
  name               = "cs-test"
  app_task_role_name = "cs-test-app-task"
}

run "app_document_objects_only_under_tenants" {
  command = apply

  assert {
    condition = one([
      for s in jsondecode(data.aws_iam_policy_document.app.json).Statement : s
      if s.Sid == "DocumentObjects"
      ]).Resource == "arn:aws:s3:::cs-test-documents-123456789012/tenants/*" && jsonencode(sort(flatten([one([
        for s in jsondecode(data.aws_iam_policy_document.app.json).Statement : s
        if s.Sid == "DocumentObjects"
    ]).Action]))) == jsonencode(["s3:DeleteObject", "s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"])
    error_message = "Document objects: exactly Get/GetVersion/Put/DeleteObject, only under tenants/* (Phase E F6, D8)."
  }
  assert {
    condition = alltrue(flatten([
      for s in jsondecode(data.aws_iam_policy_document.app.json).Statement : [
        for r in flatten([s.Resource]) : r != "arn:aws:s3:::cs-test-documents-123456789012/*" && r != "*"
      ]
    ]))
    error_message = "No statement may cover the whole documents bucket or every resource."
  }
}

run "audit_table_is_put_only_for_writes" {
  command = apply

  assert {
    condition = jsonencode(sort(distinct(flatten([
      for s in jsondecode(data.aws_iam_policy_document.app.json).Statement : flatten([s.Action])
      if contains(flatten([s.Resource]), "arn:aws:dynamodb:us-east-1:123456789012:table/cs-test-audit")
    ])))) == jsonencode(["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"])
    error_message = "The audit table gets PutItem (writes) plus Query/GetItem (reads): never UpdateItem, DeleteItem or BatchWriteItem (D4)."
  }
  assert {
    condition = !anytrue(flatten([
      for s in jsondecode(data.aws_iam_policy_document.app.json).Statement : [
        for a in flatten([s.Action]) : contains(["dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem"], a)
      ] if contains(flatten([s.Resource]), "arn:aws:dynamodb:us-east-1:123456789012:table/cs-test-audit")
    ]))
    error_message = "No Update/Delete on the audit table."
  }
}

run "no_wildcard_actions_and_no_scan" {
  command = apply

  assert {
    condition = !anytrue(flatten([
      for s in jsondecode(data.aws_iam_policy_document.app.json).Statement : [
        for a in flatten([s.Action]) : strcontains(a, "*") || a == "dynamodb:Scan"
      ]
    ]))
    error_message = "No s3:*, dynamodb:* or any wildcard action, and no Scan, in the app data-plane policy."
  }
  assert {
    condition = jsonencode(sort([
      for s in jsondecode(data.aws_iam_policy_document.app.json).Statement : s.Sid
    ])) == jsonencode(["AuditAppendOnly", "AuditRead", "DocumentObjects", "DocumentsTableCrud", "UseDataKey"])
    error_message = "The app policy has exactly its five statements."
  }
}

run "bucket_policy_statements_unchanged" {
  command = apply

  assert {
    condition = jsonencode(sort([
      for s in jsondecode(data.aws_iam_policy_document.documents_bucket.json).Statement : s.Sid
    ])) == jsonencode(["DenyForeignKmsKey", "DenyInsecureTransport", "DenyLongLivedPresignedUrls", "DenyNonKmsEncryptionHeader"])
    error_message = "The documents bucket policy keeps exactly its four Deny statements."
  }
  assert {
    condition = alltrue([
      for s in jsondecode(data.aws_iam_policy_document.documents_bucket.json).Statement : s.Effect == "Deny"
    ])
    error_message = "Every bucket-policy statement is a Deny."
  }
  assert {
    condition = one([
      for s in jsondecode(data.aws_iam_policy_document.documents_bucket.json).Statement : s
      if s.Sid == "DenyForeignKmsKey"
    ]).Condition.StringNotEquals["s3:x-amz-server-side-encryption-aws-kms-key-id"] == "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    error_message = "DenyForeignKmsKey compares against this module's CMK ARN (the app sends exactly DATA_KMS_KEY_ARN)."
  }
  assert {
    condition = one([
      for s in jsondecode(data.aws_iam_policy_document.documents_bucket.json).Statement : s
      if s.Sid == "DenyLongLivedPresignedUrls"
    ]).Condition.NumericGreaterThan["s3:signatureAge"] == "300000"
    error_message = "Pre-signed URL age is capped at presigned_url_max_seconds (default 300 s)."
  }
}
