output "kms_key_arn" {
  value = aws_kms_key.this.arn
}

output "documents_table_name" {
  value = aws_dynamodb_table.documents.name
}

output "documents_table_arn" {
  value = aws_dynamodb_table.documents.arn
}

output "audit_table_name" {
  value = aws_dynamodb_table.audit.name
}

output "audit_table_arn" {
  value = aws_dynamodb_table.audit.arn
}

output "documents_bucket_name" {
  value = aws_s3_bucket.documents.bucket
}

output "documents_bucket_arn" {
  value = aws_s3_bucket.documents.arn
}

output "app_environment" {
  description = "Feed straight into modules/compute container_environment."
  value = {
    DOCUMENTS_TABLE           = aws_dynamodb_table.documents.name
    AUDIT_TABLE               = aws_dynamodb_table.audit.name
    DOCUMENTS_BUCKET          = aws_s3_bucket.documents.bucket
    DATA_KMS_KEY_ARN          = aws_kms_key.this.arn
    PRESIGNED_URL_MAX_SECONDS = tostring(var.presigned_url_max_seconds)
  }
}
