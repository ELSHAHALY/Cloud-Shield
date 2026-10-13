output "bucket_name" {
  value = aws_s3_bucket.this.bucket
}

output "bucket_arn" {
  value = aws_s3_bucket.this.arn
}

output "kms_key_arn" {
  value = aws_kms_key.this.arn
}

output "flow_logs_destination_arn" {
  description = "Pass to modules/network. The prefix must match the AWSLogDeliveryWrite statement."
  value       = "${aws_s3_bucket.this.arn}/vpc-flow-logs/"
}
