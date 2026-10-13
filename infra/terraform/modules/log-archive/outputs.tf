# Consumers (flow logs, trail, Config, GuardDuty export) start delivering as
# soon as they exist; depending on the policies prevents a first delivery
# before the bucket and key policies allow it.
output "bucket_name" {
  value      = aws_s3_bucket.this.bucket
  depends_on = [aws_s3_bucket_policy.this, aws_kms_key.this]
}

output "bucket_arn" {
  value      = aws_s3_bucket.this.arn
  depends_on = [aws_s3_bucket_policy.this, aws_kms_key.this]
}

output "kms_key_arn" {
  value = aws_kms_key.this.arn
}

output "flow_logs_destination_arn" {
  description = "Pass to modules/network. The prefix must match the AWSLogDeliveryWrite statement."
  value       = "${aws_s3_bucket.this.arn}/vpc-flow-logs/"
  depends_on  = [aws_s3_bucket_policy.this, aws_kms_key.this]
}
