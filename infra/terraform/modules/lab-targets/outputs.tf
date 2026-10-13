output "honeytoken_user_name" {
  value = aws_iam_user.honeytoken.name
}

output "honeytoken_user_arn" {
  value = aws_iam_user.honeytoken.arn
}

output "lab_bucket_name" {
  value = aws_s3_bucket.lab.bucket
}

output "lab_bucket_arn" {
  value = aws_s3_bucket.lab.arn
}
