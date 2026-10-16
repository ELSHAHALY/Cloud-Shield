output "user_pool_id" {
  value = aws_cognito_user_pool.this.id
}

output "user_pool_arn" {
  description = "modules/edge: the REST API Cognito authorizer."
  value       = aws_cognito_user_pool.this.arn
}

output "user_pool_client_id" {
  description = "The SPA client (public, no secret). The app checks it as the ID token's aud."
  value       = aws_cognito_user_pool_client.spa.id
}

output "issuer_url" {
  description = "Expected iss of every token the API accepts."
  value       = "https://cognito-idp.${local.region}.amazonaws.com/${aws_cognito_user_pool.this.id}"
}

output "group_names" {
  value = sort(keys(aws_cognito_user_group.this))
}

output "app_environment" {
  description = "Non-secret settings for the docs-api container (merged into modules/compute container_environment)."
  value = {
    COGNITO_USER_POOL_ID = aws_cognito_user_pool.this.id
    COGNITO_CLIENT_ID    = aws_cognito_user_pool_client.spa.id
    COGNITO_ISSUER       = "https://cognito-idp.${local.region}.amazonaws.com/${aws_cognito_user_pool.this.id}"
  }
}
