###############################################################################
# Module: identity — Cognito user pool for the docs-api SPA (TB1, S2)
#
#   * admin-created users only; sign-in by email; TOTP MFA (no SMS)
#   * custom:tenant_id is immutable AND not client-writable (F9): the tenant
#     comes only from the verified ID-token claim (F8, decision D5)
#   * four RBAC groups, enforced by the API from cognito:groups (no IAM roles)
#   * SPA client: SRP + refresh only, no secret, no OAuth / hosted UI (D5)
#
# Always on in dev (decision D6): idle cost is zero on the Essentials tier.
# Schema changes REPLACE the pool (and lose every user): the schema is frozen
# in tests/identity.tftest.hcl.
###############################################################################

data "aws_region" "current" {}

locals {
  region = data.aws_region.current.region

  groups = {
    "secops-analyst" = { precedence = 5, description = "SOC dashboard: incidents and audit trail (plan §8.8)." }
    "admin"          = { precedence = 10, description = "Tenant administrator: manage documents and members." }
    "member"         = { precedence = 20, description = "Tenant member: read and write own tenant's documents." }
    "auditor"        = { precedence = 30, description = "Read-only, including the tenant audit trail." }
  }
}

resource "aws_cognito_user_pool" "this" {
  name                = "${var.name}-users"
  user_pool_tier      = var.user_pool_tier
  deletion_protection = var.deletion_protection ? "ACTIVE" : "INACTIVE"

  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  username_configuration {
    case_sensitive = false
  }

  # A changed email stays unverified (and unusable for recovery) until the
  # user confirms the code sent to the new address.
  user_attribute_update_settings {
    attributes_require_verification_before_update = ["email"]
  }

  # TOTP only: there is deliberately no sms_configuration block.
  mfa_configuration = var.mfa_configuration
  software_token_mfa_configuration {
    enabled = true
  }

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  password_policy {
    minimum_length                   = 14
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 1
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  schema {
    name                     = "tenant_id"
    attribute_data_type      = "String"
    mutable                  = false
    required                 = false
    developer_only_attribute = false

    string_attribute_constraints {
      min_length = 1
      max_length = 64
    }
  }

  user_pool_add_ons {
    advanced_security_mode = var.threat_protection_mode
  }

  tags = var.tags
}

resource "aws_cognito_user_pool_client" "spa" {
  name         = "${var.name}-spa"
  user_pool_id = aws_cognito_user_pool.this.id

  # Public SPA client: a secret could not be kept in the browser anyway.
  generate_secret = false

  explicit_auth_flows           = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
  prevent_user_existence_errors = "ENABLED"
  enable_token_revocation       = true

  access_token_validity  = var.access_token_minutes
  id_token_validity      = var.access_token_minutes
  refresh_token_validity = var.refresh_token_days
  auth_session_validity  = 3

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }

  read_attributes = ["email", "email_verified", "custom:tenant_id"]
  # custom:tenant_id is NOT writable: a user must never move themselves to
  # another tenant (F9).
  write_attributes = ["email"]

  # No OAuth flows / hosted UI in Phase D (decision D5).
  allowed_oauth_flows_user_pool_client = false
  supported_identity_providers         = ["COGNITO"]
}

resource "aws_cognito_user_group" "this" {
  for_each     = local.groups
  name         = each.key
  user_pool_id = aws_cognito_user_pool.this.id
  precedence   = each.value.precedence
  description  = each.value.description
}
