# terraform test — offline, mocked AWS provider (no credentials).
# Freezes the user-pool contract: a schema change replaces the pool and
# deletes every user, so it must fail here first.

mock_provider "aws" {
  mock_data "aws_region" {
    defaults = {
      region = "us-east-1"
    }
  }
  mock_resource "aws_cognito_user_pool" {
    defaults = {
      id  = "us-east-1_AbCdEfGhI"
      arn = "arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_AbCdEfGhI"
    }
  }
}

variables {
  name = "cs-test"
}

run "defaults_are_secure" {
  command = apply

  assert {
    condition     = aws_cognito_user_pool.this.mfa_configuration == "ON"
    error_message = "MFA must be ON by default."
  }
  assert {
    condition     = aws_cognito_user_pool.this.software_token_mfa_configuration[0].enabled
    error_message = "TOTP MFA must be enabled."
  }
  assert {
    condition     = length(aws_cognito_user_pool.this.sms_configuration) == 0
    error_message = "No SMS configuration (TOTP only)."
  }
  assert {
    condition     = aws_cognito_user_pool.this.admin_create_user_config[0].allow_admin_create_user_only
    error_message = "Self sign-up must be disabled (admin-created users only)."
  }
  assert {
    condition = (
      aws_cognito_user_pool.this.password_policy[0].minimum_length >= 14 &&
      aws_cognito_user_pool.this.password_policy[0].require_lowercase &&
      aws_cognito_user_pool.this.password_policy[0].require_uppercase &&
      aws_cognito_user_pool.this.password_policy[0].require_numbers &&
      aws_cognito_user_pool.this.password_policy[0].require_symbols &&
      aws_cognito_user_pool.this.password_policy[0].temporary_password_validity_days == 1
    )
    error_message = "Password policy: >= 14 characters, all four classes, temporary password valid 1 day."
  }
  assert {
    condition     = [for m in aws_cognito_user_pool.this.account_recovery_setting[0].recovery_mechanism : m.name] == ["verified_email"]
    error_message = "Account recovery by verified email only."
  }
  assert {
    condition     = aws_cognito_user_pool.this.username_attributes == toset(["email"]) && aws_cognito_user_pool.this.username_configuration[0].case_sensitive == false
    error_message = "Sign-in by email, case-insensitive."
  }
  assert {
    condition     = aws_cognito_user_pool.this.user_pool_tier == "ESSENTIALS" && aws_cognito_user_pool.this.user_pool_add_ons[0].advanced_security_mode == "OFF"
    error_message = "Essentials tier with threat protection off by default (F15)."
  }
}

run "tenant_attribute_is_frozen" {
  command = apply

  assert {
    condition = [
      for a in aws_cognito_user_pool.this.schema : {
        type     = a.attribute_data_type
        mutable  = a.mutable
        required = a.required
        min      = a.string_attribute_constraints[0].min_length
        max      = a.string_attribute_constraints[0].max_length
      } if a.name == "tenant_id"
      ] == [{
        type     = "String"
        mutable  = false
        required = false
        min      = "1"
        max      = "64"
    }]
    error_message = "custom:tenant_id must be an immutable String of length 1-64 (F9)."
  }
  assert {
    condition     = length(aws_cognito_user_pool.this.schema) == 1
    error_message = "Schema changes replace the pool: exactly one custom attribute."
  }
}

run "spa_client_contract" {
  command = apply

  assert {
    condition     = aws_cognito_user_pool_client.spa.generate_secret == false
    error_message = "Public SPA client: no secret."
  }
  assert {
    condition     = aws_cognito_user_pool_client.spa.explicit_auth_flows == toset(["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"])
    error_message = "Auth flows must be exactly SRP + refresh."
  }
  assert {
    condition     = !contains(aws_cognito_user_pool_client.spa.write_attributes, "custom:tenant_id") && aws_cognito_user_pool_client.spa.write_attributes == toset(["email"])
    error_message = "Users must not be able to write custom:tenant_id (F9)."
  }
  assert {
    condition     = contains(aws_cognito_user_pool_client.spa.read_attributes, "custom:tenant_id")
    error_message = "The tenant claim must be readable (it reaches the ID token)."
  }
  assert {
    condition     = aws_cognito_user_pool_client.spa.prevent_user_existence_errors == "ENABLED"
    error_message = "User-existence errors must be prevented (no account enumeration)."
  }
  assert {
    condition     = aws_cognito_user_pool_client.spa.enable_token_revocation
    error_message = "Token revocation must be on."
  }
  assert {
    condition     = aws_cognito_user_pool_client.spa.allowed_oauth_flows_user_pool_client == false && length(coalesce(aws_cognito_user_pool_client.spa.allowed_oauth_flows, [])) == 0
    error_message = "No OAuth flows in Phase D (D5)."
  }
  assert {
    condition     = aws_cognito_user_pool_client.spa.access_token_validity == 60 && aws_cognito_user_pool_client.spa.id_token_validity == 60 && aws_cognito_user_pool_client.spa.refresh_token_validity == 1 && aws_cognito_user_pool_client.spa.auth_session_validity == 3
    error_message = "Token lifetimes: 60 min access/ID, 1 d refresh, 3 min auth session."
  }
}

run "groups_are_exactly_the_four_roles" {
  command = apply

  assert {
    condition     = toset(keys(aws_cognito_user_group.this)) == toset(["admin", "member", "auditor", "secops-analyst"])
    error_message = "Groups must be exactly admin, member, auditor, secops-analyst."
  }
  assert {
    condition = { for k, g in aws_cognito_user_group.this : k => g.precedence } == {
      "secops-analyst" = 5
      "admin"          = 10
      "member"         = 20
      "auditor"        = 30
    }
    error_message = "Group precedences are fixed (secops-analyst 5, admin 10, member 20, auditor 30)."
  }
  assert {
    condition     = alltrue([for g in aws_cognito_user_group.this : g.role_arn == null])
    error_message = "No IAM roles on groups: RBAC is enforced in the API."
  }
  assert {
    condition     = output.app_environment.COGNITO_ISSUER == "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI"
    error_message = "Issuer must be the regional cognito-idp URL of this pool."
  }
}

run "mfa_optional_is_accepted" {
  command = plan

  variables {
    mfa_configuration = "OPTIONAL"
  }

  assert {
    condition     = aws_cognito_user_pool.this.mfa_configuration == "OPTIONAL"
    error_message = "OPTIONAL MFA must be accepted."
  }
}

run "mfa_off_is_rejected" {
  command = plan

  variables {
    mfa_configuration = "OFF"
  }

  expect_failures = [var.mfa_configuration]
}

run "threat_protection_requires_plus" {
  command = plan

  variables {
    threat_protection_mode = "ENFORCED"
  }

  expect_failures = [var.threat_protection_mode]
}

run "threat_protection_with_plus_is_accepted" {
  command = plan

  variables {
    user_pool_tier         = "PLUS"
    threat_protection_mode = "ENFORCED"
  }

  assert {
    condition     = aws_cognito_user_pool.this.user_pool_add_ons[0].advanced_security_mode == "ENFORCED"
    error_message = "ENFORCED threat protection must be accepted on PLUS."
  }
}
