# Runbook: provision and deprovision a tenant user (Cognito)

- **Owner:** S2 (@YasseenAbdelghany) · **Relates to:** ADR-0004 (identity), `app/README.md` (token contract)
- **When:** onboarding a customer user, adding a SecOps analyst, or removing access.

Self sign-up is disabled (`allow_admin_create_user_only = true`): every user is created by an administrator with these commands. The tenant is fixed at creation: `custom:tenant_id` is **immutable** and users cannot write it, so the API can trust the claim.

## Before you start

```bash
cd infra/terraform/environments/dev
POOL=$(terraform output -raw cognito_user_pool_id)   # or: module.identity user_pool_id
aws sts get-caller-identity                          # confirm the account first
```

Choose the tenant id carefully: 1–64 characters, stable, not personal data (for example `t-acme-01`). It can never be changed for this user.

## 1. Create the user

```bash
aws cognito-idp admin-create-user \
  --user-pool-id "$POOL" \
  --username "user@example.com" \
  --user-attributes \
      Name=email,Value=user@example.com \
      Name=email_verified,Value=true \
      Name=custom:tenant_id,Value=t-acme-01 \
  --desired-delivery-mediums EMAIL
```

Cognito emails a temporary password, valid for 1 day. At first sign-in the user sets a new password (minimum 14 characters, all four character classes) and enrols a **TOTP** authenticator app: MFA is `ON` and there is no SMS option.

## 2. Assign exactly one role group

| Group | Who | API permissions |
|---|---|---|
| `member` | normal tenant user | own tenant's documents |
| `admin` | tenant administrator | own tenant's documents and users |
| `auditor` | compliance reviewer | read-only, including the tenant's audit trail |
| `secops-analyst` | CloudShield SOC (internal staff only) | the SOC dashboard (plan §8.8) |

```bash
aws cognito-idp admin-add-user-to-group --user-pool-id "$POOL" \
  --username "user@example.com" --group-name member
```

Groups carry no IAM roles; the API enforces them from the verified `cognito:groups` claim. Never put a customer in `secops-analyst`.

## 3. Verify

```bash
aws cognito-idp admin-get-user --user-pool-id "$POOL" --username "user@example.com" \
  --query 'UserAttributes[?Name==`custom:tenant_id`]'
aws cognito-idp admin-list-groups-for-user --user-pool-id "$POOL" --username "user@example.com"
```

## Moving a user to another tenant

Not possible by design. Create a new user with the new tenant id, then deprovision the old one.

## Deprovision (leaver, compromise)

1. Disable the user, then revoke their refresh tokens:

   ```bash
   aws cognito-idp admin-disable-user --user-pool-id "$POOL" --username "user@example.com"
   aws cognito-idp admin-user-global-sign-out --user-pool-id "$POOL" --username "user@example.com"
   ```

2. ID and access tokens already issued stay valid until they expire (at most 60 minutes). If that window matters (a compromised account), also ask S1 to add a temporary block at the edge for the user's source address, or rotate the affected tenant's data access.
3. Keep the disabled user while its audit records are needed. Deleting it (`admin-delete-user`) is permanent and is a separate, deliberate decision by the tenant admin and S2.
