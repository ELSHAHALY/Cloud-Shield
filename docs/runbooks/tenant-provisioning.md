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

Choose the tenant id carefully: stable, not personal data, and matching the format docs-api enforces (Phase E D7): `^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`, that is 1–64 lowercase letters, digits and inner hyphens (for example `t-acme-01`). Cognito accepts other strings, but the API answers **403 `TENANT_INVALID`** for them (fail closed). Ids starting with `_` are reserved (`_platform`). It can never be changed for this user.

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

## 4. First sign-in: onboarding (Phase E D26)

The tenant's **first** user should be its `admin`. At first sign-in the SPA routes the admin to `/onboarding`:

1. Read the DPA and the SLA (plain text) and tick "I confirm I have authority to bind <tenant> to this agreement", then **Accept**. The API records click-through acceptance (user, time, text SHA-256, source IP, request id). It is evidence of acceptance, not a qualified or advanced electronic signature; the texts are templates.
2. Until every required agreement is accepted, document uploads and changes answer **403 `AGREEMENT_REQUIRED`** for everyone in the tenant (reads still work).
3. Set the tenant's GRC profile (`/grc`): jurisdictions (EG / EU / SA), sector, CBE regulation, data categories. The assessment is informational, not legal advice.

Members and auditors see "Waiting for your tenant administrator to accept…".

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
