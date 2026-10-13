# Repo admin setup (S1 · @ELSHAHALY)

One-time GitHub settings for `ELSHAHALY/Cloud-Shield`. Every command needs repo **admin**, so only @ELSHAHALY can run them. Requires the GitHub CLI: `gh auth login` first.

```bash
REPO=ELSHAHALY/Cloud-Shield
```

## 1. Collaborators (Write access)

```bash
gh api -X PUT "repos/$REPO/collaborators/YasseenAbdelghany" -f permission=push
gh api -X PUT "repos/$REPO/collaborators/ahklsfg" -f permission=push
```

Each person must accept the emailed invitation. Check with:

```bash
gh api "repos/$REPO/collaborators" --jq '.[] | [.login, .role_name] | @tsv'
```

## 2. Repository variables

Run after `infra/terraform/bootstrap` is applied. The values come from its outputs.

```bash
cd infra/terraform/bootstrap
gh variable set AWS_PLAN_ROLE_ARN    --repo "$REPO" --body "$(terraform output -raw gha_plan_role_arn)"
gh variable set TF_STATE_BUCKET      --repo "$REPO" --body "$(terraform output -raw state_bucket)"
gh variable set TF_STATE_KMS_KEY_ARN --repo "$REPO" --body "$(terraform output -raw state_kms_key_arn)"
gh variable set AWS_REGION           --repo "$REPO" --body "us-east-1"
gh variable list --repo "$REPO"
```

Set these later, not now:

| Variable | When |
|---|---|
| `ENFORCE_GATES=true` | Only after `scripts/gate-selftest.sh all` shows ✓ for every gate. Until then the gates are fail-open. |
| `STAGING_URL` | Once the app is deployed. Turns on the ZAP gate. |
| `APP_DIR` | Only if the app is not at `app/docs-api`. |

## 3. Branch protection on `main`

The required checks are the CI **job names** exactly as they appear in `.github/workflows/ci.yml`. DAST is left out because it is skipped on pull requests, and a required check that never runs blocks every merge.

```bash
cat > /tmp/protection.json <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      { "context": "gate: secrets (gitleaks)" },
      { "context": "gate: sast (semgrep)" },
      { "context": "gate: sca (trivy fs)" },
      { "context": "gate: iac (terraform + checkov)" },
      { "context": "gate: image (trivy image + sbom)" }
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 2,
    "require_code_owner_reviews": true,
    "dismiss_stale_reviews": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
JSON
gh api -X PUT "repos/$REPO/branches/main/protection" --input /tmp/protection.json
gh api "repos/$REPO/branches/main/protection" --jq '.required_status_checks.checks[].context'
```

Notes:

- With 3 people and 2 required approvals, every PR needs **both** other team members to approve. That is the intended two-person review (handoff §2.5, M7).
- `enforce_admins: true` means @ELSHAHALY can no longer push straight to `main` either. Set it to `false` only if the team agrees.
- When a new CI job becomes a gate (for example the SOAR unit-test job), add its name to `checks` and re-run the `PUT`.
