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
| `IMAGE_CONTEXT` | Only if the docs-api build context is not `app` (Phase E D2: the contract and `app/grc` must be inside the context). |
| `AWS_ECR_PUSH_ROLE_ARN` | After `environments/dev` is applied with `github_oidc_provider_arn` set (bootstrap output). Turns on the "Push scanned image (main only)" step of the image gate. |
| `ECR_REPOSITORY` | Same time as `AWS_ECR_PUSH_ROLE_ARN`: the full repository URL the push step tags and pushes to. |

The two ECR variables come from the dev outputs:

```bash
cd infra/terraform/bootstrap
OIDC_ARN="$(terraform output -raw github_oidc_provider_arn)"
cd ../environments/dev
terraform apply -var "github_oidc_provider_arn=$OIDC_ARN"   # S1, locally (there is no CI apply role)
gh variable set AWS_ECR_PUSH_ROLE_ARN --repo "$REPO" --body "$(terraform output -raw ecr_push_role_arn)"
gh variable set ECR_REPOSITORY        --repo "$REPO" --body "$(terraform output -raw ecr_repository_url)"
```

CI only pushes, on `main`, an image that passed **every** gate: the push step requires this job's Trivy image scan **and** the secrets, SAST and SCA scans to have really succeeded, **and** (Phase E) the `app` gate (lint, typecheck, tests, build) (each gate job exports its scan step's outcome, so a fail-open finding still blocks the push). It never deploys. Deploying stays a local apply with `container_image` set to the digest shown in the job summary.

### 2b. Optional (S1): bind the OIDC subject to the workflow file

Today the ECR push role trusts `sub = repo:ELSHAHALY/Cloud-Shield:ref:refs/heads/main` exactly. Any workflow file on `main` can mint that token, not just `ci.yml`. GitHub can add the calling workflow to the subject claim:

```bash
gh api -X PUT "repos/$REPO/actions/oidc/customization/sub" \
  --input - <<'JSON'
{ "use_default": false, "include_claim_keys": ["repo", "context", "job_workflow_ref"] }
JSON
gh api "repos/$REPO/actions/oidc/customization/sub"   # check
```

After that the push token's subject becomes `repo:ELSHAHALY/Cloud-Shield:ref:refs/heads/main:job_workflow_ref:ELSHAHALY/Cloud-Shield/.github/workflows/ci.yml@refs/heads/main` [inferred from GitHub's OIDC docs: check the `sub` of one real token before relying on it].

**Do not run this on its own.** The customization applies to every token the repository mints, so in the same change:

- the ECR push role's `sub` (`modules/compute/ci-push.tf`, `local.ci_push_subject`) must become the new value, and
- the plan role's `sub` patterns (`bootstrap/main.tf`: `...:pull_request` and `...:ref:refs/heads/main`) must be rewritten to the new format,

otherwise both roles stop being assumable. The trust policies stay in the current shape until this step is actually applied; it is a tracked follow-up (audit A9), not done in Phase D. Undo with `{"use_default": true}`.

## 3. Branch protection on `main`

> **Timing (Phase F):** apply this only after PRs #1–#4 and the Phase F PR are merged, as the last step of [final-merge-and-cutover.md](final-merge-and-cutover.md) §4. Earlier, the stacked PRs cannot satisfy it (#1–#3 have no `gate: app` job).

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
      { "context": "gate: soar (ruff + pytest)" },
      { "context": "gate: app (lint + typecheck + test + build)" },
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
- When a new CI job becomes a gate, add its name to `checks` and re-run the `PUT`. (`gate: soar` was added in Phase F.)
