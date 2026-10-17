# Runbook: final merge of the PR stack and cutover to enforced gates

| | |
|---|---|
| **Owner** | S1 @ELSHAHALY (the only repo admin). Reviews by S2 @YasseenAbdelghany and S3 @ahklsfg. |
| **When** | Once, after the Phase F PR is green. Takes about 1–2 h, mostly waiting for CI. |
| **Where** | S1's own machine: `gh` ≥ 2.40 authenticated as @ELSHAHALY, plus a full clone of the repo. `gh pr …` uses GraphQL, which works there. Claude Code sessions are refused GraphQL and the Actions-variables API, so they can only use the REST forms in the [appendix](#appendix-rest-equivalents-for-agent-sessions), and still cannot set `ENFORCE_GATES`. |
| **Decisions** | Phase F plan D8 (merge commits, explicit retarget), D9 (enforce before merging), D10 (protection last, 7 checks), D11 (second code owners). |
| **Never** | `--squash`, `--rebase`, `--admin`, a force push, deleting a branch that is still some open PR's base, or committing a secret to "prove" a gate. |

## Why merge commits, and why in this order

The five PRs form one linear stack. Each branch contains every commit of the one below it:

| PR | Head branch | Head SHA (CI-green) | Base | Green CI run |
|---|---|---|---|---|
| #1 | `feat/s3-soar-playbooks` | `b28c75d` | `main` @ `1019669` | 38478422214 |
| #2 | `feat/s3-detection-athena-sims` | `7d6c677` | `feat/s3-soar-playbooks` | 38486109181 |
| #3 | `feat/s1-s2-edge-identity-waf` | `247643a` | `feat/s3-detection-athena-sims` | 38930049163 |
| #4 | `feat/s2-app-soc-ui-grc` | `9adc96d` | `feat/s1-s2-edge-identity-waf` | 38984704551 |
| `$PF` | `feat/depi-phase-f-capstone-complete` | (latest) | `feat/s2-app-soc-ui-grc` | (latest) |

- **Squash or rebase** would write new commits to `main` that the next branch does not contain. The next PR's diff would then replay the PR below it and conflict, and the audited, CI-tested SHAs above would never reach `main`.
- **A merge commit** keeps every one of those SHAs in `main`'s history, which gives a chain of custody for the code. §3 checks it with `git merge-base --is-ancestor`.
- **Retarget explicitly**, and only then delete branches. GitHub's automatic retargeting happens only when the base branch is deleted through GitHub, and deleting a base branch any other way can close the PRs that sit on it [verify against GitHub docs]. A base change also runs no CI, because `on: pull_request` does not listen for `edited`. So every PR is retargeted, then **updated** (which pushes a merge commit and gives a fresh CI run against the new `main`), and checked again before its own merge.

## §0 Preconditions (stop if any fails)

```bash
REPO=ELSHAHALY/Cloud-Shield
PF=<number of the Phase F PR>            # issues and PRs share numbering; look it up
gh auth status && gh repo set-default "$REPO"
gh api "repos/$REPO" --jq '{merge_commit: .allow_merge_commit, delete_branch_on_merge, allow_update_branch}'
#   merge_commit must be true. delete_branch_on_merge should stay false (see §3).
#   allow_update_branch reads false today. That setting controls the "Update branch" button;
#   the API call in §2 is expected to work regardless [verify]. If it is refused, see §2.
gh api "repos/$REPO/codeowners/errors?ref=feat/depi-phase-f-capstone-complete" --jq .errors   # must print []

for n in 1 2 3 4 "$PF"; do
  gh pr view "$n" --json number,headRefName,baseRefName,headRefOid,isDraft,mergeable,reviewDecision \
    --jq '[.number,.headRefName,.baseRefName,.headRefOid[0:7],.isDraft,.mergeable,.reviewDecision] | @tsv'
done
```

1. **Heads match the table.** If a head moved, the newer commits need review and green CI before you continue.
2. **The stack is linear.** `behind_by` must be `0` for every pair:

   ```bash
   gh api "repos/$REPO/compare/main...feat/s3-soar-playbooks" --jq .behind_by
   gh api "repos/$REPO/compare/feat/s3-soar-playbooks...feat/s3-detection-athena-sims" --jq .behind_by
   gh api "repos/$REPO/compare/feat/s3-detection-athena-sims...feat/s1-s2-edge-identity-waf" --jq .behind_by
   gh api "repos/$REPO/compare/feat/s1-s2-edge-identity-waf...feat/s2-app-soc-ui-grc" --jq .behind_by
   gh api "repos/$REPO/compare/feat/s2-app-soc-ui-grc...feat/depi-phase-f-capstone-complete" --jq .behind_by
   ```

3. **CI is green on every head.** Run `for n in 1 2 3 4 "$PF"; do gh pr checks "$n"; done`. Every `gate:` job passes. `terraform plan (dev)` and `gate: dast (zap baseline)` show as skipped, which is expected.
4. **The scans really passed** (not just fail-open green). Every `Report (fail-open)` step must be `skipped`:

   ```bash
   for n in 1 2 3 4 "$PF"; do
     sha=$(gh pr view "$n" --json headRefOid --jq .headRefOid)
     run=$(gh api "repos/$REPO/actions/runs?head_sha=$sha&event=pull_request" --jq '.workflow_runs[0].id')
     echo "PR #$n run $run"
     gh api "repos/$REPO/actions/runs/$run/jobs?per_page=50" \
       --jq '.jobs[] | select(any(.steps[]; .name == "Report (fail-open)" and .conclusion != "skipped")) | "  FAIL-OPEN FIRED: \(.name)"'
   done                                    # no "FAIL-OPEN FIRED" line may appear
   ```

5. **Two-person review by team policy.** Protection does not exist yet, so this is enforced by you. A PR author's own approval never counts. PRs #1–#4 are authored by @ahklsfg, so **S1 and S2** approve each of them; for `$PF`, check the author first (`gh pr view "$PF" --json author --jq .author.login`), and the two team members who are **not** its author approve:

   ```bash
   gh pr review <n> --approve --body "Reviewed for the final merge (cutover runbook §0)."   # S1, then S2 on their machine
   gh pr view <n> --json reviewDecision,reviews --jq '.reviewDecision, [.reviews[] | select(.state=="APPROVED") | .author.login]'
   ```

## §1 Prove the gates, then enforce them (D9)

The gate scans on all four PRs really passed (§0.4), so turning enforcement on **before** the merges makes every post-retarget CI run a hard gate.

```bash
scripts/gate-selftest.sh all     # needs gitleaks, semgrep, trivy, checkov, docker
#   expect one ✓ line per gate and a final line with "NOT caught: 0" and "skipped: 0"
gh variable set ENFORCE_GATES --repo "$REPO" --body true
gh variable list --repo "$REPO"   # ENFORCE_GATES  true
```

- **If the self-test cannot finish** (a tool is missing, or the Trivy DB download fails), do not guess. Skip this step, merge fail-open, set the variable at §4 instead, and record the reason in HANDOFF §14.
- **If an enforced gate turns red later in §2** (for example a CVE published today), fix it on the branch being merged with a new commit, wait for green, and continue. Never unset the variable to get a merge through.

## §2 The merge loop

Every step stops the loop on its first error: `main` has no protection yet, so a red check or a failed merge must never be followed by the next command. Copy both helpers once, in the same shell where `REPO` is set:

```bash
# Wait (at most 15 min) until CI has registered on a head SHA, then watch it;
# non-zero on any failing check or on timeout.
wait_ci() {   # wait_ci <pr> <sha>
  local i
  for i in $(seq 90); do
    [ "$(gh api "repos/$REPO/commits/$2/check-runs" --jq .total_count)" -gt 0 ] && break
    sleep 10
  done
  [ "$(gh api "repos/$REPO/commits/$2/check-runs" --jq .total_count)" -gt 0 ] || { echo "no CI on $2 after 15 min"; return 1; }
  gh pr checks "$1" --watch --fail-fast --interval 15 || { echo "CI not green on PR #$1"; return 1; }
}

# Merge PR N, then retarget and update NEXT, and wait for NEXT's fresh CI.
merge_pair() {   # merge_pair <N> <NEXT>
  local N="$1" NEXT="$2" SHA OLD NEW i
  SHA=$(gh pr view "$N" --json headRefOid --jq .headRefOid) || return 1
  wait_ci "$N" "$SHA" || return 1                       # green on the exact head you merge
  gh pr merge "$N" --merge --match-head-commit "$SHA" \
    --subject "Merge PR #$N: $(gh pr view "$N" --json headRefName --jq .headRefName)" || return 1
  #   no --delete-branch: this branch is still NEXT's base until the retarget below
  [ "$(gh pr view "$N" --json state --jq .state)" = MERGED ] || { echo "PR #$N is not MERGED"; return 1; }
  [ -n "$NEXT" ] || return 0                            # the last PR has no successor

  gh pr edit "$NEXT" --base main || return 1            # explicit retarget
  OLD=$(gh pr view "$NEXT" --json headRefOid --jq .headRefOid) || return 1
  gh pr update-branch "$NEXT" || return 1               # merge commit "Merge branch 'main' into …" (never --rebase)
  NEW="$OLD"
  for i in $(seq 60); do                                # at most 5 min for the new head to appear
    NEW=$(gh pr view "$NEXT" --json headRefOid --jq .headRefOid)
    [ "$NEW" != "$OLD" ] && break
    sleep 5
  done
  if [ "$NEW" = "$OLD" ]; then
    # Either GitHub said "already up to date" (fine: the head already contains main)
    # or the update did not happen (stop).
    [ "$(gh api "repos/$REPO/compare/main...$NEW" --jq .behind_by)" = 0 ] || { echo "PR #$NEXT is behind main and was not updated"; return 1; }
  fi
  wait_ci "$NEXT" "$NEW" || return 1                    # fresh CI against the new main
  gh pr view "$NEXT" --json mergeable,mergeStateStatus --jq '.mergeable + " " + .mergeStateStatus'   # MERGEABLE CLEAN
}
```

Then run the whole stack as one chain, which stops at the first failure:

```bash
merge_pair 1 2 && merge_pair 2 3 && merge_pair 3 4 && merge_pair 4 "$PF" && merge_pair "$PF" "" \
  && echo "STACK MERGED" || echo "STOPPED: fix the reported problem, then resume from the failed pair"
```

To resume after a fix, run the remaining pairs only. For example, if `merge_pair 3 4` stopped after #3 merged but before #4 was updated, run `gh pr view 4 --json baseRefName,state` first, then continue from whichever step is not done yet.

- **The race:** right after `update-branch`, `gh pr checks` can still report the old head, or no checks at all. That is why the loop waits for the new head SHA and for its check runs to exist before it watches.
- **`--match-head-commit`** refuses the merge if someone pushed after you checked. If that happens, re-run `wait_ci` on the new head.
- **On a conflict** (none expected, given §0.2), merge rather than rebase: `git fetch origin && git switch <branch> && git merge origin/main`, resolve, `git push`, then `wait_ci` again. Never force-push someone else's branch.
- **`update-branch` says the branch is already up to date?** Then the head already contains `main` (`merge_pair` checks `behind_by = 0`), and the CI already on that head tested exactly what will merge. Never push an empty commit and never close and reopen to trigger CI.
- **`update-branch` refused** (for example because of the repo's update-branch setting, §0): either enable it (`gh api -X PATCH "repos/$REPO" -F allow_update_branch=true`), or merge `main` into the branch locally and push (the conflict path below). Then resume.

## §3 Check `main`, then delete the branches

```bash
git fetch origin
for s in b28c75d 7d6c677 247643a 9adc96d "$(gh pr view "$PF" --json headRefOid --jq .headRefOid)"; do
  git merge-base --is-ancestor "$s" origin/main && echo "ok  $s on main" || echo "MISSING $s"
done
for n in 1 2 3 4 "$PF"; do gh pr view "$n" --json number,state,mergedAt --jq '[.number,.state,.mergedAt] | @tsv'; done

gh run list --branch main --workflow ci.yml --limit 5
gh run watch "$(gh run list --branch main --workflow ci.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
#   push run on main: every gate green. The ECR push steps are skipped until
#   vars.AWS_ECR_PUSH_ROLE_ARN exists; terraform plan is skipped until AWS_PLAN_ROLE_ARN exists.
```

Only when all five PRs show `MERGED` and every SHA reads `ok`:

```bash
for b in feat/s3-soar-playbooks feat/s3-detection-athena-sims feat/s1-s2-edge-identity-waf \
         feat/s2-app-soc-ui-grc feat/depi-phase-f-capstone-complete; do
  gh api -X DELETE "repos/$REPO/git/refs/heads/$b" && echo "deleted $b"
done
```

## §4 Branch protection on `main` (D10): last

Apply protection only now. Before this point it cannot work: PRs #1–#3 have no `gate: app` job, and `enforce_admins` would block the stack. The seven contexts are the CI job `name:` values exactly (`grep -n 'name: "gate:' .github/workflows/ci.yml`):

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
  "required_conversation_resolution": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
gh api -X PUT "repos/$REPO/branches/main/protection" --input /tmp/protection.json
gh api "repos/$REPO/branches/main/protection" --jq '.required_status_checks.checks[].context'   # the 7 names
gh variable list --repo "$REPO"                                                               # ENFORCE_GATES true (set it now if §1 fell back)
```

- **Not required, on purpose:**
  - `gate: dast (zap baseline)` is skipped on pull requests, and a required check that never reports blocks every merge;
  - `terraform plan (dev)` is skipped until the plan-role variables exist;
  - `app-smoke (docker compose, optional)` stays optional, as designed.
- **Optional hardening:** add `"app_id": 15368` (GitHub Actions) to each check, so that only Actions can satisfy it [verify the id in GitHub's docs before using it].
- **Code owners (D11):** since Phase F every CODEOWNERS path lists owners from at least two roles. A PR author's own approval never counts, so a path whose only owner was its author could never pass code-owner review. GitHub reads CODEOWNERS from the **base** branch, so this works once the Phase F PR is on `main`. Two required approvals in a three-person team still means both non-authors approve.
- **`strict: true`:** from now on every PR must be up to date with `main` before it merges ("Update branch", then green CI again).

## §5 After the cutover

1. Open a one-line docs PR from a non-admin account. It must list all seven checks as required and show "Review required". Close it.
2. Run `gh variable list --repo "$REPO"`; it must read `ENFORCE_GATES true`.
3. Optionally tag the submission snapshot:

   ```bash
   git fetch origin && git tag -a capstone-2026-fall -m "DEPI capstone submission" origin/main
   git push origin capstone-2026-fall
   ```

## §6 Rollback

- **A bad merge:** revert it through a PR (`git revert -m 1 <merge-sha>` on a branch, then the normal review). Never rewrite or force-push `main`.
- **Enforcement:** unset `ENFORCE_GATES` only with a written reason in HANDOFF, and set it back as soon as the cause is fixed.
- **Protection:** `gh api -X DELETE "repos/$REPO/branches/main/protection"` removes it in an emergency. Re-apply it from §4 the same day.

## §7 Status (S1 fills in)

| Step | Done by | Date | Notes |
|---|---|---|---|
| §0 preconditions | | | |
| §0.5 approvals (S1 + S2 on each PR) | | | |
| §1 self-test + `ENFORCE_GATES=true` | | | fallback used? |
| §2 #1 merged | | | merge SHA |
| §2 #2 merged | | | |
| §2 #3 merged | | | |
| §2 #4 merged | | | |
| §2 `$PF` merged | | | |
| §3 SHAs on `main`, push CI green, branches deleted | | | run id |
| §4 protection applied (7 checks) | | | |
| §5 checks + tag | | | |

Related: [repo-admin-setup.md](repo-admin-setup.md) §3 (the protection payload, same seven checks) and [HANDOFF.md](../HANDOFF.md) §14.

## Appendix: REST equivalents for agent sessions

Claude Code sessions get HTTP 403 on GraphQL, so `gh pr …` fails there. These REST calls do the same things, apart from setting Actions variables, which the agent proxy blocks:

| Step | REST |
|---|---|
| View a PR | `gh api repos/$REPO/pulls/$N --jq '{head: .head.ref, sha: .head.sha, base: .base.ref, mergeable, mergeable_state, draft}'` |
| Checks on a SHA | `gh api repos/$REPO/commits/$SHA/check-runs --jq '.check_runs[] \| [.name, .status, .conclusion] \| @tsv'` |
| Approve | `gh api -X POST repos/$REPO/pulls/$N/reviews -f event=APPROVE -f body='…'` |
| Merge (merge commit) | `gh api -X PUT repos/$REPO/pulls/$N/merge -f merge_method=merge -f sha=$SHA -f commit_title="Merge PR #$N: …"` |
| Retarget | `gh api -X PATCH repos/$REPO/pulls/$NEXT -f base=main` |
| Update branch | `gh api -X PUT repos/$REPO/pulls/$NEXT/update-branch -f expected_head_sha=$OLD` (returns 202; poll `.head.sha`) |
| Delete a branch | `gh api -X DELETE repos/$REPO/git/refs/heads/<branch>` |
| Variable (human only) | `gh api -X POST repos/$REPO/actions/variables -f name=ENFORCE_GATES -f value=true` (or `-X PATCH …/variables/ENFORCE_GATES` if it exists) |
