# Phase F: verify-all, final merge and cutover, capstone reports, live demo, deck

**Branch:** `feat/depi-phase-f-capstone-complete`, created from `feat/s2-app-soc-ui-grc` @ `9adc96d` (PR #4 → #3 → #2 → #1). It becomes **PR #5** (the next number on the repo; issues and PRs share numbering, so the runbook uses `$PF` rather than a hard-coded 5), with base `feat/s2-app-soc-ui-grc` at first and retargeted to `main` after #4 merges.
**Status:** APPROVED, 17 Oct 2026. The user answered Q1–Q3 (§13): Q1 add second code owners (D11 implemented); Q2 seven required checks, the user's six plus `gate: image` (D10); Q3 the name is "Compliance Readiness Pack" (D12). Q4 and Q5 keep their defaults.

**Owners**
- **S1 @ELSHAHALY** (lead for Part 1): `scripts/verify-all.sh`, `Makefile`, the cutover runbook, branch protection and `ENFORCE_GATES`, the CI step label, and `environments/dev` for the Object Lock pass-through. Speaks the pipeline and edge slides.
- **S2 @YasseenAbdelghany:** the GRC readiness-pack export in `app/spa`; report chapter 05; demo acts 2 and 3.
- **S3 @ahklsfg:** report chapter 06 and the SOAR and forensics parts of 07; demo acts 4 and 5. S3 is also the **author of PRs #1–#4** (F7).
- All three: chapters 01–03 and 07 and the deck. ADR-style sign-off as in earlier phases.

**Sources read for this plan:** `docs/HANDOFF.md` (all of it), `README.md`, `Makefile`, `.github/workflows/ci.yml`, `.github/CODEOWNERS`, `.github/pull_request_template.md`, `.gitignore`, `.pre-commit-config.yaml`, ADR-0001…0006, every `docs/runbooks/*.md`, every `docs/plans/*.md`, `soar/README.md`, `soar/pyproject.toml`, `soar/requirements-dev.txt`, `soar/sims/{README.md,runner.py,local_router.py,scenarios.py}`, `soar/tests/{conftest.py,test_sims.py,test_queries.py,fixtures/coc_golden.json}`, `soar/core/aws.py`, `attack-sim/README.md`, `detection/`, `app/README.md`, `app/grc/README.md`, `app/openapi.yaml` (the GRC and SOC paths), `app/spa/src/{grc/GrcHub.tsx,soc/EvidencePanel.tsx,auth/session.tsx,components/ui.tsx,grc/grc.test.tsx}`, `app/docs-api/{package.json,jest.config.js,test/helpers/moto.ts}`, `app/spa/{package.json,vitest.config.ts}`, `app/local-dev/src/{seed.ts,smoke.ts}`, `docker-compose.local.yml`, `scripts/gate-selftest.sh`, `.zap/rules.tsv`, `infra/terraform/modules/{network/variables.tf,soar/{main.tf,state-machine.tf,variables.tf},detection/athena.tf,log-archive/main.tf}`, `environments/dev/{main.tf,variables.tf,outputs.tf}`, and `docs/runbooks/repo-admin-setup.md`. Live repo state came from the GitHub REST API: PRs, compare, check-runs, job steps and repo settings. `git log` was read locally.

**How facts are marked** (same legend as the Phase E plan)
- **[repo]:** read from this repository, or from the GitHub REST API for this repository on 17 Oct.
- **[observed]:** seen in this planning sandbox (tool versions, network reachability).
- **[doc]:** vendor or official documentation, from memory. Not re-checked while planning.
- **[inferred]:** my best understanding, not verified. Each one is a Builder step-0 item (§9), a rehearsal item, or worded as unverified in the deliverable.
- **[verify]:** an edition, date, version, legal or behavioural claim that must be checked against the official source before it ships. Reports must keep the `[verify]` mark until it is checked.

---

## 0. Summary

Phase F changes almost no product code. It adds:

1. **`make verify-all`**: one sequential local gate run with stop-on-first-failure, a colour summary per domain, and a guarantee that it leaves the working tree unchanged.
2. **`docs/runbooks/final-merge-and-cutover.md`**: merge the PR stack with **merge commits**, with an explicit retarget and update-branch for each PR, then enforce the gates and protect `main`.
3. **Seven capstone report chapters** under `docs/reports/`.
4. **`docs/runbooks/live-demo-runbook.md`**, with an **offline track** (the default, because nothing is applied to AWS) and an **AWS lab track**.
5. **`docs/presentation/deck-outline.md`** (20 slides).
6. **HANDOFF §14**.

The only code changes are a **client-side GRC readiness-pack export** in the SPA (no API change), an **`evidence_object_lock_days` pass-through** in `environments/dev`, and wording fixes (README overclaims, Makefile and sims comments, a stale CI step label). The governing rule is honesty over polish. No AWS measurement exists, so none is presented. Every number in the reports cites a file, a CI run or a dated local run.

---

## 1. Facts that shape the design

| # | Fact | Mark | Plan |
|---|---|---|---|
| F1 | **PR stack is linear.** #1 `feat/s3-soar-playbooks` @`b28c75d` → `main` @`1019669`; #2 `feat/s3-detection-athena-sims` @`7d6c677` → #1's branch; #3 `feat/s1-s2-edge-identity-waf` @`247643a` → #2's; #4 `feat/s2-app-soc-ui-grc` @`9adc96d` → #3's. `compare` for each base…head reports ahead 5 / 3 / 8 / 8 and behind 0. Each merge base is exactly the parent head. All open, none draft, **all authored by @ahklsfg**. | [repo: REST] | D8 |
| F2 | **Latest CI per head is green, and the scans really passed.** In every gate job the `Report (fail-open)` step was **skipped**, so the scan step's outcome was success, not just the job. Runs: #1 `38478422214`, #2 `38486109181`, #3 `38930049163`, #4 `38984704551`. `terraform plan (dev)` and `gate: dast` are skipped (expected). `gate: app` and `app-smoke` exist only from #4. `gate: image` ran on all four (#1–#3 skipped the Trivy step because there was no Dockerfile yet). | [repo: REST] | D9; ch. 07 evidence |
| F3 | Repo settings: merge, squash and rebase are all allowed; `delete_branch_on_merge=false`; `allow_update_branch=false`; **`main` is not protected**. | [repo: REST] | D8, D10 |
| F4 | Exact CI job `name:`s: `gate: secrets (gitleaks)`, `gate: sast (semgrep)`, `gate: sca (trivy fs)`, `gate: soar (ruff + pytest)`, `gate: app (lint + typecheck + test + build)`, `gate: iac (terraform + checkov)`, `gate: image (trivy image + sbom)`, `app-smoke (docker compose, optional)`, `terraform plan (dev)`, `gate: dast (zap baseline)`. | [repo ci.yml] | D10 |
| F5 | `repo-admin-setup.md` §3 requires secrets/sast/sca/iac/app/image but **not `soar`**. README §3 lists only 5 checks (no soar, no app). HANDOFF §10 says to add soar. | [repo] | Stage 1 doc fixes |
| F6 | From Claude Code sessions **GitHub GraphQL is refused** (`gh pr list` gives HTTP 403), so `gh pr …` subcommands fail in the agent sandbox. REST (`gh api repos/…`) works. The **Actions variables API path is blocked** by the proxy, so the agent cannot set `ENFORCE_GATES` (only S1 can, as admin, anyway). The Actions runs and jobs paths work. | [observed] | Part 4 uses REST; the runbook is for S1's own machine, where `gh pr` works |
| F7 | CODEOWNERS has single-owner paths: `*`, `/infra/`, bootstrap/network/compute/edge, `/Makefile` (S1 only); `/app/`, data, identity (S2 only); `/soar/`, `/detection/`, `/attack-sim/`, modules soar and log-archive (S3 only). A PR author's own approval never counts, and GitHub evaluates CODEOWNERS **from the base branch** [doc]. With "Require review from Code Owners", a PR by @ahklsfg that touches an S3-only path can never be code-owner-approved; the same holds for S1 and S2. | [repo] [doc] | D10, D11, Q1 |
| F8 | **SOAR coverage is configured in `soar/pyproject.toml`:** `[tool.coverage.run] branch=true, source=[core, safety_guard, playbooks, notifier, tools, sims]`, `[tool.coverage.report] fail_under=95`. pytest runs from `soar/` with `pythonpath=["."]`, and there is **no `soar` package**. So `--cov=soar` would measure nothing useful and would fight the configured `source`, and `--cov-fail-under=95` would duplicate `fail_under`. CI and `make soar-test` run `python -m pytest --cov`. The CI step is still **labelled "pytest (coverage >= 90%)"** (stale). | [repo] | D2 |
| F9 | `npm test` in docs-api is plain `jest`: no coverage flag. Thresholds are in `jest.config.js` (lines/statements/functions 90, branches 85). The `*.int.test.ts` suites need moto at `MOTO_ENDPOINT` (default `http://localhost:5000`). In the SPA, `test` is `vitest run` with no coverage; `test:coverage` exists; thresholds are in `vitest.config.ts` (80/80/80/75). | [repo] | D3 |
| F10 | `make fmt` **writes** (no `-check`). `make validate` and `make test` run `init` in the tree. `.gitignore` ignores module lock files but **not** root `.terraform.lock.hcl` files (bootstrap, dev), so an in-tree init leaves untracked files. | [repo] | D5 |
| F11 | 11 directories are validated (bootstrap, `environments/dev`, 9 modules) and 8 have `tests/` (all modules except network). CI pins: TF 1.16.5, gitleaks 8.30.1, Checkov 3.3.26, Semgrep 1.180.0, Trivy 0.75.0, Python 3.13, Node from `app/.nvmrc` = 24.22.0, ruff 0.17.0, moto 5.2.4, hadolint v2.14.0 by digest. | [repo] | D4 version WARN |
| F12 | **Sandbox:** terraform 1.16.5, checkov 3.3.26, gitleaks 8.30.1, semgrep 1.180.0, Docker 29.8.2 (daemon up), Node 24.22.0, Python 3.13.16 with moto 5.2.4 and pytest-cov, **ruff 0.16.8 (CI pins 0.17.0)**. Missing: actionlint, shellcheck, hadolint, trivy. `registry.terraform.io` is **unreachable**; releases.hashicorp.com, Docker Hub and npm are reachable; github.com release downloads return 403. Full clone (not shallow), 26 commits. | [observed] | Part 4 environment notes |
| F13 | `make local-smoke` has **8 checks** (1, 2, 3, 4a–4c, 5a, 5b). It needs Compose v2.20+, Node 24, and host ports `127.0.0.1:3000` (SPA) and `:5000` (moto). `make local-moto` also binds 5000. | [repo] | D1 port checks |
| F14 | **Nothing has ever been applied to AWS.** moto does not enforce IAM, KMS key ids, bucket policies or Object Lock retention reads. | [repo HANDOFF §1/§13, local-dev.md] | D15–D19 |
| F15 | **Seeded SOC incidents carry hand-authored times.** MTTC is 18 s (A), 25 s (A-recon), 32 s (B), 9 s (C), 12 s (E), 40 s (A-recon-2) and 22 s (crypto) (`app/local-dev/src/seed.ts`). The golden chain-of-custody fixture has `mttc_seconds: 18.0` (synthetic). **Neither is a measurement.** | [repo] | D16 |
| F16 | `make sim … TARGET=local` is **not offline**. It drives the real handlers through the default boto3 chain (`core/aws.client`); `soar/sims/README.md` warns about this, but its code block says "offline smoke test (what CI runs)" and the Makefile says "Offline default". **CI's replay evidence is pytest under moto** (`tests/test_sims.py::test_replay_local_scenario_{a,b,c}_contains`, the D/E dry-run tests). The runner prints its `SimResult` JSON, which `pytest -s` shows. | [repo] | D18 Act 4; Stage 1 wording fixes |
| F17 | **MTTC as implemented:** `RecordDetected` writes `eventTime` = this run's EventBridge `time` (keeping `firstEventTime` and `findingCreatedAt`); `MarkContained` writes `containedAt = $$.State.EnteredTime`; dry-run ends at `wouldContainAt` and is excluded. SOC metrics give n, last, p50, p90 and max with a **nearest-rank** percentile (`metrics.ts`). `replay --target aws` builds the event with `time = now` **on the operator's clock** and calls `StartExecution` directly (no EventBridge hop). EventBridge `time` has whole-second resolution [inferred]. | [repo] [inferred] | D16 |
| F18 | **Evidence Object Lock:** `modules/soar` has `evidence_object_lock_days` (default 0, GOVERNANCE, "only settable at bucket creation"), but **`environments/dev` does not expose it**. Only `log_archive_object_lock_days` exists there. The dry-run SSM parameter is Terraform-managed (`value = var.dry_run`); there is no `ignore_changes`. | [repo] | D13; demo AWS track |
| F19 | Athena workgroup is `${name}-cs-forensics` (outputs `athena_workgroup`, `glue_database`, `hunt_queries`). There are 4 hunt queries, tested statically only (`test_queries.py`); none has ever run against data. `edge-waf-demo.md` names the workgroup `cs-forensics`, which is inaccurate. | [repo] | Demo runbook uses `terraform output` |
| F20 | **GRC:** `GET /grc/assessment` returns ruleset version and SHA-256, profile version, `generatedAt`, `platformFacts`, `disclaimer`, `summary` and `findings[]` (each with `citationStatus`). **There is no export.** A precedent exists: `EvidencePanel.downloadReport` (fetch with bearer → Blob → `<a download>`) is tested and shipped. The session exposes `me.tenantId`; `grc:assess` belongs to admin and auditor. Ruleset `2026.10.0` has 32 rules (EU-GDPR 12, EG-PDPL 9, EG-CBE 4, SA-PDPL 4, SA-NCA 3). Seeded **dina** (admin of `t-nile-02`: EG, financial, CBE-regulated) has a profile. | [repo] | D12 |
| F21 | Gates are fail-open unless `ENFORCE_GATES=true`. `soar`, `app` and terraform fmt/validate/test always hard-fail. `gate-selftest.sh` builds seeds at runtime; the secrets seed is a fake `ghp_` token; `AKIAIOSFODNN7EXAMPLE` is allow-listed. **Proven to trip:** secrets and IaC (CKV_AWS_24). **SAST seed pack membership is unconfirmed**, and the SCA, image and DAST seeds have never run (HANDOFF §5). | [repo] | D18 Act 1 |
| F22 | **The plan PDF, the DEPI Fall 2026 rubric and WBS Chapter 7 are not in the repo.** The repo references (detail in §6.2):<ul><li>R1 (team size, H×H), R2 (automation storm / guard), R3 (cost overrun), R4 (AWS abuse in sims), R5 (cross-account complexity), R6 (integration risk);</li><li>FR-2/3/4 (the Phase E plan itself marks this mapping [inferred]), FR-5 (enforced gates), FR-8 (hunting + IR report);</li><li>KPI §2.4 (seeded SQLi caught by SAST); "success criterion 06" (IR report);</li><li>plan §1.2 (single region), §2.2 (RACI), §4.2, §4.3–4.4, §5 / Figure 5.1, §5.1, §5.2, §6.2–6.5 / Figure 6.5, §7, §8.4, §8.6, §8.8, Figure 7.1 (the README trust-boundary table);</li><li>WBS §6.1, §6.2, §6.5, §7.</li></ul>**Not found anywhere:** R7, FR-1, FR-6, FR-7, the content of plan §1.1, any rubric criteria, WBS Chapter 7. | [repo] | D15, §6.2 |
| F23 | **README overclaims and staleness:**<ul><li>line 8: "contain an incident automatically, **typically in under 60 s**" (never measured);</li><li>line 41: "**append-only** audit" (contradicts M6; the wording is "insert-only by convention");</li><li>cost: "**4 KMS keys**". Default-on keys are now 5 (compute, data, log-archive, soar, detection/athena), plus edge when enabled and the bootstrap state key.</li></ul> | [repo] | D14 |
| F24 | HANDOFF §2.1: "Autonomous" overstates the design. Say "*automated containment with human-gated eradication*". | [repo] | D18 wording rules |
| F25 | Earlier phases settled the following, and the reports must keep them: FR-3 encryption context = bucket ARN (S3 Bucket Keys), so tenant isolation is not cryptographic (ADR-0002 §5, Phase E F7). FR-4 is insert-only **by convention**; the stream consumer is a follow-up (ADR-0006). The build is **single account** (ADR-0001). Data is **DynamoDB only**: `documents` (`tenantId`/`docId`: `doc#…`, `meta#grc-profile`), `audit` (`tenantId`/`eventKey`; stream; `AGREEMENT#` markers), `soar-incidents` (`incidentId`; GSI `status-eventTime`), `soar-pb05-harvest-state`. There is no RDBMS. | [repo] | D15 |
| F26 | **Last recorded measurements** (HANDOFF §13, local Linux, after the audit fixes; CI on PR #4 green):<ul><li>docs-api Jest 290 tests / 17 suites (94.5 % lines, 86.8 % branches);</li><li>SPA Vitest 50 (96.3 % lines); local-dev Jest 5; local-smoke 8/8;</li><li>terraform test 110/110 (compute 22, data 6, detection 14, edge 14, identity 8, lab-targets 1, log-archive 3, soar 42); validate 11/11; fmt clean;</li><li>Checkov 953 terraform + 202 dockerfile passed, 0 failed;</li><li>pytest coverage 97.6 % (the test count is not recorded in §13; §12 had 622).</li></ul> | [repo] | Ch. 07 re-measures; never reuses these numbers without citing §13 |
| F27 | GitHub behaviour [doc]:<ul><li>`on: pull_request` with default activity types (opened, synchronize, reopened) **does not run on a base change** (`edited`).</li><li>A *re-run* reuses the original run's merge SHA [inferred/verify].</li><li>Deleting a merged PR's head branch retargets open PRs that use it as their base to the merged PR's base [verify].</li><li>`strict: true` requires the head branch to be up to date with the base.</li></ul> | [doc] [verify] | D8 |
| F28 | Real delivery dates (git log): 8 Oct design + scaffold + audit; 14 Oct push, CI fix, SOAR, Phase C; 16 Oct Phase D; 16–17 Oct Phase E. | [repo] | Ch. 01 Gantt (real dates only) |

---

## 2. Decisions

| # | Decision |
|---|---|
| **D1 verify-all shape** | A new `scripts/verify-all.sh` (bash, in the `gate-selftest.sh` style) and a `make verify-all` target. Domains run in the user's order: `preflight` → `terraform` → `soar` → `docs-api` → `spa` → `checkov` → `gitleaks` → `actionlint` → `local-smoke`. Each domain mirrors its CI job (lint, typecheck and build included), so "verify-all green" means "the hard CI gates plus Checkov, Gitleaks and actionlint are green locally". **Not covered** (printed in the summary): Semgrep, Trivy fs/image and ZAP, because they need registry or DB downloads and CI is the authority; `make sast sca` stays available. Optional positional arguments select a subset (`scripts/verify-all.sh soar spa`); unselected domains show `not selected`. |
| **D2 SOAR coverage** | Run `cd soar && python -m pytest --cov`, exactly as CI and `make soar-test` do. The threshold (95) and the measured packages live **only** in `pyproject.toml`. No `--cov=soar` (wrong target, F8) and no `--cov-fail-under` (double configuration). The summary reads `fail_under` from `pyproject.toml` (`tomllib`) for display only. CI step label corrected to "pytest (coverage gate in pyproject.toml, 95 %)". |
| **D3 Node coverage** | `npm --prefix app/docs-api test -- --coverage --ci` with moto running, and `npm --prefix app/spa run test:coverage`. Thresholds stay in `jest.config.js` and `vitest.config.ts`. `npm ci --ignore-scripts` runs first in each package, as in CI. |
| **D4 Prerequisites: FAIL, not silent skip** | A missing tool, a stopped Docker daemon, a busy port, a shallow clone or Node ≠ 24 means preflight **FAIL**, exit 2, with an install hint per tool. `VERIFY_ALLOW_SKIP=1` turns a missing-tool domain into **SKIP** (yellow); the run then exits 0 but prints `RESULT: INCOMPLETE (n skipped)`. Report chapter 07 never cites an INCOMPLETE run as a full verification. A version that differs from the CI pin is a **WARN** in the summary (for example ruff 0.16.8 vs 0.17.0), not a failure. |
| **D5 No tree mutation** | **Terraform runs on a scratch copy**: tracked plus untracked-but-not-ignored files of `infra/terraform`, from `git ls-files -co --exclude-standard` copied into `$WORK`. That copy absorbs `.terraform/` and root lock files (F10). Providers come from a shared `TF_PLUGIN_CACHE_DIR` outside the repo (default `${XDG_CACHE_HOME:-$HOME/.cache}/cloudshield/tf-plugins`). An existing `TF_CLI_CONFIG_FILE` (provider mirror) is honoured.<br>Format uses `terraform fmt -check -recursive -diff`, never `make fmt`. The package build writes to `$WORK`.<br>Before and after the run the script snapshots `git status --porcelain=v1 --untracked-files=all`, `git diff --binary \| sha256sum` and `git diff --cached --binary \| sha256sum`. Any difference means **FAIL, exit 3**, listing the paths. Gitignored artefacts (`node_modules/`, `coverage/`, `dist/`, `.coverage`, `__pycache__/`) are allowed.<br>Logs go to `${TMPDIR:-/tmp}/cloudshield-verify.XXXXXX/<domain>.log` and are kept; the path is printed. |
| **D6 Colour** | Colour only when stdout is a TTY, `NO_COLOR` is unset or empty (no-color.org) and `TERM` is not `dumb`. Otherwise plain text with the same `PASS`/`FAIL`/`SKIP`/`WARN` words, so logs and CI-style captures stay readable. Symbols ✓ ✗ - as in `gate-selftest.sh`. |
| **D7 Not wired into CI** | No new workflow and no required check. CI already runs each domain as its own parallel job and keeps `app-smoke` optional; a monolithic sequential job would only duplicate them and add about 15–25 min [inferred]. The script is linted with shellcheck (pinned Docker image) by the Builder and Validator, and `bash -n` runs in its own preflight. |
| **D8 Merge method: merge commits, explicit retarget** | `gh pr merge N --merge --match-head-commit <sha>`, strictly in order #1 → #2 → #3 → #4 → #PF. **No squash and no rebase**: both create new commits on `main` that the next stacked branch does not contain, so its diff would replay the earlier PR and conflict, and the CI-proven head SHAs would vanish from `main`'s history. Merge commits keep every audited, CI-tested SHA on `main`: a chain of custody for the code.<br>After each merge: explicit `gh pr edit <next> --base main` (do not rely on auto-retarget, F27), then **update-branch**, which creates a `synchronize` event and a fresh CI run against the new base, then `gh pr checks --watch`. Branches are deleted only after the whole stack is merged. |
| **D9 `ENFORCE_GATES=true` before the merges** | The scans on all four PRs really passed (F2), so S1 runs `scripts/gate-selftest.sh all` (every gate ✓, 0 not caught, 0 skipped), then sets `ENFORCE_GATES=true`, **then** merges. Every post-retarget CI run is then enforced. If a newly published CVE makes a re-run red, fix it on the branch being merged and continue. **Fallback, if the self-test cannot complete:** merge fail-open, flip after #PF, and record why in HANDOFF §14. |
| **D10 Branch protection: last, with 7 checks** | Applied **after #PF merges**. Before that it cannot work: #1–#3 have no `gate: app` job (F2), and every PR is by @ahklsfg touching S3-only paths (F7) while `enforce_admins: true` would bar any bypass.<br>Required checks: the user's six (secrets, sast, sca, iac, **soar**, app) **plus `gate: image (trivy image + sbom)`**, which `repo-admin-setup.md` already requires and which runs on every PR. Dropping it would weaken the existing design; it is easy to remove if the user disagrees.<br>Other settings: `strict: true`, 2 approvals, code-owner review, dismiss stale reviews, `enforce_admins: true`, conversation resolution, no force pushes or deletions. Optional hardening: `"app_id": 15368` (GitHub Actions) on each check, so only Actions can satisfy it [verify]. Excluded: dast (skipped on PRs), `terraform plan` (skipped until variables are set) and `app-smoke` (optional). |
| **D11 Second code owner on single-owner paths** (Q1) | In PR #PF, give every single-owner path a second owner from another role: S3 paths `@ahklsfg @ELSHAHALY`; S2 paths `@YasseenAbdelghany @ELSHAHALY`; S1 paths `@ELSHAHALY @ahklsfg`; plus `/docs/ @ELSHAHALY @YasseenAbdelghany @ahklsfg`. GitHub's any-one-owner rule plus 2 required approvals keeps review two-person. Without this, D10's code-owner rule blocks every PR by a path's sole owner. **Default if Q1 is unanswered: implement**, because it is on the cutover's critical path. |
| **D12 Readiness pack: client-side, no API change** | The SPA gets "Download readiness pack (Markdown)" and "(JSON)" buttons in `GrcHub`, shown only when an assessment is loaded (admin and auditor). The pack is built from the already-fetched `GET /grc/assessment` plus `GET /grc/ruleset`, with the `EvidencePanel` Blob pattern.<br>**Name:** "Compliance Readiness Pack", not "Audit Pack": it is a self-assessment against partly unverified citations, not an audit. The demo line becomes "exporting the Egypt PDPL / CBE Compliance Readiness Pack (a self-assessment, not an audit)".<br>**Scope:** banner "Not legal advice. Not an audit or certification."; the server disclaimer verbatim; provenance (tenant id, ruleset id, version, SHA-256 and lastReviewed, profile version, server `generatedAt`, client `exportedAt`); summary counts; per-framework tables of applicable findings (status, ruleId, topic, obligation, controls, citations with `[doc]`/`[verify]` status), with a **"⚠ VERIFY against the official text"** marker on every `citationStatus = verify` row; a CUSTOMER_ACTION list; and the residency-GAP-by-construction note.<br>The JSON form is the assessment verbatim plus `exportMeta {format: "cloudshield.grc.readiness-pack/1", exportedAt, tenantId, rulesetVersion, rulesetSha256, disclaimer}`.<br>Not audited and not signed (a client-side read); stated in the pack and in chapter 05. An API route with an audit event is a recorded follow-up. |
| **D13 Object Lock pass-through** | `environments/dev` gains `evidence_object_lock_days` (number, default 0, validation ≥ 0, description "0 = off; set before the first apply: only settable at bucket creation; GOVERNANCE; blocks teardown for N days"). It is wired to `module.soar`, with a `terraform.tfvars.example` line and a README flags row. Without this, demo act 5's Object Lock cannot exist in a lab (F18). |
| **D14 Honesty fixes** | README line 8 → "designed to contain an incident automatically within a 60 s target (MTTC, measured per ADR-0002 §3; **not yet measured on AWS**)". Line 41 → "insert-only-by-convention audit (conditional writes, stream, PITR)". Cost → "5 KMS keys by default". README §3 checks list → the 7 of D10. Makefile `sim` comment and the `soar/sims/README.md` code-block comment → "`TARGET=local` drives the real handlers with your configured AWS credentials; CI runs this path under moto via pytest". |
| **D15 Report rules** | See §6.1. The essentials: Markdown; numbers only with a cited source; two evidence columns, **measured locally / in CI** and **pending first apply**, with placeholder tables the team fills after a lab apply; "logical view" for DynamoDB items (no invented relational tables); TB0–TB5 described **as implemented in one account** next to the multi-account **target**; every item from the PDF, rubric or WBS that is absent from the repo marked `[source: plan PDF, not in repo — team to verify]`. |
| **D16 MTTC, defined once** | Formal definition and measurement classes in §7.2. Every MTTC figure anywhere (reports, deck, demo) states its class. Only M3 and M4 count as "MTTC on AWS", and neither exists yet. |
| **D17 Literature** | Only real, well-known primary sources from the list in §6.4, each with `[verify]` on edition and date and an access date. No invented papers, surveys, statistics or market figures. The commercial SOAR comparison is qualitative (capabilities and deployment model) with no prices. |
| **D18 Demo tracks and wording** | The **offline track is the default primary**, because no lab apply exists; the AWS lab track is used for acts 4–5 only if it was applied and rehearsed by T-24h.<br>**Act 1:** live `scripts/gate-selftest.sh secrets` (the seed is built at runtime and never committed), plus a demo PR opened at T-60 carrying a **Checkov CKV_AWS_24 seed** (proven to trip, F21), red under enforcement and blocked by required checks. It is never merged: closed afterwards, branch deleted. **No secret is ever committed.**<br>**Act 4 offline:** `pytest -s` replay showing the real playbook reaching `CONTAINED` in-process under moto, explicitly "not MTTC".<br>**Wording:** "automated containment with human-gated eradication"; seeded numbers are always called "seeded". |
| **D19 Act 5** | **Offline:** the SOC evidence panel (A intact, C **BROKEN**, recomputed SHA-256), the IR report download, and, if step 0 confirms it, the **Python IR tool against the compose moto** (`AWS_ENDPOINT_URL`, exit 2 on C). Athena is shown as SQL and explained, not run. **AWS:** a live hunt query 03 after scenario C (run at T-30 to absorb CloudTrail delivery delay), `make ir-report`, `get-object-retention`, and a refused `delete-object` on a locked version (requires D13 at first apply). |
| **D20 Deck** | 20 slides (§8.3); the speaker follows ownership; slide claims match chapter text word for word on MTTC, FR-3, FR-4, single account and "automated". |
| **D21 PR #PF base** | `feat/s2-app-soc-ui-grc` (stacked, so its diff shows only Phase F), retargeted after #4 per D8. |
| **D22 File names** | The user's names: `docs/reports/{README.md, 01_project_charter_and_management.md, 02_literature_review_and_benchmarking.md, 03_system_analysis_and_architecture.md, 04_devsecops_shift_left_pipeline.md, 05_secure_cloud_application_and_identity.md, 06_detection_telemetry_and_soar_engine.md, 07_verification_attack_simulations_and_qa.md}`, `docs/runbooks/{final-merge-and-cutover.md, live-demo-runbook.md}`, `docs/presentation/deck-outline.md`. |

---

## 3. Part 1a: `make verify-all` design

### 3.1 Domains (exact commands)

| # | Domain | Commands | Needs (preflight) |
|---|---|---|---|
| 0 | `preflight` | `bash -n "$0"`; `git rev-parse --is-shallow-repository` must print `false` (hint: `git fetch --unshallow`); tool presence and versions; Docker daemon (`docker info`); `docker compose version` ≥ 2.20; Node major 24; Python ≥ 3.12 that can `import pytest, pytest_cov, moto, boto3` (hint: `pip install -r soar/requirements-dev.txt`); `ruff`; host ports 3000 and 5000 free (hint: `make local-down`, `docker stop cloudshield-moto`); Terraform registry reachable **or** `TF_CLI_CONFIG_FILE` set (hint: provider mirror). | — |
| 1 | `terraform` | Copy to `$WORK/tf` (D5). Then `terraform fmt -check -recursive -diff infra/terraform`. For each of the 11 directories (bootstrap, `environments/*/`, `modules/*/`): `terraform -chdir=$d init -backend=false -input=false -no-color` and `terraform -chdir=$d validate -no-color`. For each of the 8 module directories with `tests/`: `terraform -chdir=$d test -no-color`. | terraform (WARN if ≠ 1.16.5) |
| 2 | `soar` | `cd soar && ruff check . ../scripts/package_soar.py && ruff format --check . ../scripts/package_soar.py && python -m pytest --cov && python -m tools.export_attack_table --check ../app/docs-api/src/soc/attack-table.generated.json`. Then `python scripts/package_soar.py --out "$WORK/a.zip"` twice (`b.zip`); the two SHA-256s must be equal. | python, ruff (WARN if ≠ 0.17.0) |
| 3 | `docs-api` | `npm --prefix app/docs-api ci --ignore-scripts`; `… run lint -- --max-warnings 0`; `… run typecheck`; `… run openapi:check`. Start `docker run -d --rm --name cloudshield-verify-moto-$$ -p 127.0.0.1:5000:5000 $MOTO_IMAGE` (the Makefile digest) and poll `/moto-api/` until healthy. Then `MOTO_ENDPOINT=http://127.0.0.1:5000 AWS_ACCESS_KEY_ID=local-only AWS_SECRET_ACCESS_KEY=local-only AWS_REGION=us-east-1 npm --prefix app/docs-api test -- --coverage --ci`. Stop moto (also in the trap). | node 24, docker |
| 4 | `spa` | `npm --prefix app/spa ci --ignore-scripts`; `… run lint`; `… run typecheck`; `… run test:coverage`; then the CI production build: `VITE_AUTH_MODE=cognito VITE_COGNITO_USER_POOL_ID=us-east-1_Placeholder VITE_COGNITO_CLIENT_ID=placeholderclientid VITE_AWS_REGION=us-east-1 npm --prefix app/spa run build`, `node app/spa/scripts/check-bundle.mjs app/spa/dist`, and `! grep -R local-idp app/spa/dist/`. | node 24 |
| 5 | `checkov` | `checkov -d infra/terraform --framework terraform --quiet --compact --download-external-modules false`, then `checkov -d app --framework dockerfile --quiet --compact` (the CI commands). Hadolint on the 3 Dockerfiles: the binary if present, else `docker run … $HADOLINT_IMAGE` exactly as in the Makefile. | checkov (WARN if ≠ 3.3.26), docker or hadolint |
| 6 | `gitleaks` | `gitleaks git . --redact --verbose --exit-code 1` (full history). | gitleaks (WARN if ≠ 8.30.1) |
| 7 | `actionlint` | `actionlint .github/workflows/*.yml`, or the pinned Docker image `rhysd/actionlint:<ver>@sha256:<digest>` (step 0 picks the version and digest) with the repo mounted read-only. | actionlint or docker |
| 8 | `local-smoke` | `docker compose -f docker-compose.local.yml config -q`; local-dev (`npm --prefix app/local-dev ci --ignore-scripts`, lint, typecheck, `npx jest --ci`); `make local-up`; `make local-smoke` (expects "all checks passed", 8 checks); **always** `make local-down` (trap). | docker compose ≥ 2.20, ports |

### 3.2 Semantics

- `set -Euo pipefail`. Each domain runs in a function with its own log. The **first failing domain stops the run**; later domains show `not run`.
- `trap` on EXIT, INT and TERM stops the moto container, runs `make local-down` if the stack was started, and prints the summary. The trap must not mask the original exit code. **Auditor item:** check this with Ctrl-C mid-domain.
- **Exit codes:** 0 = all selected domains PASS (or SKIP under `VERIFY_ALLOW_SKIP=1`, with banner INCOMPLETE); 1 = a check failed; 2 = a prerequisite is missing; 3 = the working tree changed.
- Summary columns: `domain | result | duration | facts | log`. "Facts" come from best-effort greps (pytest `TOTAL … %` and `N passed`; Jest `Tests: N passed` and the coverage summary; Vitest `Tests N passed`; `terraform test` `N passed`; Checkov `Passed checks: N, Failed checks: M`; gitleaks "no leaks found"; smoke "all checks passed"). A failed grep shows `—` and never changes the result.
- Header line: commit SHA, a "dirty" flag, UTC time, `uname -sm`. Footer: "Not covered: semgrep, trivy fs/image, ZAP: see CI".
- The script never prints environment variables. Gitleaks runs with `--redact`. Nothing user-supplied reaches `eval`.

### 3.3 Makefile, README, CI

- Makefile: a `verify-all` target (`scripts/verify-all.sh $(VERIFY_DOMAINS)`), added to `.PHONY` and `help`.
- README Testing table: a `make verify-all` row (prerequisites, `NO_COLOR`, `VERIFY_ALLOW_SKIP`, exit codes).
- `ci.yml`: only the soar pytest step label changes (D2).

---

## 4. Part 1b: `docs/runbooks/final-merge-and-cutover.md` design

**Owner:** S1 @ELSHAHALY, the only admin. To be run on his own machine with `gh` ≥ 2.40 authenticated (`gh pr` uses GraphQL, which works there; F6). Every step has a REST alternative in a collapsed note for agent sessions.

### §0 Preconditions (stop if any fails)

```bash
REPO=ELSHAHALY/Cloud-Shield; PF=<phase-F PR number>
gh auth status && gh repo set-default "$REPO"
gh api "repos/$REPO" --jq '{merge: .allow_merge_commit, update_branch: .allow_update_branch}'   # merge must be true
for n in 1 2 3 4 "$PF"; do gh pr view "$n" --json number,headRefName,baseRefName,headRefOid,isDraft,reviewDecision,mergeable; done
for n in 1 2 3 4 "$PF"; do gh pr checks "$n"; done   # every gate job pass; dast + terraform plan skipped = expected
```

- An expected-stack table (F1) with heads and bases; continue only if heads match, or if the newer heads were reviewed.
- Linearity check: `gh api repos/$REPO/compare/<base>...<head> --jq .behind_by` must be `0` for each pair.
- Fail-open check: open each PR's latest run summary; there must be **no** "⚠️ … gate failed (fail-open mode)" line. The REST alternative checks the `Report (fail-open)` step conclusion is `skipped` (F2).
- **Team policy before protection exists:** every PR has 2 approvals from the two non-authors (`gh pr review N --approve`, run by S1 and S2; the author @ahklsfg cannot approve). Record `reviewDecision`.

### §1 Prove the gates, then enforce (D9)

```bash
scripts/gate-selftest.sh all     # every line ✓; "NOT caught: 0   skipped: 0"
gh variable set ENFORCE_GATES --repo "$REPO" --body true && gh variable list --repo "$REPO"
```

Fallback if the self-test cannot complete: skip this step, merge fail-open, and come back to it in §4 (D9).

### §2 Merge loop (#1 to #4, then #PF)

For `N` in 1, 2, 3, 4, with `NEXT` = 2, 3, 4, `$PF`:

```bash
SHA=$(gh pr view "$N" --json headRefOid --jq .headRefOid)
gh pr checks "$N" --watch --fail-fast
gh pr merge "$N" --merge --match-head-commit "$SHA" --subject "Merge PR #$N from $(gh pr view "$N" --json headRefName --jq .headRefName)"
# no --delete-branch: it is NEXT's base until NEXT is retargeted
gh pr edit "$NEXT" --base main
gh pr update-branch "$NEXT"          # REST: gh api -X PUT repos/$REPO/pulls/$NEXT/update-branch -f expected_head_sha=<head>
sleep 30; gh pr checks "$NEXT" --watch --fail-fast   # loop until checks for the NEW head appear (race)
```

- **Why update-branch:** a base change triggers no CI (F27), and a re-run would test the old merge ref [verify]. Update-branch adds a "Merge branch 'main'" commit, so a `synchronize` event runs CI against `main`. It also satisfies `strict` later.
- **On a conflict** (none expected, F1): `git fetch origin && git switch <branch> && git merge origin/main`, resolve, push, re-check. Never force-push. Never `--admin`.
- **On an enforced gate red after update:** fix on that branch (a new commit), re-check, then continue.
- Finally merge `$PF` the same way.

### §3 Verify `main`, then clean up

```bash
git fetch origin
for s in b28c75d 7d6c677 247643a 9adc96d <PF-head>; do git merge-base --is-ancestor "$s" origin/main && echo "ok $s"; done
gh run list --branch main --workflow ci.yml --limit 5; gh run watch <id>   # push run on main: all gates green; image push step skipped until the ECR variables exist
for n in 1 2 3 4 "$PF"; do gh pr view "$n" --json state,mergedAt; done
for b in feat/s3-soar-playbooks feat/s3-detection-athena-sims feat/s1-s2-edge-identity-waf feat/s2-app-soc-ui-grc feat/depi-phase-f-capstone-complete; do gh api -X DELETE "repos/$REPO/git/refs/heads/$b"; done
```

### §4 Branch protection (D10)

- The JSON payload with the 7 exact `context` names (F4), `strict: true`, 2 approvals, code owners, `dismiss_stale_reviews`, `enforce_admins: true`, `required_conversation_resolution: true`, no force pushes or deletions, and optionally `"app_id": 15368` per check [verify].
- Apply with `gh api -X PUT repos/$REPO/branches/main/protection --input <file>`; read it back with `gh api …/protection --jq '.required_status_checks.checks[].context'`.
- Explain why DAST, `terraform plan` and `app-smoke` are not required.
- Explain the code-owner semantics and the D11 change.
- Explain that `strict` forces "update branch" on every PR from now on.

### §5 Post-cutover checks

- A no-op docs PR from a non-admin must show all 7 checks and "Review required".
- `ENFORCE_GATES` reads `true`.
- Optional annotated tag for the submission snapshot: `git tag -a capstone-2026-fall -m "DEPI capstone submission" <main-sha> && git push origin capstone-2026-fall`.

### §6 Rollback

- Revert a bad merge through a PR: `git revert -m 1 <merge-sha>`. Never rewrite `main`.
- Unset `ENFORCE_GATES` only with a written reason.

### §7 Status

- Whether each item is done, and by whom (a table S1 fills in).
- Links: `repo-admin-setup.md` (updated: soar added to the required list; protection timing points here).

---

## 5. Small code changes (Stage 1)

### 5.1 Readiness pack (D12): S2

- **New `app/spa/src/grc/readinessPack.ts`:**
  - pure `buildReadinessPackMarkdown(assessment, ruleset, tenantId, exportedAt)` and `buildReadinessPackJson(…)`;
  - `mdCell()` escaping: `\` and `|` escaped; CR/LF to a space; `<`, `>` and `&` to entities, so pasted output can never become HTML; length capped;
  - `downloadText(text, mime, filename)` (Blob → object URL → `<a download>` → revoke, as in `EvidencePanel`);
  - filename `cloudshield-grc-readiness-<tenant>-<rulesetVersion>.<md|json>`, sanitised to `[A-Za-z0-9._-]`.
- **`app/spa/src/grc/GrcHub.tsx`:** two buttons inside the Summary card, rendered only when `assessment && ruleset` exist; errors go to `ErrorBox`. No new API call, no `localStorage`, no inline style (the CSP and the ESLint rules).
- **Tests (new `app/spa/src/grc/readinessPack.test.ts` plus additions to `grc.test.tsx`):**
  - the disclaimer and the "Not an audit" banner are always present;
  - every `verify` finding carries the VERIFY marker and `doc` findings do not;
  - NOT_APPLICABLE rows are excluded from the tables but counted in the summary;
  - the provenance fields are present;
  - `|`, newlines and `<script>` in a fixture obligation are escaped;
  - the JSON round-trips to the assessment plus `exportMeta`;
  - the filename is sanitised;
  - the buttons are absent for member (no `grc:assess`) and before the assessment loads;
  - a click calls `createObjectURL` with the right MIME and filename, then `revokeObjectURL`.
- Coverage stays ≥ the Vitest thresholds. No OpenAPI change, so no type drift.

### 5.2 Terraform (D13): S1, with S3 review

- `environments/dev/variables.tf` (+ validation), `main.tf` (`evidence_object_lock_days = var.evidence_object_lock_days` in `module "soar"`), `terraform.tfvars.example` (commented line).
- `validate`, the soar module tests (which already cover the lock configuration) and Checkov stay green.

### 5.3 Wording and governance: S1

- README (D14 + the D10 check list + the verify-all row + the new flag row).
- Makefile comment (D14).
- `soar/sims/README.md` code-block comment (D14). It is an S3 path, but PR #PF is reviewed before protection exists.
- `ci.yml` step label (D2).
- `.github/CODEOWNERS` (D11, if Q1 holds).
- `docs/runbooks/repo-admin-setup.md` §3: add `gate: soar (ruff + pytest)`; point to the cutover runbook for timing.
- `docs/runbooks/edge-waf-demo.md`: workgroup name taken from `terraform output -raw athena_workgroup` (F19).

---

## 6. Part 2: reports

### 6.1 Common rules (every chapter)

- **Front matter:** title; chapter number; version; date; status (DRAFT or FINAL); owner(s); reviewers; the "Sources and marks" legend; a "What is measured vs pending" box.
- **Format:** Markdown that renders on GitHub. Numbered sections. Tables for every comparison. **Mermaid** only in GitHub-supported types: `flowchart`, `sequenceDiagram`, `stateDiagram-v2`, `erDiagram`, `gantt`. No C4 and no beta types.
- **UML use-case** diagrams are drawn as a `flowchart` with actor nodes and stadium-shaped use cases inside subgraph system boundaries; the caption says "UML use-case notation approximated in Mermaid".
- **Length targets** (words, excluding tables and code): 01 ≈ 2–3k; 02 ≈ 3–4k; 03 ≈ 4–6k; 04 ≈ 3–4k; 05 ≈ 3–5k; 06 ≈ 4–6k; 07 ≈ 4–6k [inferred: adjust to the rubric once it is available].
- **Citation forms:**
  - repo facts: `[repo: path §/line]`;
  - CI: `[CI: run <id>, PR #n, <sha>]`;
  - local measurements: `[local: verify-all <date>, <sha>, <env>]`;
  - prior records: `[HANDOFF §13]`;
  - external: `[L<n>]` (the `L` prefix avoids a clash with risk ids R1–R7), defined in that chapter's references list.
- **Numbers rule:** a number without a citation is not allowed. AWS behaviour that was not observed is stated as design intent ("is designed to", "the target is"). The words **"measured on AWS"** may appear only next to an M3 or M4 row (§7.2), and none exist yet.
- **Fixed wording** (grep-checked by the Auditor):
  - "insert-only by convention", never "immutable" or "append-only" for the audit table;
  - "tenant isolation is enforced in the API, not by IAM or cryptography (the SSE-KMS context is the bucket ARN under S3 Bucket Keys)";
  - "single AWS account (ADR-0001); the multi-account design is the target state";
  - "DynamoDB only; the data model shows a logical view of item types, not relational tables";
  - "automated containment with human-gated eradication";
  - "Object Lock is off by default (`evidence_object_lock_days = 0`)";
  - the audit stream consumer "is a follow-up".
- **Placeholders** for pending data are visible tables with `PENDING (first lab apply)` cells and the exact command that fills each one.

### 6.2 What can be honoured from repo content

| Item | Honoured from | Otherwise |
|---|---|---|
| Figure 7.1 (TB0–TB5) | README trust-boundary table; ADR-0002 §1 | "Redrawn from the README table, which was itself read from Figure 7.1; fidelity [source: plan PDF, not in repo — team to verify]" |
| §2.2 RACI | CODEOWNERS header, the README team table, ADR "Deciders" | Present as "RACI derived from repo ownership"; the original matrix [source: plan PDF] |
| §4.2 accounts; §4.3–4.4 ingress, container, subnets | ADR-0001, ADR-0002 §4, `app/README.md`, the network module | — |
| §5 / Figure 5.1 pipeline | The `ci.yml` header | — |
| §6.2–6.5 / Figure 6.5 SOAR, PB-01 | `soar/README.md`, ADR-0003 | — |
| §7 attack sims; §8.4, §8.6 class model, §8.8 SOC | `soar/sims/README.md`, `soar/core/*`, ADR-0006 | — |
| KPI §2.4; success criterion 06; FR-2/3/4/5/8 | README, `.zap/rules.tsv`, `generate_ir_report.py`, the Phase E plan | FR-2/3/4 numbering is [inferred] in the repo itself; say so |
| R1–R6 | HANDOFF, ADR-0001, bootstrap, `soar/variables.tf`, sims | Ratings other than R1 = H×H: [source: plan PDF] |
| **R7, FR-1, FR-6, FR-7, plan §1.1 content, DEPI rubric criteria, WBS Chapter 7 structure** | Nothing in the repo | `[source: plan PDF, not in repo — team to verify]` rows with an empty "content" cell for the team. Each chapter has a "Rubric mapping" table with the same marker. |

### 6.3 Chapter outlines and sources (Builder: write these sections in order)

**01 Project charter and management.** Sources: HANDOFF §1–§13; README (team, costs, next steps); CODEOWNERS; ADR-0001, ADR-0002; `bootstrap/main.tf` (budget alarms 50 / 100 / forecast 100, the R3 comments); `git log --date=short`; PR list (F1).
1. Document control.
2. Executive summary: the two loops, and what is built and audited vs not applied.
3. Charter: purpose; objectives tied to KPIs (MTTC < 60 s target, KPI §2.4, Checkov 0 failed, FR-5 enforcement); scope in and out (in: single account in us-east-1, PB-01..05, local stack; out: multi-account, multi-region, automated eradication, legal advice); FR table (§6.2 rule); constraints (G1 waiver unresolved and still the top risk, G2 account model, G4 budget).
4. Team, roles, RACI (derived).
5. Delivery approach: the per-phase pipeline Planner → Builder → Independent Auditor → Validator; the phase table A–F with branch, PR and date; a Mermaid `gantt` with **real commit dates only**; the WBS mapping placeholder.
6. Governance: ADRs; reviews (2 approvals, code-owner semantics); gates; a table of the independent audit outcomes per phase:
   - scaffold: PASS WITH FIXES, 10 major / 10 minor;
   - SOAR: 3 major / 9 minor;
   - Phase C: 1 major / 5 minor;
   - Phase D: FAIL → fixed, 2 major / 9 minor;
   - Phase E: 0 critical / 0 high / 2 medium / 8 low / 2 info;
   - all from HANDOFF.
7. Risk register R1–R7 (ID, risk, likelihood × impact, owner, mitigation in the repo, status, source) plus a register of risks found during delivery (gaps 2, 10, 11, 15, 16; nothing applied; Semgrep platform; open legal verify items; PB-05 shared egress; DNS-channel exfiltration after quarantine).
8. Cost model:
   - method: the Terraform resource inventory per flag times AWS public list prices [verify; record the pricing page and access date];
   - a baseline table (NAT gateway; 5 KMS keys; CloudTrail incl. data events; Config S3-only; GuardDuty after the trial; logs and S3);
   - a per-flag delta table (edge ≈ $20/month; report worker; Runtime Monitoring paid; interface endpoints ≈ $100/month avoided);
   - a lab-session estimate per day for the demo, marked [inferred];
   - cost controls (budgets, destroy when idle, flags off, Athena 1 GiB cap).
9. Communication and tooling.
10. Open items: G1, G4, the first apply, legal verify items, filling chapter 07.

**02 Literature review and benchmarking.** Sources: §6.4; README; ADR-0002 §3; ADR-0005; `soar/README.md`.
1. Method: inclusion criteria (standards bodies, primary vendor docs); `[verify]` policy; access dates.
2. DevSecOps foundations: SSDF, SP 800-204C, the OWASP DevSecOps Guideline, OWASP Top 10, SLSA, SBOM (CycloneDX), the CIS AWS Foundations Benchmark.
3. Incident response and forensics: SP 800-61 (r2 lifecycle, r3 CSF 2.0 profile), the AWS Security Incident Response Guide, SP 800-86, ISO/IEC 27037 / 27035 [verify], MITRE ATT&CK with the repo's technique ids.
4. Cloud security architecture: the Well-Architected Security Pillar; the AWS Security Reference Architecture (multi-account target); shared responsibility.
5. Benchmarking:
   - (a) vs a single-loop DevOps pipeline: a capability table (build-time gates only vs CloudShield's two loops and their links: the posture banner shows build gates; the image is pushed only when the gates pass; PB-04 redeploys by digest; the PB-03 IR report's IaC snippet feeds back into Terraform);
   - (b) vs commercial SOAR platforms (Splunk SOAR, Palo Alto Cortex XSOAR, Microsoft Sentinel automation/playbooks, Google Security Operations SOAR), qualitative only: deployment model, playbook authoring, guardrails, case management, evidence handling, multi-cloud, licensing model "commercial" with no prices;
   - (c) vs AWS samples and solutions ("Automated Security Response on AWS", "Automated Forensic Orchestrator for Amazon EC2", aws-samples incident-response playbooks, the AWS Security Incident Response service), names and status [verify]. What CloudShield adds: a fail-closed guard double-bound by scope tag and IAM; verify-before-contained; an explicit MTTC clock; evidence after containment; a notify-only decoy; the GRC hub. What it lacks: case management, enrichment, multi-account, scale testing.
6. Gap statement → design goals.
7. References `[L1]…`.

**03 System analysis and architecture.** Sources: README; ADR-0001…0006; `modules/network/variables.tf` and SG/NACL files; `modules/data/main.tf`; `modules/soar/{main,state-machine,edge-bus}.tf`; `modules/edge/*`; `app/openapi.yaml`; `docs/plans/*`.
1. Context, stakeholders and actors.
2. Requirements: FR table (§6.2); NFRs (MTTC target, cost, security, operability); a **traceability matrix** FR → module/code → test suite → evidence.
3. UML use-case model (Mermaid; boundaries: Portal, SOC, GRC, Pipeline, SOAR).
4. Architecture and trust boundaries: a TB0–TB5 table with columns "implemented in (single account)" and "target account"; a Mermaid component diagram with one subgraph per TB and every boundary-crossing flow labelled (protocol, authn).
5. VPC: `10.20.0.0/16`, 2 AZs; public `10.20.0.0/24`, `.1.0/24`; app `.10.0/24`, `.11.0/24`; worker `.20.0/24`, `.21.0/24` (dedicated NACL); forensics `10.20.99.0/26`; one NAT; S3 and DynamoDB gateway endpoints; interface endpoints off; flow logs as Parquet; SGs incl. quarantine; internal NLB + REST VPC Link.
6. Component and module map (ADR-0002 §1) and the feature-flag table.
7. Data model: an `erDiagram` titled "Logical view of DynamoDB item types (no joins, no foreign keys)"; the key design; access patterns; S3 key layouts (`tenants/<t>/docs/<id>`, `incidents/<id>/…`); the KMS keys and the FR-3 statement.
8. Sequences (`sequenceDiagram`): an authenticated document download through the edge; finding → router → guard → playbook → `MarkContained` → evidence; a decoy hit (notify-only).
9. `stateDiagram-v2` of `cs-ir-router` (state names from `state-machine.tf`).
10. Multi-account target (ADR-0001) and what one account loses.
11. ADR summary table.
12. Known limits (ADR-0002 §5).

**04 DevSecOps pipeline.** Sources: `ci.yml`; `scripts/gate-selftest.sh`; `.zap/rules.tsv`; `.github/{dependabot.yml,CODEOWNERS}`; `bootstrap/main.tf` (OIDC plan role); `modules/compute/ci-push.tf`; the Dockerfiles; `.hadolint.yaml`; `repo-admin-setup.md`; the cutover runbook; HANDOFF §5, §10–§13.
1. Overview: a job table (order, tool and version, threshold, hard vs fail-open, artefacts).
2. Gate by gate:
   - **secrets:** full history; the allow-list caveat;
   - **SAST:** packs, ERROR severity, excludes;
   - **SCA:** fixable CRITICAL; skips `infra/`;
   - **IaC:** fmt / validate / test always hard; Checkov fails on any check; the skip-with-reason policy;
   - **soar / app correctness gates;**
   - **image:** fixable CRITICAL/HIGH; SBOM artefact kept 90 days;
   - **DAST:** passive, FAIL rules, main plus `STAGING_URL` only.
3. Fail-open → enforced: the real-outcome outputs; push only when every scan succeeded.
4. Proving the gates trip: the seed table; proven vs not proven.
5. CI identity: OIDC; the plan role (read-only, its sub patterns); the ECR push role (exact `main` sub; `id-token: write` on that job only); no long-lived keys; the `job_workflow_ref` follow-up.
6. Supply chain: SHA-pinned actions; Dependabot; exact versions and lockfiles; `--ignore-scripts`; digest-pinned images; ECR immutable + scan-on-push; deploy by digest; a SLSA self-assessment [inferred, not certified].
7. Container hardening: distroless `nodejs24-debian13:nonroot`; 1000:1000; read-only rootfs; `/tmp` only; `cap_drop ALL`; no-new-privileges (compose); hadolint; Checkov dockerfile; the build-info gate outcomes; the task-definition env filter.
8. Local shift-left: pre-commit, Makefile targets, `make verify-all`.
9. Branch protection and review (D10, D11).
10. Evidence: the CI runs per PR (F2) and the verify-all summary.
11. Limitations: the Semgrep packs; ZAP is passive; no Checkov severity data; the plan role uses `ReadOnlyAccess`; no apply role (gap 9); the fail-open window.

**05 Secure application and identity.** Sources: `app/README.md`; `app/openapi.yaml`; `app/docs-api/src/{auth,documents,audit,decoy,soc,grc,middleware,config.ts}`; `app/spa/src/**`; `app/grc/**`; ADR-0004; ADR-0006; `modules/{identity,data,edge}`; the tenant-provisioning, decoy-route, spa-deploy and local-dev runbooks; the test suites.
1. Overview and a threat model per boundary (a qualitative STRIDE table for TB1–TB3).
2. Identity:
   - **Cognito configuration:** TOTP, admin-create, 14-character passwords, 4 groups, immutable `custom:tenant_id`;
   - **token contract:** re-verification of signature, `iss`, `aud` and `token_use`; the authorizer `aud` gap [inferred];
   - **SPA session:** SRP with tokens in `sessionStorage`.
3. Authorisation: an RBAC table from `principal.ts`; ABAC owner checks; cross-tenant answers 404.
4. **FR-2 tenant isolation:** enforced in the API from the token; the IDOR tests and smoke check 3; not IAM-enforced; the `LeadingKeys` stretch goal.
5. **FR-3:** the CMKs; the bucket-policy denies; Bucket Keys, so the context is the bucket ARN and isolation is not cryptographic; version-pinned pre-signed downloads ≤ 300 s; uploads through the API with SHA-256 and magic bytes.
6. **FR-4:** the audit schema; conditional writes; no Update/Delete IAM; stream; PITR; one transaction for the change and its event; "insert-only by convention"; the stream consumer is a follow-up.
7. Edge (built, not applied): WAF rules, the origin-verify deterrent, CSP, no `custom_error_response`.
8. Decoy (notify-only) and its residual risks.
9. SOC read model and posture honesty.
10. GRC hub:
    - rules as data; DSL safety; the status set; residency GAP by construction;
    - verify badges; click-through agreements are logging, not e-signatures;
    - the **readiness pack** (D12, incl. "not audited, not signed");
    - the open legal verify list.
11. Local-mode safety.
12. Verification evidence and the verify-on-first-apply list.

**06 Detection telemetry and SOAR engine.** Sources: `modules/{detection,log-archive,soar}`; `detection/athena-queries/*.sql`; `soar/README.md`; `soar/core/*`; `soar/playbooks/*`; `route_choices.json`; ADR-0002 §3, ADR-0003, ADR-0005; `soar/sims/README.md`; `generate_ir_report.py`; `app/docs-api/src/soc/{metrics,time,evidence}.ts`.
1. Telemetry sources and log archive: delivery policies; Object Lock optional.
2. Hunting: Glue with partition projection; the Athena workgroup with its 1 GiB cap; the 4 queries and their purpose; tested only statically.
3. SOAR architecture: the EventBridge rules (GuardDuty, edge bus); the router; dedupe and re-runs; the fail-closed contract.
4. Safety guard (R2): rules 1–5 and the ECS/IP variants; the IAM double bound (scope-tag conditions, permissions boundary).
5. A PB-01…PB-05 table: trigger, actions, the "contained" verification, the evidence step, what is not covered.
6. Automation boundary: it stops at CONTAINED; the sweeper is expiry, not recovery; eradication runbooks.
7. **MTTC:** the §7.2 definition, classes, statistics, validity threats, and a status table.
8. Evidence and chain of custody: canonical JSON; S3 SHA-256 checksums; the hash on the row; append-only `evidenceRecords`; version pinning; recompute with exit 2; TS/Python parity through the golden fixtures; Object Lock off by default with the D13 pass-through.
9. IR report, ChatOps and the LLM hook (off by default).
10. Limits and follow-ups (DNS channel, PB-04 no eradication, shared egress, bus-policy trust, decoy corroboration, audit-stream consumer).

**07 Verification, attack simulations and QA.** Sources: the verify-all summary (Part 4), CI runs (F2 + PR #PF), HANDOFF §5, §10–§13, the test suites, `soar/sims/*`, `coc_golden.json`, the seed, ADR-0004 §9, ADR-0005 and ADR-0006 verify lists. Detail in §7.3.

### 6.4 Approved external sources (all `[verify]` for edition, date and URL; access date recorded)

- NIST SP 800-61 Rev. 2 (2012) and Rev. 3 (2025, CSF 2.0 community profile).
- NIST SP 800-218 (SSDF v1.1).
- NIST SP 800-204C (DevSecOps for microservices with a service mesh).
- NIST SP 800-190 (containers).
- NIST SP 800-86 (forensics in IR).
- NIST CSF 2.0.
- OWASP Top 10 (2021; check whether a newer edition is final).
- OWASP DevSecOps Guideline; OWASP ASVS.
- MITRE ATT&CK Enterprise (Cloud / IaaS matrix; record the version).
- AWS Security Incident Response Guide (whitepaper).
- AWS Well-Architected Framework, Security Pillar.
- AWS Security Reference Architecture.
- SLSA v1.0 (or v1.1).
- CycloneDX specification (ECMA-424).
- CIS Amazon Web Services Foundations Benchmark (v3.0.0 is the version the repo's Security Hub flag names).
- ISO/IEC 27035 and 27037.
- Forsgren, Humble and Kim, *Accelerate* (2018); Kim et al., *The DevOps Handbook* (2nd ed.).

The Builder checks each link resolves (`curl -sI`). If it cannot be checked from the sandbox, the entry keeps `[verify: link not checked]`. **Nothing outside this list without the same treatment. No statistics quoted from any source.**

---

## 7. Evidence inventory, MTTC and how chapter 07 presents results

### 7.1 What exists

| Evidence | Class | Where |
|---|---|---|
| CI runs on #1–#4 (and #PF), scan steps really passed | CI | F2 run ids |
| pytest + coverage, Jest, Vitest, local-dev Jest, terraform test/validate/fmt, Checkov, Gitleaks, actionlint, hadolint | local-measured / CI | verify-all (Part 4), HANDOFF §13 |
| `make local-smoke` 8/8 | local-measured / CI `app-smoke` | verify-all, run `38984704551` |
| Replay-local A/B/C → CONTAINED; D/E → WOULD_CONTAIN_DRY_RUN; safety-gate refusals | CI (pytest under moto) | `soar/tests/test_sims.py` |
| Golden chain-of-custody cases (intact, tampered, missing, base64 mismatch, versioned, not contained) with Python/TS parity | synthetic oracle | `coc_golden.json`, `test_ir_golden.py`, docs-api SOC tests |
| Seeded SOC incidents (incl. C BROKEN) | seeded demo data | `app/local-dev/src/seed.ts` |
| Gate self-test: secrets and IaC proven; SAST, SCA, image and DAST not yet | local | HANDOFF §5; Part 4 may extend |
| **Anything on AWS:** GuardDuty, Step Functions, Lambda, Athena, Object Lock, WAF, MTTC | **pending first apply** | — |

### 7.2 MTTC: the rigorous definition (chapters 06 and 07, the deck, the demo)

- **Per run r:**
  - `MTTC(r) = containedAt(r) − eventTime(r)`, in seconds, defined **only** when the run ends `CONTAINED`;
  - `eventTime(r)` is the `time` of the EventBridge event that started run r (written by `RecordDetected`; `firstEventTime` and `findingCreatedAt` keep the first sighting);
  - `containedAt(r)` is `$$.State.EnteredTime` of `MarkContained`, entered only after the playbook returns boolean `contained: true` from a read-back verification.
- **Excluded by design:** attacker action → GuardDuty detection; GuardDuty `createdAt` → EventBridge delivery (stored for audit, reported separately as detection latency); evidence capture after CONTAINED; dry-run runs (`WOULD_CONTAIN_DRY_RUN`). `BLOCKED_BY_GUARD`, `FAILED` and `NO_PLAYBOOK` have no MTTC; they are reported as counts and a containment rate.
- **KPI:** each graded scenario run must have `MTTC < 60 s` (as `sims.runner` asserts). Over a window, report n, median (p50), p90 and max, using the **nearest-rank** percentile as `metrics.ts` does. Never a mean alone.
- **Validity threats:**
  - whole-second resolution of the EventBridge `time` (≈ ±1 s) [inferred];
  - `replay-aws` stamps `time` on the operator's clock and skips the EventBridge hop (NTP sync required; the result is labelled "router MTTC, synthetic detection");
  - cold starts (the first run after deploy is reported separately);
  - small n.
- **Measurement classes:**

| Class | What it measures | Exists? |
|---|---|---|
| M0 synthetic oracle | Golden fixture 18.0 s | Yes, but a test oracle, **never** reported as a result |
| M1 seeded | Local demo data (9–40 s, F15) | Yes; **always** labelled "seeded" |
| M2 replay-local | In-process logic under moto; reports test durations, **not MTTC** | Yes |
| M3 replay-aws | Real router, Lambdas and AWS APIs, synthetic detection (D4) | **Pending first apply** |
| M4 live-aws | End to end incl. GuardDuty | **Pending first apply** |

### 7.3 Chapter 07 structure

1. Verification strategy (pyramid: static gates → unit and mocked → moto integration → contract tests → local end-to-end → offline Terraform tests → independent audits → live, pending).
2. Evidence-class legend (§7.1, §7.2).
3. **Results, measured:** one table per domain with numbers and their source, from the Part 4 verify-all run (commit, date, environment, every tool version incl. WARNs) and the PR #PF CI run; HANDOFF §13 figures only as "previous record".
4. Independent audits summary.
5. Attack simulations A–E:
   - design: ATT&CK ids; the R4 gates; a mode availability matrix (replay-local ✓ CI; replay-aws and live-aws pending; D/E replay-local only, by design);
   - offline results: test name → status;
   - **lab placeholder table:** scenario, mode, dry-run, date, commit, incident id, status, eventTime, containedAt, MTTC (s), < 60 s?, evidence intact?, IR report file, operator; every cell `PENDING (first lab apply)`, with the exact `make sim …` command per row.
6. MTTC results: the class table; an "M3/M4: none yet" statement; the placeholder.
7. QA:
   - functional (smoke, 8 checks);
   - security (the IDOR, injection, RBAC-matrix and decoy suites; gate self-test status);
   - DAST (pending `STAGING_URL`);
   - edge QA (`edge-waf-demo.md`, pending).
8. **Chain-of-custody report:** method; golden cases and parity; a sample IR report excerpt **generated from the seeded local stack**, labelled as such; the offline `make ir-report` result if step 0 confirms it (exit 2 on C, 0 on A); an AWS placeholder (intact chain + Object Lock retention + refused delete).
9. A consolidated verify-on-first-apply list with a status column.
10. Threats to validity (what moto does not enforce; sandbox vs CI; seeded data; the Semgrep platform).
11. Appendices: A, the verify-all summary output; B, CI run links; C, how to fill each placeholder.

---

## 8. Part 3: live demo runbook and deck

### 8.1 `docs/runbooks/live-demo-runbook.md` structure

- **§0 Rules:**
  - R4: our own resources only;
  - no real secret ever (seeds are built at runtime);
  - dry-run stays on except during act 4's window on the AWS track;
  - wording: say "seeded", "replayed", "pending"; "automated containment with human-gated eradication"; the pack is "a self-assessment, not an audit";
  - no number without its class.
- **§1 Track decision at T-24h:**
  - **AWS lab track** only if the lab was applied with the flags below and acts 4–5 were rehearsed end to end at least once;
  - otherwise the **offline track** (default);
  - acts 1–3 are the same on both tracks (acts 2–3 always use the local stack running the production image; say so).
- **§2 Prerequisites:**
  - **laptop:** Docker + Compose ≥ 2.20, Node 24, Python 3.13 + `soar/requirements-dev.txt`, `gh`, a browser, repo at the submission tag;
  - **offline:** images pre-built (`make local-up` at T-60, because the first build pulls images);
  - **AWS:**
    - bootstrap and dev applied with `enable_lab_targets = true`, `soar_playbook_package` set, `soar_dry_run = true` at rest, `evidence_object_lock_days = 1` **set before the first apply** (D13; blocks deleting locked versions for 1 day; GOVERNANCE), and `enable_report_worker = true` only if scenario A is used;
    - `enable_edge` off unless needed (≈ $20/month);
    - GuardDuty and CloudTrail via `detection`;
    - short-lived credentials (SSO);
    - the cost note from chapter 01 §8;
    - budgets confirmed.
- **§3 Checklists:**
  - **T-24h:** a rehearsal run and screen recordings of every act as fallback.
  - **T-60:** `make local-up && make local-smoke` (8/8); open the demo PR with the CKV_AWS_24 seed on branch `demo/shift-left-<date>` (`infra/terraform/demo-seed/main.tf`, fmt-clean, outside the validate loop) and confirm `gate: iac` is red under enforcement and the merge box is blocked; open the browser tabs.
  - **AWS track, T-30:** run scenario C once (`make sim SCENARIO=c MODE=replay TARGET=aws ACCOUNT=… SIM_ARGS="--state-machine-arn $(terraform output -raw soar_state_machine_arn) --bucket-name <lab bucket>"`) with dry-run off, then back on, so CloudTrail has delivered for act 5's query.
  - **T-5:** `NO_COLOR` unset; terminal font size; Wi-Fi off test for the offline track.
- **§4 Minute by minute (15:00):**

| Time | Act | Speaker | Steps (exact) | Expected | Fallback |
|---|---|---|---|---|---|
| 00:00–02:00 | **1 Shift-left block** | S1 | `scripts/gate-selftest.sh secrets` (✓ tripped; the seed was generated in a temp dir and deleted). Show the demo PR: the red `gate: iac`, the Checkov CKV_AWS_24 annotation, "Merging is blocked". Mention `ENFORCE_GATES=true` and the 7 required checks. | ✓ line; red check | Screenshot / recording |
| 02:00–05:00 | **2 Multi-tenant + GRC** | S2 | `http://localhost:3000`: alice lists Acme docs; mallory opens an Acme doc id → 404 (IDOR); dina's onboarding shows writes blocked (`AGREEMENT_REQUIRED`); dina → GRC hub → the assessment (EG-PDPL / EG-CBE; residency GAP explained) → **Download readiness pack (Markdown)** → open the file: banner, disclaimer, VERIFY markers, ruleset SHA-256. | 404; pack downloaded | `make local-smoke` check 3; a pre-exported pack file |
| 05:00–07:00 | **3 Decoy trap** | S2 + S3 | `curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3000/api/admin/backup` → 403 (same as any denial). Run `make local-smoke` checks 4a–4c (audit row + `DecoyRouteHit` on the local bus). Sam's SOC shows the seeded decoy incident `BLOCKED_BY_GUARD`, notify-only. Explain why it never blocks. | 403; 4a–4c ✓ | Smoke output recording |
| 07:00–12:00 | **4 Automated IR (containment)** | S3 | **Offline:** `cd soar && python -m pytest tests/test_sims.py -k "replay_local_scenario_c_contains or replay_local_scenario_a_contains" -s -v` → the JSON shows `"status": "CONTAINED"`, the playbook and the verified containment fields. Say: "in-process router against moto; this proves the logic, it is not MTTC". Then the SOC MTTC gauge, **called seeded**.<br>**AWS:** flip dry-run off (`aws ssm put-parameter --name $(terraform output -raw soar_dry_run_parameter) --value false --overwrite`; next `terraform apply` restores the configured value); run scenario C replay-aws; show the Step Functions execution graph, the incident row, the printed `mttc_seconds` and the `< 60 s` verdict (M3: synthetic detection, real containment); **immediately set dry-run back to `true`**. | CONTAINED | Offline track; recording |
| 12:00–15:00 | **5 Forensics** | S3 | **Offline:** SOC → incident A → Verify evidence: intact, SHA-256 shown; incident C: **BROKEN**; download the IR report (Markdown); optional (if step 0 confirmed it) `AWS_ENDPOINT_URL=http://127.0.0.1:5000 AWS_ACCESS_KEY_ID=local-only AWS_SECRET_ACCESS_KEY=local-only AWS_REGION=us-east-1 make ir-report INCIDENT=local-c-public-bucket NAME=cloudshield-local; echo $?` → 2. Show `03_s3_public_exposure_audit.sql` and explain partition filtering and the 1 GiB cap.<br>**AWS:** run hunt query 03 in workgroup `$(terraform output -raw athena_workgroup)`; `make ir-report INCIDENT=<id>` → intact, exit 0; `aws s3api get-object-retention …` → GOVERNANCE until …; `aws s3api delete-object --version-id …` → AccessDenied (never pass a bypass flag). | BROKEN / intact; exit codes | Recordings |

- **§5 Full offline fallback** via `docker-compose.local.yml`: the same acts, no network needed after build [inferred: confirm with Wi-Fi off at T-24h].
- **§6 Afterwards:** close the demo PR and delete its branch; confirm dry-run is `true`; on scenario A, run the ADR-0003 recovery (NACL entries, SG restore, inline policy) and `sims cleanup --yes`; check BPA is restored; `make local-down`; `terraform destroy` (locked evidence versions persist until retention ends; plan teardown a day later); check budgets.
- **§7 Q&A crib** with honest answers: "Is it autonomous?"; "Is MTTC measured on AWS?"; "Is the audit immutable?"; "Is tenant isolation cryptographic?"; "Why one account?"; "Is the GRC output legal advice?"; "What does PB-01 not block?" (DNS, IMDS).

### 8.2 Feasibility notes recorded in the runbook

- `make ir-report` and `make sim TARGET=aws` need AWS (except the step-0 moto variant).
- Step Functions, Athena and Object Lock exist only on the lab track.
- GuardDuty live findings (M4) take minutes [inferred], so live-aws is never done in a 5-minute slot; show a pre-run recording if one exists.

### 8.3 `docs/presentation/deck-outline.md` (20 slides)

Each row gives: title, one-sentence takeaway, visual, 3 talking points, speaker, and the source chapter.

1. Title and team (all)
2. The problem and our takeaway: two loops (S1)
3. Honest status: built, audited, not yet applied (S1)
4. Architecture TB0–TB5 (S1)
5. One account now, multi-account target (S1)
6. Six gates, fail-open → enforced (S1)
7. Supply chain and OIDC (S1)
8. Demo act 1 (S1)
9. Identity and the token contract (S2)
10. Tenant isolation FR-2, KMS FR-3 (bucket-ARN context), audit FR-4 (insert-only by convention) (S2)
11. Demo act 2, incl. the readiness pack (S2)
12. Decoy (notify-only) + demo act 3 (S2/S3)
13. Detection telemetry and hunting (S3)
14. SOAR router and safety guard (S3)
15. PB-01…PB-05 and what "contained" means (S3)
16. MTTC: definition and measured vs pending (S3)
17. Demo act 4 (S3)
18. Chain of custody + demo act 5 (S3)
19. Verification and QA results (all)
20. Risks R1–R7, limits, future work, Q&A (all)

---

## 9. Builder stages (sequential, disjoint files)

**Step 0** (before Stage 1; record outcomes in HANDOFF §14 "Deviations"):
1. `cd soar && python -m pytest --cov` passes and shows `TOTAL … ≥ 95 %`.
2. The compose moto plus `make ir-report` via `AWS_ENDPOINT_URL` gives exit 2 for `local-c-public-bucket` and 0 for `local-a-cred-exfil`. If not, drop the D19 option.
3. Pin the actionlint and shellcheck Docker images (tag + digest).
4. Sandbox Terraform provider mirror from releases.hashicorp.com, outside the repo, via `TF_CLI_CONFIG_FILE` (F12).
5. Checkov `-d app --framework dockerfile` with `node_modules` present gives the same counts as CI. Otherwise add `--skip-path node_modules` in verify-all only and note it.
6. A Mermaid CLI Docker image for parsing diagrams [verify name and tag].
7. Whether `gate-selftest.sh sast` trips in the sandbox (informational for chapter 04 and 07).
8. The Blob download under the local nginx CSP (rehearsal, headless browser if available).

**Stage 1: verify-all, merge runbook, small code (S1 lead; S2 for the SPA; S3 review)**
- New: `scripts/verify-all.sh`, `docs/runbooks/final-merge-and-cutover.md`, `app/spa/src/grc/readinessPack.ts`, `app/spa/src/grc/readinessPack.test.ts`.
- Edit: `Makefile`; `app/spa/src/grc/GrcHub.tsx`; `app/spa/src/grc/grc.test.tsx`; `infra/terraform/environments/dev/{variables.tf,main.tf,terraform.tfvars.example}`; `.github/workflows/ci.yml` (label only); `.github/CODEOWNERS` (D11 / Q1); `README.md`; `docs/runbooks/repo-admin-setup.md`; `docs/runbooks/edge-waf-demo.md` (workgroup output); `soar/sims/README.md` (comment only).
- Exit: verify-all green in the sandbox (or every non-green domain explained as sandbox-only, §12); shellcheck clean; Vitest thresholds met; terraform validate and Checkov green.

**Stage 2: reports 01–04 (all; S1 writes 04)**
- New: `docs/reports/README.md` (index, legend, numbers policy, evidence classes), `01_project_charter_and_management.md`, `02_literature_review_and_benchmarking.md`, `03_system_analysis_and_architecture.md`, `04_devsecops_shift_left_pipeline.md`.
- Exit: every number cited; every Mermaid block parses; the fixed-wording grep is clean; links checked or marked.

**Stage 3: reports 05–07, demo, deck, HANDOFF (S2 writes 05, S3 writes 06; all write 07)**
- New: `docs/reports/{05_secure_cloud_application_and_identity.md, 06_detection_telemetry_and_soar_engine.md, 07_verification_attack_simulations_and_qa.md}`, `docs/runbooks/live-demo-runbook.md`, `docs/presentation/deck-outline.md`.
- Edit: `docs/HANDOFF.md`: header "As of", §1 status rows, and a new **§14**:
  - what was built;
  - decisions D1–D22;
  - step-0 outcomes and deviations;
  - proof (filled in Part 4);
  - not proven;
  - next: the cutover runbook, the first lab apply, filling the chapter 07 placeholders, G1, the legal verify items.
- Chapter 07 §3 is written from the Stage-1 verify-all run and finalised by the Validator in Part 4.

---

## 10. Verification matrix

| # | Check | Command | Expected | Where |
|---|---|---|---|---|
| V1 | Full local gate run | `make verify-all` | every domain PASS; exit 0; tree unchanged | sandbox (with mirror) |
| V2 | Stop on first failure | Temporarily break one test in a scratch **copy** of the repo (never in the tree), run | that domain FAIL, the rest `not run`, exit 1 | sandbox copy |
| V3 | Missing tool | `PATH` without gitleaks | preflight FAIL with hint, exit 2; with `VERIFY_ALLOW_SKIP=1`: SKIP, INCOMPLETE, exit 0 | sandbox |
| V4 | Tree mutation guard | Run with an untracked dummy file created mid-run (scratch copy) | exit 3, path listed | sandbox copy |
| V5 | No colour | `NO_COLOR=1 make verify-all \| cat` | no ANSI escapes (`grep -P '\x1b\['` empty) | sandbox |
| V6 | Cleanup on interrupt | Ctrl-C during docs-api and during local-smoke | moto container and compose stack gone (`docker ps`) | sandbox |
| V7 | Script lint | `shellcheck scripts/verify-all.sh` (pinned image) | clean | sandbox |
| V8 | SPA readiness pack | `npm --prefix app/spa run test:coverage`, lint, typecheck, build + bundle check | green; thresholds met | sandbox + CI `gate: app` |
| V9 | Terraform delta | validate 11/11; `terraform test` all green; Checkov 0 failed | as stated | sandbox + CI `gate: iac` |
| V10 | Required-check names | `grep -n 'name: "gate:' .github/workflows/ci.yml` vs the runbook JSON | identical strings | review |
| V11 | Runbook commands | `gh pr checks --help`, `gh pr merge --help` (`--match-head-commit`), `gh pr update-branch --help` | flags exist (confirmed in gh 2.89) | sandbox |
| V12 | Wording grep | `grep -rniE 'immutable\|append-only\|typically in under\|autonomous\|measured on AWS\|cryptographic' docs/reports docs/runbooks/live-demo-runbook.md docs/presentation README.md` | each hit justified (ECR tags, Cognito attribute, a quoted title, or an M3/M4 row) | Auditor |
| V13 | Numbers cited | Each digit-bearing claim in `docs/reports/*` has a `[repo:…]`, `[CI:…]`, `[local:…]`, `[HANDOFF §…]` or `[L…]` tag | 100 % | Auditor |
| V14 | Mermaid | Parse every block with Mermaid CLI | 0 errors | sandbox |
| V15 | Links | `curl -sI` each `[L…]` URL | 2xx/3xx, or marked `[verify: link not checked]` | sandbox |
| V16 | Offline IR tool (if adopted) | step 0 #2 | exit 2 / 0 | sandbox |
| V17 | CI on PR #PF | REST: `gh api repos/$REPO/commits/<sha>/check-runs` | all gate jobs success; `Report (fail-open)` skipped | GitHub |

---

## 11. Independent Auditor focus

- **Honesty.** No AWS number anywhere; every MTTC figure classed M0–M4; seeded and golden values never called measurements; `make sim TARGET=local` never called offline; "automated", not "autonomous"; README overclaims fixed; nothing from the plan PDF, rubric or WBS invented; every external citation real, on the §6.4 list and marked `[verify]`; no statistics.
- **Fixed claims.** FR-3 bucket-ARN context; FR-4 insert-only by convention with the stream consumer as a follow-up; single account; DynamoDB only ("logical view"); Object Lock off by default; posture and pack wording.
- **verify-all correctness:**
  - stop-on-first-failure, exit codes and the trap (no masked exit code, no orphan containers);
  - the `pipefail` and `set -e` traps inside functions and pipelines with `tee`;
  - quoting; no `eval`; no env dumps; gitleaks `--redact`;
  - `fmt -check`, never `fmt`; the scratch-copy Terraform (no lock files in the tree);
  - log location outside the repo;
  - honest SKIP semantics; version WARNs;
  - mirrors the CI commands exactly (diff each command against `ci.yml`).
- **Cutover runbook:**
  - merge-commit strategy and the order;
  - explicit retarget before any branch deletion;
  - update-branch to trigger CI; the checks-race wait; `--match-head-commit`;
  - no `--admin`, no force push;
  - `ENFORCE_GATES` ordering and its fallback;
  - protection applied last with the 7 exact names; the code-owner author trap (D11);
  - the REST alternatives for agent sessions.
- **Readiness pack:**
  - escaping (Markdown and HTML injection through ruleset or profile strings);
  - the disclaimer and VERIFY marker always present;
  - only the caller's own tenant data; no new network call;
  - filename sanitising; object URL revoked; CSP-compatible;
  - "not audited / not signed" stated.
- **Demo safety (R4):**
  - own resources only; no secret committed (the seed is IaC, not a token);
  - dry-run restored in every path, incl. the failure fallbacks;
  - scenario A recovery steps;
  - the Object Lock teardown caveat; costs stated.
- **Consistency.** The deck, the chapters, the runbook and HANDOFF §14 say the same thing on each fixed claim; check names and file paths match the repo.

---

## 12. Part 4: Validator, push, PR, CI, HANDOFF §14

1. Run `make verify-all` in the sandbox with a provider mirror (`TF_CLI_CONFIG_FILE` in the scratchpad, never committed) and the actionlint image.
   - local-smoke may hit the sandbox's TLS-intercepting proxy during image builds (HANDOFF §13 environment notes). The committed Dockerfiles must not change. If it fails for that reason only, record "local-smoke: sandbox-blocked; CI `app-smoke` run <id> is the authority" and run the remaining domains with domain arguments.
   - Record ruff 0.16.8 vs 0.17.0 as a WARN, or install 0.17.0 in a venv.
2. The Independent Auditor (a fresh agent) reviews against §11. Fix the findings, each with a test where code is involved, then re-run the affected domains.
3. The Validator fills in chapter 07 §3 and Appendix A and HANDOFF §14 "Proof" with the final run (commit SHA, date, environment, versions) and the PR #PF CI run id.
4. `git push -u origin feat/depi-phase-f-capstone-complete`. Open the PR **via REST** (GraphQL is blocked, F6):

   ```bash
   gh api repos/ELSHAHALY/Cloud-Shield/pulls -X POST \
     -f title="docs+tooling: Phase F capstone (verify-all, cutover runbook, reports, demo, deck)" \
     -f head=feat/depi-phase-f-capstone-complete -f base=feat/s2-app-soc-ui-grc \
     -F body=@<scratchpad>/pr-body.md
   ```

   The body follows `.github/pull_request_template.md` and lists: domains S1/S2/S3; the merge order #1 → #2 → #3 → #4 → this PR; the cutover runbook link; the evidence (verify-all summary, CI runs); open verify items; Q1's outcome; and the required attribution footer.
5. Watch CI through `gh api repos/…/commits/<sha>/check-runs` until every gate job succeeds and the fail-open report steps are skipped. Fix and push on red.
6. HANDOFF §14 final commit; CI green again.

---

## 13. Open questions

**Answered 17 Oct:** Q1 yes (second owners); Q2 yes (`gate: image` is the 7th required check); Q3 yes ("Compliance Readiness Pack").

**Blocking (default applied if unanswered):**
- **Q1 (D11): CODEOWNERS second owners.** Branch protection with code-owner review blocks every PR whose author is a path's only owner: all four existing PRs are by @ahklsfg and touch S3-only paths. May Phase F give every single-owner path a second owner from another role (S3 paths + @ELSHAHALY; S2 paths + @ELSHAHALY; S1 paths + @ahklsfg; `/docs/` all three)? **Default: yes.** The alternative is to drop "Require review from Code Owners" and rely on 2 approvals.

**Non-blocking (defaults stated):**
- Q2: keep `gate: image` as a 7th required check (**default yes**, as in `repo-admin-setup.md`).
- Q3: rename the "Audit Pack" to "Compliance Readiness Pack" (**default yes**; it is not an audit).
- Q4: the viva date, and whether a lab apply will happen before it. This decides whether the AWS track gets rehearsed. **Default:** offline primary.
- Q5: the team should supply R7, FR-1/6/7, the plan §1.1 content, the rubric criteria and the WBS Chapter 7 structure from the PDF. Until then those cells stay `[source: plan PDF, not in repo — team to verify]`.

### Critical files for implementation
- /home/user/Cloud-Shield/scripts/verify-all.sh (new; modelled on /home/user/Cloud-Shield/scripts/gate-selftest.sh and the commands in /home/user/Cloud-Shield/.github/workflows/ci.yml)
- /home/user/Cloud-Shield/docs/runbooks/final-merge-and-cutover.md (new; extends /home/user/Cloud-Shield/docs/runbooks/repo-admin-setup.md)
- /home/user/Cloud-Shield/app/spa/src/grc/GrcHub.tsx (+ new /home/user/Cloud-Shield/app/spa/src/grc/readinessPack.ts; pattern from /home/user/Cloud-Shield/app/spa/src/soc/EvidencePanel.tsx)
- /home/user/Cloud-Shield/infra/terraform/environments/dev/variables.tf and main.tf (`evidence_object_lock_days` pass-through to /home/user/Cloud-Shield/infra/terraform/modules/soar/variables.tf)
- /home/user/Cloud-Shield/docs/reports/07_verification_attack_simulations_and_qa.md (new; evidence classes and MTTC classes per §7), with /home/user/Cloud-Shield/docs/HANDOFF.md §14
