# Chapter 04: DevSecOps shift-left pipeline

| Field | Value |
|---|---|
| Report | CloudShield: Automated DevSecOps and Cloud Incident Response (DEPI AWS Cloud Security capstone, Fall 2026) |
| Chapter | 04 |
| Version | 1.0 |
| Date | 17 Oct 2026 |
| Status | DRAFT |
| Owner | S1 @ELSHAHALY (Platform / Infra / CI-CD, repo admin) [repo: docs/plans/depi-phase-f-capstone-complete.md §9 "Stage 2"] |
| Reviewers | S2 @YasseenAbdelghany, S3 @ahklsfg (the `.github/` path is co-owned by S1 and S3) [repo: .github/CODEOWNERS] |
| Sources and marks | Legend in [docs/reports/README.md §2](README.md#2-sources-and-marks-legend), numbers policy in [§3](README.md#3-numbers-policy) |

**Marks used in this chapter.** `[repo: path §/line]` means read from the repository at the Phase F branch. `[CI: run <id>, PR #n, <sha>]` is a GitHub Actions run. `[HANDOFF §n]` is a prior record. `[L<n>]` is an external source from §12, still `[verify]`. `[inferred]` is the authors' unverified understanding. `[verify]` marks a vendor behaviour or edition still to be checked against the official source. `[source: plan PDF, not in repo — team to verify]` marks an item whose content only the plan PDF, the rubric or the WBS holds.

> **What is measured vs pending**
>
> - **Measured in CI:** the latest run on each PR of the stack is green, and in every gate job the `Report (fail-open)` step was **skipped**. The scan steps themselves succeeded, so the green result does not come from fail-open mode [CI: run 38478422214, PR #1, b28c75d] [CI: run 38486109181, PR #2, 7d6c677] [CI: run 38930049163, PR #3, 247643a] [CI: run 38984704551, PR #4, 9adc96d]. The authors read the job and step conclusions through the GitHub REST API on 17 Oct 2026.
> - **Measured locally:** the gate self-test tripped the secrets and IaC (CKV_AWS_24) seeds [HANDOFF §5]. Previous local record: Checkov 953 terraform + 202 dockerfile passed, 0 failed. Gitleaks, hadolint and actionlint clean [HANDOFF §13]. The Phase F `make verify-all` run is recorded in chapter 07 §3 and Appendix A.
> - **Not yet proven:** that the SAST, SCA, image, DAST and Dockerfile seeds trip [HANDOFF §5, §13]. Enforcement (`ENFORCE_GATES=true`) and branch protection are not yet active: they are the last steps of the cutover (§9). Neither OIDC role has ever been assumed, because nothing has been applied to AWS [HANDOFF §1].

---

## 1. Overview

### 1.1 Purpose and shape

The shift-left loop is one GitHub Actions workflow, `.github/workflows/ci.yml`. It runs on every pull request, on every push to `main` and on manual dispatch. The workflow-level token permission is `contents: read`, and a newer run cancels an older one on the same ref [repo: .github/workflows/ci.yml lines 17–30]. The file header orders the gates "cheapest/fastest first: secrets -> SAST -> SCA -> IaC -> image -> DAST" [repo: .github/workflows/ci.yml line 3]. That order is the logical gate numbering. Jobs without a `needs:` run in parallel, and only the image, DAST, app-smoke and plan jobs wait for others (Figure 4.1).

```mermaid
flowchart LR
  secrets["gate: secrets (gitleaks)"]
  sast["gate: sast (semgrep)"]
  sca["gate: sca (trivy fs)"]
  soar["gate: soar (ruff + pytest)"]
  app["gate: app (lint + typecheck + test + build)"]
  iac["gate: iac (terraform + checkov)"]
  image["gate: image (trivy image + sbom)"]
  smoke["app-smoke (docker compose, optional)"]
  plan["terraform plan (dev)"]
  dast["gate: dast (zap baseline)"]
  ecr[("ECR push, main only")]
  secrets --> image
  sast --> image
  sca --> image
  app --> image
  app --> smoke
  iac --> plan
  image --> dast
  image -.->|"only if every scan outcome is success"| ecr
```

*Figure 4.1. Job graph of `ci.yml`. Edges are `needs:` dependencies [repo: .github/workflows/ci.yml lines 355, 504, 538, 598]. `gate: soar` has no dependants. Its result does not gate the image push, but it is a required check after cutover (§9).*

### 1.2 Job table

| # | Job `name:` (exact) | Tool and pinned version | Fails when | Hard or fail-open | Outputs and artefacts | Timeout |
|---|---|---|---|---|---|---|
| 1 | `gate: secrets (gitleaks)` | Gitleaks `8.30.1`, release tarball from GitHub [repo: ci.yml lines 34, 64–69] | Any finding in the **full** history (`fetch-depth: 0`) [repo: ci.yml lines 61, 74] | Fail-open until `ENFORCE_GATES=true` | Job output `scan` = the scan step's real outcome [repo: ci.yml lines 56–57] | 10 min |
| 2 | `gate: sast (semgrep)` | Semgrep `1.180.0` via pip. Packs `p/owasp-top-ten`, `p/nodejs`, `p/python`, `p/typescript`, `p/react`. [repo: ci.yml lines 35, 96–112] | Any `ERROR`-severity finding outside `infra/` and `docs/` | Fail-open | `scan` output | 15 min |
| 3 | `gate: sca (trivy fs)` | Trivy `0.75.0` (image `aquasec/trivy:0.75.0`) [repo: ci.yml lines 36, 134–144] | A **fixable CRITICAL** vulnerability in a lockfile (`--ignore-unfixed`). `infra/` is skipped. | Fail-open | `scan` output | 15 min |
| — | `gate: soar (ruff + pytest)` | Python `3.13`. ruff `0.17.0`, pytest `9.1.1`, pytest-cov `7.1.0`, moto `5.2.4` [repo: ci.yml line 171; soar/requirements-dev.txt] | ruff lint or format, the pytest branch-coverage gate `fail_under = 95` [repo: soar/pyproject.toml `[tool.coverage.report]`], a non-deterministic package build, or ATT&CK table drift [repo: ci.yml lines 176–190] | **Always hard** [repo: ci.yml lines 152–156] | — | 10 min |
| — | `gate: app (lint + typecheck + test + build)` | Node from `app/.nvmrc` (`24.22.0`). moto service `5.2.4` by digest. hadolint `v2.14.0` by digest. [repo: ci.yml lines 44, 201–226; app/.nvmrc] | ESLint (docs-api `--max-warnings 0`), `tsc`, OpenAPI drift, Jest coverage (lines/statements/functions 90, branches 85), Vitest coverage (80/80/80/75), the production build with the bundle check and no `local-idp`, local-dev tests, hadolint, `docker compose config` [repo: ci.yml lines 228–276] [repo: app/docs-api/jest.config.js line 7] [repo: app/spa/vitest.config.ts line 15] | **Always hard** [repo: ci.yml lines 192–196] | — | 20 min |
| 4 | `gate: iac (terraform + checkov)` | Terraform `1.16.5`, Checkov `3.3.26` [repo: ci.yml lines 33, 37] | `fmt -check`, `validate` on every root and module, `terraform test` on every module with `tests/`, and any failed Checkov check (terraform and dockerfile frameworks) [repo: ci.yml lines 297–339] | fmt/validate/test **always hard**. Checkov fail-open. [repo: ci.yml lines 295–296, 332] | — | 15 min |
| 5 | `gate: image (trivy image + sbom)` | Docker build, Trivy `0.75.0` [repo: ci.yml lines 374–413] | A **fixable CRITICAL or HIGH** vulnerability in the built image [repo: ci.yml lines 397–406] | Trivy fail-open | Artefact `sbom-<sha>` (CycloneDX), **kept 90 days**. On `main`, the push to ECR. [repo: ci.yml lines 408–421, 438–493] | 20 min |
| 6 | `gate: dast (zap baseline)` | ZAP baseline, image `ghcr.io/zaproxy/zaproxy:stable` [repo: ci.yml line 616] | A rule set to `FAIL` in `.zap/rules.tsv` (`-I` ignores warnings) [repo: ci.yml lines 605–617] | Fail-open. Runs only off-PR with `STAGING_URL`. [repo: ci.yml line 599] | Artefact `zap-report-<sha>` [repo: ci.yml lines 619–625] | 20 min |
| — | `app-smoke (docker compose, optional)` | `make local-up`, `make local-smoke` [repo: ci.yml lines 516–528] | Any of the 8 smoke checks [repo: docs/plans/depi-phase-f-capstone-complete.md F13] | Hard, but **not** a required check | Compose logs on failure | 25 min |
| — | `terraform plan (dev)` | Terraform `1.16.5` with the OIDC plan role [repo: ci.yml lines 534–588] | Plan error | Runs only when `AWS_PLAN_ROLE_ARN` is set, and never for fork PRs [repo: ci.yml lines 539–542] | Last 40 plan lines in the job summary | 20 min |

Sources for the timeouts: the `timeout-minutes` of each job [repo: .github/workflows/ci.yml lines 53, 88, 126, 160, 200, 284, 354, 503, 537, 597]. The table abbreviates `.github/workflows/ci.yml` as `ci.yml`.

**Security scans** (gates 1–6) can be fail-open, because a new CVE or rule can turn a build red without a code change. **Correctness checks** (Terraform fmt/validate/test, `gate: soar`, `gate: app`) always fail hard: "a broken safety guard must never merge" [repo: .github/workflows/ci.yml lines 152–156, 295–296].

---

## 2. Gate by gate

### 2.1 Secrets (Gitleaks)

The secrets gate checks out the **full history** (`fetch-depth: 0`). A secret that was committed and later deleted is still leaked, and only a history scan finds it [repo: .github/workflows/ci.yml line 61]. It runs `gitleaks git . --redact --verbose --exit-code 1`, and `--redact` keeps any match out of the log [repo: .github/workflows/ci.yml line 74]. The failure message tells the developer to "Rotate the credential FIRST, then purge history" [repo: .github/workflows/ci.yml line 79]. This is the right order, because history rewriting does not revoke a credential.

**The allow-list caveat.** Gitleaks allow-lists AWS's documented example key `AKIAIOSFODNN7EXAMPLE`, so a test "secret" copied from vendor documentation passes silently. The self-test therefore builds a fake GitHub token at runtime [repo: scripts/gate-selftest.sh lines 46–54] [HANDOFF §8].

### 2.2 SAST (Semgrep)

Semgrep runs five registry packs, `p/owasp-top-ten`, `p/nodejs`, `p/python`, `p/typescript` and `p/react`, with `--severity ERROR --error --metrics off`, excluding `infra/` and `docs/` [repo: .github/workflows/ci.yml lines 99–112]. The SOAR build added `p/python`, and Phase E added the TypeScript and React packs [HANDOFF §10, §13]. On PR #4 the gate ran 95 rules and reported 0 findings [HANDOFF §13]. WARNING-level patterns are not gated. KPI §2.4 (a seeded SQL injection caught by SAST) needs the injection rule in one of these packs at ERROR severity, which is not yet confirmed (§4) [HANDOFF §5]. Semgrep cannot run in the build sandbox, and it crashed on Windows earlier, so **CI is the authority for SAST** [HANDOFF §10, §13].

### 2.3 SCA (Trivy filesystem)

Trivy scans the checkout read-only for vulnerable dependencies (`--scanners vuln`). It fails only on a **fixable CRITICAL** (`--severity CRITICAL --ignore-unfixed`), and it skips `/src/infra` [repo: .github/workflows/ci.yml lines 134–144]. A HIGH dependency CVE therefore fails only the image gate, and only if the dependency ships in the image (§2.6). Terraform providers are not SCA-scanned. Dependabot's `terraform` ecosystem covers them instead (§6).

### 2.4 IaC (Terraform + Checkov)

The IaC job has four steps:

1. `terraform fmt -check -recursive -diff`.
2. `init -backend=false` plus `validate` for **every** root **and** module (a module that no environment calls yet would otherwise never be validated).
3. `terraform test` for every module with a `tests/` directory.
4. Checkov over `infra/terraform` (terraform framework, no external module download) and over `app` (dockerfile framework).

[repo: .github/workflows/ci.yml lines 297–339]

Steps 1–3 are hard. That covers 11 validated directories and 8 tested modules, all except `network` [repo: docs/plans/depi-phase-f-capstone-complete.md F11]. The tests use a mocked AWS provider and assert the safety defaults: feature flags off, dry-run on, digest-pinned images, IMDSv2, and guard before playbook [repo: .github/workflows/ci.yml lines 312–313].

**No severity data, so any failed check fails.** The plan asked to "fail on HIGH". Open-source Checkov has no severity data without a vendor API key, so the gate fails on **any** failed check [repo: .github/workflows/ci.yml lines 327–329] [HANDOFF §3 gap 4].

**Skip-with-reason policy.** Accepted exceptions are inline `#checkov:skip=<ID>:<reason>` annotations next to the resource. The Terraform tree carries 121 such annotations, and none of them lacks a reason text [repo: `grep -rho '#checkov:skip=' infra --include=*.tf`, 17 Oct 2026]. The audits have corrected them: the scaffold audit made the reasons "honest", and Phase D audit A8 changed the design so that an untrue reason on the SPA bucket became true [HANDOFF §2.5, §12]. The previous local record is 953 terraform and 202 dockerfile checks passed, 0 failed [HANDOFF §13].

### 2.5 Correctness gates: `soar` and `app`

`gate: soar` runs ruff (lint and format), then `python -m pytest --cov` from `soar/`. The step label was corrected in Phase F to "pytest (coverage gate in pyproject.toml, 95 %)" [repo: .github/workflows/ci.yml line 181]. The threshold and the measured packages live only in `soar/pyproject.toml`: `branch = true`, `source = [core, safety_guard, playbooks, notifier, tools, sims]`, `fail_under = 95` [repo: soar/pyproject.toml]. CI therefore cannot drift from `make soar-test` [repo: docs/plans/depi-phase-f-capstone-complete.md D2]. The job also builds the Lambda zip and checks the ATT&CK table exported for docs-api [repo: .github/workflows/ci.yml lines 184–190].

`gate: app` runs docs-api, SPA and local-dev lint, typecheck and tests. It includes an OpenAPI type-drift check and the Jest suites against a moto service container. It builds the SPA in Cognito mode, then fails if the bundle contains the dev-only local sign-in or anything the edge CSP would block, and it runs `! grep -R "local-idp" dist/` [repo: .github/workflows/ci.yml lines 228–258] [repo: app/spa/scripts/check-bundle.mjs lines 1–2]. It also lints the three Dockerfiles with hadolint and validates the compose file [repo: .github/workflows/ci.yml lines 268–276]. Every `npm ci` uses `--ignore-scripts`, so a dependency's install script never runs in CI [repo: .github/workflows/ci.yml lines 231, 243, 263].

### 2.6 Image (build + Trivy image + SBOM)

The image job waits for secrets, SAST, SCA and app [repo: .github/workflows/ci.yml line 355]. It builds `app/docs-api/Dockerfile` with context `app/`. The build arguments include the **real** outcomes of the earlier gates, which `write-build-info.mjs` validates into `build-info.json` [repo: .github/workflows/ci.yml lines 374–395] [repo: app/docs-api/scripts/write-build-info.mjs]. Trivy then scans the built image and fails on a fixable CRITICAL **or HIGH** vulnerability [repo: .github/workflows/ci.yml lines 397–406]. A CycloneDX SBOM is generated from the same image and uploaded as the artefact `sbom-<sha>` with **90-day retention** [repo: .github/workflows/ci.yml lines 408–421]. The job skips itself until a Dockerfile exists in `$APP_DIR`. That is why PRs #1–#3 skipped the build and scan steps, and PR #4 ran them [CI: run 38930049163, PR #3, 247643a] [CI: run 38984704551, PR #4, 9adc96d]. Trivy reported 0 fixable CRITICAL/HIGH on PR #4 [HANDOFF §13].

### 2.7 DAST (ZAP baseline)

The DAST gate runs `zap-baseline.py` against `vars.STAGING_URL` with `-c rules.tsv -I -m 1`. `-I` means only rules set to `FAIL` break the build, and `-m 1` limits the spider to one minute so the scan stays under the CloudFront per-IP rate limit [repo: .github/workflows/ci.yml lines 605–617]. Four passive rules are `FAIL`: 10020 (anti-clickjacking header), 10021 (`X-Content-Type-Options`), 10035 (HSTS) and 10038 (CSP). Rule 10202 (anti-CSRF tokens) is deliberately not `FAIL`, because the API uses bearer JWTs, not cookies [repo: .zap/rules.tsv]. The job runs only when `STAGING_URL` is set and the event is not a pull request, that is, on `main` or on manual dispatch [repo: .github/workflows/ci.yml line 599]. **It has never run**: no staging deployment exists, so it was skipped in all four PR runs (front matter). An earlier version ran with `-I` and no `FAIL` rules, so it could never fail. The header rules fix that (gap 14) [HANDOFF §3].

---

## 3. Fail-open → enforced

### 3.1 Mechanism

Every security-scan step carries `continue-on-error: ${{ vars.ENFORCE_GATES != 'true' }}` [repo: .github/workflows/ci.yml lines 73, 101, 136, 332, 400, 611]. While the repository variable is unset, a finding makes the scan step's **outcome** `failure`, but the job still concludes `success`. A `Report (fail-open)` step then writes a `::warning` annotation and a "⚠️ … gate failed (fail-open mode)" line into the job summary [repo: .github/workflows/ci.yml lines 76–80]. Once `ENFORCE_GATES=true`, the same finding fails the job: this is the FR-5 hard gate [repo: .github/workflows/ci.yml lines 5–12].

### 3.2 The real-outcome outputs

A fail-open pipeline has an obvious weakness: a green job can hide a failed scan. CloudShield closes this in two ways.

- **Each scan job exports its scan step's outcome** as a job output (`scan: ${{ steps.scan.outcome }}`), and the outcome is `failure` whenever findings exist, even in fail-open mode [repo: .github/workflows/ci.yml lines 54–57, 429–437].
- **The image push requires every outcome to be `success`.** The push steps run only on a push to `main`, only when `AWS_ECR_PUSH_ROLE_ARN` is set, and only when this job's Trivy scan **and** the secrets, SAST and SCA scan outcomes are `success` **and** `gate: app` succeeded [repo: .github/workflows/ci.yml lines 438–461]. A commit with a fail-open finding can be merged during the bootstrap period, but its image can never reach ECR. This condition fixes Phase D audit finding A9 [HANDOFF §12].

The same outcomes reach runtime. `build-info.json` records `gates.{secrets,sast,sca,app}` and `gatesEnforced`, and the SOC posture banner shows them. It "never claims 'no vulnerabilities'" [repo: app/docs-api/src/posture/posture.ts lines 1–23].

### 3.3 When enforcement is switched on

The README asked for `ENFORCE_GATES=true` "no later than the end of Sprint 1" [repo: README.md "Fail-open → enforced"], but the variable is still unset. Phase F fixes the timing (D9). S1 runs `scripts/gate-selftest.sh all`, requires "NOT caught: 0 skipped: 0", sets `ENFORCE_GATES=true` and only then merges, so every CI run after a retarget is enforced. If the self-test cannot complete, the stack is merged fail-open and the variable is flipped after the Phase F PR, with the reason recorded in HANDOFF §14 [repo: docs/plans/depi-phase-f-capstone-complete.md D9]. The precondition holds as of the four PR runs: their `Report (fail-open)` steps were skipped, so the scans would also have passed with enforcement on (§10). Only S1, as admin, can set the variable. The Actions variables API is also blocked in the agent sandbox [repo: docs/plans/depi-phase-f-capstone-complete.md F6].

---

## 4. Proving the gates trip

A gate that never fails proves nothing. `scripts/gate-selftest.sh` runs each tool with the CI flags against a **seed**: a known-bad input generated in a temporary directory at runtime and deleted afterwards. Nothing bad is ever committed, because a committed seed secret would live in history and trip every future full-history scan [repo: scripts/gate-selftest.sh lines 1–18].

The self-test applies a strict criterion. A non-zero exit counts as a trip **only if the seeded finding's signature appears in the tool output**. A bare non-zero exit, such as a crash, a failed database download or an unknown subcommand, counts as a failure, and exit 127 counts as "skipped (tool not installed)" [repo: scripts/gate-selftest.sh lines 26–42]. This fixes scaffold audit finding M8 [HANDOFF §2.5].

| Gate | Seed (built at runtime) | Command differs from CI? | Expected signature | Status | Source |
|---|---|---|---|---|---|
| secrets | A syntactically valid but fake GitHub token (`ghp_` + 36 random characters), assembled so the script itself contains no secret pattern | `gitleaks dir` on the seed directory (CI: `gitleaks git .`) | `github-pat` | **Proven to trip** | [repo: scripts/gate-selftest.sh lines 49–54] [HANDOFF §5] |
| sast | An Express route concatenating `req.query.id` into SQL (OWASP A03) | Only `p/owasp-top-ten` and `p/nodejs` (CI runs 5 packs) | `sql\|CWE-89` | **Not proven.** It trips Semgrep `tainted-sql-string`, but membership in those packs is unconfirmed. | [repo: scripts/gate-selftest.sh lines 57–71] [HANDOFF §5] |
| sca | A `package-lock.json` pinning lodash `4.17.4` (CVE-2019-10744, CRITICAL, fixed in `4.17.12`) | Same flags | `CVE-2019-10744` | **Not proven** (never run: the Trivy DB was blocked) | [repo: scripts/gate-selftest.sh lines 73–86] [HANDOFF §5] |
| iac | A security group with port 22 open to `0.0.0.0/0` | `--check CKV_AWS_24` only | `CKV_AWS_24` | **Proven to trip** | [repo: scripts/gate-selftest.sh lines 88–106] [HANDOFF §5] |
| dockerfile | `FROM node:latest` + `USER root` | hadolint `--failure-threshold warning`. Checkov limited to two checks. | `DL3007`. `CKV_DOCKER_7\|CKV_DOCKER_8`. | **Not proven** (added in Phase E, no recorded run) | [repo: scripts/gate-selftest.sh lines 108–121] [HANDOFF §13 "Next" item 2] |
| image | `node:14` (end of life) | Same flags | `CRITICAL\|HIGH` | **Not proven** (never run) | [repo: scripts/gate-selftest.sh lines 123–126] [HANDOFF §5] |
| dast | A local `python3 -m http.server` on `127.0.0.1:18080` that sends none of the `FAIL` headers | Same `rules.tsv`, local target | `FAIL-NEW: [1-9]`. HSTS (10035) cannot fire over plain HTTP, but 10020, 10021 and 10038 can. | **Not proven** (never run: Docker was blocked) | [repo: scripts/gate-selftest.sh lines 128–142] [HANDOFF §5] |

The self-test's commands are close to CI's but not identical (column 3), so a ✓ shows that **the tool and the rule** trip on the seed, not that the exact CI invocation would. For IaC the difference does not matter, because CI runs all checks, CKV_AWS_24 included. For SAST it might: KPI §2.4 needs the injection rule in the CI packs at ERROR severity, which is exactly what is unconfirmed. Whether the SAST seed trips in the sandbox is an informational Phase F step-0 item [repo: docs/plans/depi-phase-f-capstone-complete.md §9 step 0 item 7].

---

## 5. CI identity: GitHub OIDC

### 5.1 No long-lived keys

`bootstrap/` creates a GitHub OIDC provider (`https://token.actions.githubusercontent.com`, client id `sts.amazonaws.com`) [repo: infra/terraform/bootstrap/main.tf lines 132–144]. CI therefore holds no AWS access key. The repository configuration consists of *variables*, not secrets: role ARNs, the state bucket, the KMS key ARN, the region and `ENFORCE_GATES` [repo: README.md "Wire up GitHub"] [repo: docs/runbooks/repo-admin-setup.md §2]. Only the two jobs that assume a role request `id-token: write`, the image job and the plan job, and each grants it at job level only [repo: .github/workflows/ci.yml lines 356–358, 543–545].

### 5.2 The two roles

| Property | Plan role `cloudshield-gha-terraform-plan` | ECR push role `<name>-gha-ecr-push` |
|---|---|---|
| Defined in | `infra/terraform/bootstrap/main.tf` lines 146–215 | `infra/terraform/modules/compute/ci-push.tf` lines 13–81 |
| Created | Always (bootstrap) | Only when `github_oidc_provider_arn` is passed to dev [repo: ci-push.tf line 14] |
| `aud` condition | `StringEquals` `sts.amazonaws.com` | `StringEquals` `sts.amazonaws.com` |
| `sub` condition | `StringLike` with the two values `repo:${var.github_repository}:pull_request` and `repo:${var.github_repository}:ref:refs/heads/main` [repo: bootstrap/main.tf lines 158–167] | `StringEquals` `repo:${var.github_repository}:ref:refs/heads/${var.ecr_push_branch}` [repo: ci-push.tf lines 16, 33–39] |
| Resolved with defaults | `repo:ELSHAHALY/Cloud-Shield:pull_request`, `repo:ELSHAHALY/Cloud-Shield:ref:refs/heads/main` [repo: bootstrap/variables.tf line 16] | `repo:ELSHAHALY/Cloud-Shield:ref:refs/heads/main` (`ecr_push_branch` default `main`, validated to contain no wildcard) [repo: compute/variables.tf lines 181–190] |
| Permissions | AWS-managed `ReadOnlyAccess`, plus state access: `ListBucket`, `GetObject`, `PutObject`/`DeleteObject` on `*.tflock` only, and the state KMS key [repo: bootstrap/main.tf lines 178–215] | `ecr:GetAuthorizationToken` on `*` (no resource-level support). Layer upload, `PutImage`, `BatchGetImage`, `DescribeImages` and `DescribeImageScanFindings` on the one repository ARN `…:repository/<name>/docs-api`. [repo: ci-push.tf lines 52–74] |
| Session | 3600 s maximum [repo: bootstrap/main.tf line 175] | 3600 s maximum [repo: ci-push.tf line 48] |
| Can deploy? | No (plan only) | No. ECS runs only the digest set in `container_image` by a local S1 apply. [repo: ci-push.tf lines 5–7] |

The push role's rule is "Exact match: one repository, one branch. Never StringLike" [repo: infra/terraform/modules/compute/ci-push.tf lines 33–34]. The plan role uses `StringLike`, but its two values contain no wildcard, so it is in effect an exact match on two subjects. Fork PRs cannot assume it, and the plan job's `if:` skips them anyway [repo: infra/terraform/bootstrap/main.tf lines 158–160] [repo: .github/workflows/ci.yml lines 539–542].

Two weaknesses remain, and both are analysed here rather than taken from the repo.

- **The `pull_request` subject is shared by every same-repository PR.** Any collaborator with Write access can open a PR whose head edits `ci.yml` and obtain a plan-role session with `ReadOnlyAccess` [inferred]. This is a property of GitHub's default subject format [verify]. It is the main reason the broad managed policy is a limitation (§11), not just an inconvenience.
- **Any workflow file on `main` can mint the push token,** not only `ci.yml`. The tracked follow-up (audit A9) is to customise the OIDC subject to include `job_workflow_ref` and rewrite **both** trust policies in the same change, because the customisation applies to every token the repository mints [repo: docs/runbooks/repo-admin-setup.md §2b].

---

## 6. Supply chain

### 6.1 Controls in place

| Control | Implementation | Source |
|---|---|---|
| Actions pinned to commit SHAs | Every `uses:` is a full SHA with the tag in a comment, for example `actions/checkout@3d3c42e5… # v7.0.1`, `aws-actions/configure-aws-credentials@e1253824… # v6.3.0` | [repo: .github/workflows/ci.yml lines 14–15, 59, 447] |
| Scanner and tool versions pinned | `TF_VERSION`, `GITLEAKS_VERSION`, `SEMGREP_VERSION`, `TRIVY_IMAGE`, `CHECKOV_VERSION` in the workflow `env:`. hadolint and moto pinned by digest. | [repo: .github/workflows/ci.yml lines 32–44, 203] |
| Dependabot | Weekly updates for `github-actions`, `terraform` (bootstrap, dev, every module), `npm` (docs-api, spa, local-dev; grouped `aws-sdk` and `dev-tooling`), `docker` (the three Dockerfiles) and `docker-compose` | [repo: .github/dependabot.yml] |
| Exact versions and lockfiles | `.npmrc`: `save-exact=true`, `ignore-scripts=true`, `engine-strict=true`. Committed `package-lock.json` per package. | [repo: app/docs-api/.npmrc] |
| Install scripts disabled | `npm ci --ignore-scripts` in CI and in every Dockerfile build stage | [repo: .github/workflows/ci.yml lines 231, 243, 263] [repo: app/docs-api/Dockerfile line 9] |
| Base images pinned by digest | `node:24-bookworm-slim@sha256:a5f4…`, `gcr.io/distroless/nodejs24-debian13:nonroot@sha256:59c4…`, `nginxinc/nginx-unprivileged:stable-alpine@sha256:782b…` | [repo: app/docs-api/Dockerfile lines 7, 31] [repo: app/spa/Dockerfile line 16] |
| Build context allow-list | `Dockerfile.dockerignore` starts with `*` and re-includes only the files the image needs | [repo: app/docs-api/Dockerfile.dockerignore lines 1–12] |
| Registry | ECR `image_tag_mutability = "IMMUTABLE"`, `scan_on_push = true`, KMS-encrypted. CI tags with the commit SHA and skips the push if the tag exists. | [repo: infra/terraform/modules/compute/main.tf lines 76–85] [repo: .github/workflows/ci.yml lines 473–479] |
| Deploy by digest | `container_image` must match `@sha256:[a-f0-9]{64}$`, never a tag. The push step prints the digest to deploy. | [repo: infra/terraform/modules/compute/variables.tf lines 53–59] [repo: .github/workflows/ci.yml lines 482–493] |
| SBOM | CycloneDX from Trivy, per commit, kept 90 days | [repo: .github/workflows/ci.yml lines 408–421] |
| Deterministic Lambda package | `scripts/package_soar.py` builds a byte-identical zip. `verify-all` asserts equal SHA-256 across two builds. | [HANDOFF §10] [repo: docs/plans/depi-phase-f-capstone-complete.md §3.1 domain 2] |

The ECR registry also gives the SOC a runtime read. docs-api calls `DescribeImageScanFindings` on its own running digest, on the app repository only, and the posture banner shows it [repo: infra/terraform/modules/compute/main.tf line 293] [repo: app/docs-api/src/posture/posture.ts lines 1–4].

### 6.2 Gaps in the pinning

Some pins are weaker than the table suggests, and the authors list them here:

- The ZAP image is the floating tag `ghcr.io/zaproxy/zaproxy:stable` [repo: .github/workflows/ci.yml line 616].
- Trivy is pinned by tag (`aquasec/trivy:0.75.0`), not by digest [repo: .github/workflows/ci.yml line 36].
- The Gitleaks tarball is downloaded with `curl` and no checksum check [repo: .github/workflows/ci.yml lines 66–69].
- Semgrep's registry packs are fetched at run time, so the rules can change between two runs of the same commit [inferred].
- Dependabot has no `pip` entry, so `soar/requirements-dev.txt` is bumped by hand [repo: .github/dependabot.yml].
- The CI environment pins and service images are bumped by hand, as the workflow says itself (audit E12) [repo: .github/workflows/ci.yml lines 42–43].

### 6.3 SLSA self-assessment [inferred, not certified]

SLSA v1.0 defines Build levels L1–L3 [L6]. The table is the authors' own reading of those levels against the repository. No third party has assessed it, and nothing here is a certification.

| SLSA v1.0 Build requirement (paraphrased) [L6] | CloudShield today | Assessment [inferred] |
|---|---|---|
| L1: provenance exists, describing how the artefact was built | `build-info.json` inside the image records the commit, build time, CI run id and gate outcomes [repo: app/docs-api/scripts/write-build-info.mjs]. A CycloneDX SBOM is uploaded. | **Partial.** Neither is SLSA provenance: no build-definition and run-details statement in the specified format, and nothing is published next to the digest. |
| L2: a hosted build platform generates signed provenance | GitHub-hosted runners build and push the image | **Not met.** The platform is hosted, but no provenance is signed. |
| L3: a hardened build platform, with provenance the tenant cannot forge | Ephemeral hosted runners. The push needs the exact `main` subject. | **Not met.** No unforgeable provenance. Any workflow on `main` can mint the push token (§5.2). |
| (Source integrity, outside the v1.0 Build track) | Two-person review and required checks after cutover (§9) | Pending cutover |

The honest position is **SLSA Build L0 with several L1 prerequisites in place**. Reaching L1 would mean generating a provenance statement for each pushed digest and publishing it with the image. Reaching L2 would mean signing it in the hosted build [inferred].

---

## 7. Container hardening

| Layer | Control | Source |
|---|---|---|
| Base image | Multi-stage build. The runtime stage is distroless `nodejs24-debian13:nonroot`: no shell, no package manager, no npm at runtime. The Debian 12 variant was dropped because it carried fixable CRITICAL/HIGH `libssl3` CVEs in Oct 2026. | [repo: app/docs-api/Dockerfile lines 28–31] |
| User | `USER 1000:1000`. Application files copied root-owned and not writable by the runtime user. | [repo: app/docs-api/Dockerfile lines 35, 46] |
| Task definition user | `user = var.container_user` (default `1000:1000`). Validation refuses `0` or `root`. | [repo: infra/terraform/modules/compute/service.tf line 118] [repo: infra/terraform/modules/compute/variables.tf lines 63–72] |
| Filesystem | `readonlyRootFilesystem = true`, `privileged = false`. The only writable path is a task volume mounted at `/tmp`. | [repo: infra/terraform/modules/compute/service.tf lines 108–137] |
| Capabilities | `linuxParameters.capabilities.drop = ["ALL"]`. `initProcessEnabled = true` for ECS Exec (PB-04 volatile capture). | [repo: infra/terraform/modules/compute/service.tf lines 138–141] |
| Stop behaviour | `stopTimeout = 2`, so a PB-04 `StopTask` kills processes well inside the MTTC target | [repo: infra/terraform/modules/compute/service.tf lines 119–121] |
| Local stack | `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`, `tmpfs: [/tmp]` on the hardened services. The SPA image runs nginx-unprivileged as `USER 101`. | [repo: docker-compose.local.yml lines 11–15] [repo: app/spa/Dockerfile lines 16–19] |
| Lint | hadolint with `failure-threshold: warning` and trusted registries `docker.io` and `gcr.io` | [repo: .hadolint.yaml] |
| Policy | Checkov `--framework dockerfile` over `app/` (previous record: 202 passed, 0 failed) | [repo: .github/workflows/ci.yml line 339] [HANDOFF §13] |
| Build provenance (internal) | `GATE_*` and `GATES_ENFORCED` build arguments. Values outside the enum become `unknown`. The image never contains its own Trivy result. | [repo: app/docs-api/scripts/write-build-info.mjs lines 1–2] |
| Environment filter | The task definition drops, and a precondition refuses, `AUTH_LOCAL_*`, `AWS_ENDPOINT_URL` and `AWS_ENDPOINT_URL_*`, `S3_PUBLIC_ENDPOINT`, and any `CLOUDSHIELD_ENV` other than `aws`. Terraform therefore cannot create a task definition that starts the production image in local mode. | [repo: infra/terraform/modules/compute/service.tf lines 11–23, 157–159] [repo: docs/adr/0006-app-soc-grc-local.md D21–D22] |

The image still embeds a local-mode code path, a residual risk defended in depth by the config validator, the Terraform filter and the Cognito authorizer [repo: docs/adr/0006-app-soc-grc-local.md "Residual risks"]. Distroless as 1000:1000 with a read-only root filesystem on Fargate is a first-apply verify item [repo: docs/adr/0006-app-soc-grc-local.md "Verify on the first apply"].

---

## 8. Local shift-left

### 8.1 Pre-commit

`.pre-commit-config.yaml` runs the following before every commit:

- Gitleaks at the CI version (`v8.30.1`);
- `terraform_fmt` (pre-commit-terraform `v1.109.2`);
- from pre-commit-hooks `v6.0.0`: `check-merge-conflict`, `detect-private-key`, `detect-aws-credentials` (with `--allow-missing-credentials`), `end-of-file-fixer` and `trailing-whitespace`.

[repo: .pre-commit-config.yaml]

Pre-commit is advisory, since a developer can skip it. The full-history secrets gate in CI is the control that cannot be skipped.

### 8.2 Makefile targets

| Target | What it runs | Mirrors CI? | Source |
|---|---|---|---|
| `make scan` | `secrets sast sca iac soar-lint soar-test app-lint app-test dockerlint` | Mostly. `sca` adds `--skip-dirs "**/node_modules"` locally, and `iac` runs Checkov on terraform only. | [repo: Makefile `scan`, `sca`, `iac`] |
| `make secrets` / `sast` | The CI Gitleaks and Semgrep commands | Yes | [repo: Makefile `secrets`, `sast`] |
| `make fmt` | `terraform fmt -recursive` | **No: it writes.** CI only checks. | [repo: Makefile `fmt`] [repo: docs/plans/depi-phase-f-capstone-complete.md F10] |
| `make validate` / `test` | `init -backend=false` plus validate/test per directory **in the tree** | Yes, but leaves root lock files untracked | [repo: docs/plans/depi-phase-f-capstone-complete.md F10] |
| `make gate-selftest` | `scripts/gate-selftest.sh all` | — | [repo: Makefile `gate-selftest`] |
| `make soar-lint` / `soar-test` | ruff, `python -m pytest --cov` | Yes | [repo: Makefile `soar-lint`, `soar-test`] |
| `make dockerlint` | hadolint + Checkov on the Dockerfiles | Yes | [repo: README.md "Testing"] |
| `make verify-all` | `scripts/verify-all.sh $(VERIFY_DOMAINS)` | By design, domain by domain (§8.3) | [repo: Makefile `verify-all`] |

### 8.3 `make verify-all` (Phase F)

The individual targets have two weaknesses: they do not stop on the first failure, and `fmt`, `validate` and `test` modify the working tree. Phase F therefore adds `scripts/verify-all.sh` and `make verify-all` [repo: docs/plans/depi-phase-f-capstone-complete.md D1–D7] [repo: scripts/verify-all.sh lines 1–23]. Its design:

- **Domains, in order:** `preflight` → `terraform` → `soar` → `docs-api` → `spa` → `checkov` → `gitleaks` → `actionlint` → `local-smoke`. Each domain mirrors its CI job, lint, typecheck and build included [repo: scripts/verify-all.sh line 29] [repo: docs/plans/depi-phase-f-capstone-complete.md §3.1]. Positional arguments select a subset, for example `scripts/verify-all.sh soar spa`. Unselected domains show `not selected` [repo: docs/plans/depi-phase-f-capstone-complete.md D1].
- **Stop on the first failure.** Later domains show `not run`. A trap on `EXIT`, `INT` and `TERM` removes the verify moto container, takes the compose stack down if this run started it, and prints the summary without masking the original exit code [repo: docs/plans/depi-phase-f-capstone-complete.md §3.2] [repo: scripts/verify-all.sh lines 147–162].
- **Exit codes:** 0 pass, 1 a check failed, 2 a prerequisite is missing or the usage is wrong, 3 the working tree changed during the run [repo: scripts/verify-all.sh lines 18–20].
- **Prerequisites fail, not skip.** A missing tool, a stopped Docker daemon, a busy port 3000 or 5000, a shallow clone or a Node major other than 24 fails preflight with an install hint. Under `VERIFY_ALLOW_SKIP=1` a missing-tool domain is SKIPped and the run prints `RESULT: INCOMPLETE (n skipped)`. Chapter 07 never cites such a run as a full verification. A version that differs from a CI pin is a WARN [repo: docs/plans/depi-phase-f-capstone-complete.md D4] [repo: scripts/verify-all.sh lines 12, 141].
- **No tree mutation.** Terraform runs on a scratch copy, formatting uses `fmt -check`, and zips go to the scratch directory. The script compares `git status --porcelain` and the working-tree and index diff hashes before and after the run, and any difference is exit 3 [repo: docs/plans/depi-phase-f-capstone-complete.md D5] [repo: scripts/verify-all.sh lines 21–23, 78–84].
- **Colour only on a TTY,** with `NO_COLOR` unset and `TERM` not `dumb` [repo: scripts/verify-all.sh lines 42–46] [repo: docs/plans/depi-phase-f-capstone-complete.md D6].
- **Not wired into CI** (D7). CI already runs each domain as its own parallel job. The pinned actionlint image is `rhysd/actionlint:1.7.12` by digest [repo: scripts/verify-all.sh line 38].
- **Not covered:** Semgrep, Trivy fs/image and ZAP. They need registry or database downloads, and **CI is the authority** for them. The summary footer says so [repo: scripts/verify-all.sh line 132].

"verify-all green" therefore means: the hard CI gates plus Checkov, Gitleaks and actionlint are green locally. It does not mean the whole pipeline is green [repo: docs/plans/depi-phase-f-capstone-complete.md D1].

---

## 9. Branch protection and review

### 9.1 State before cutover

As of 17 Oct, `main` is **not protected**. Merge, squash and rebase are all allowed, and `delete_branch_on_merge` and `allow_update_branch` are both false [repo: docs/plans/depi-phase-f-capstone-complete.md F3]. Four PRs form a linear stack, #1 → #2 → #3 → #4, each based on the previous branch and all authored by @ahklsfg. The Phase F PR stacks on #4 [repo: docs/plans/depi-phase-f-capstone-complete.md F1, D21].

### 9.2 Code owners (D11)

CODEOWNERS maps paths to the three roles, and the last matching pattern wins. **When a line lists several owners, GitHub needs approval from any one of them.** Two-person review therefore comes from branch protection's "2 required approvals", not from the file. Scaffold audit M7 corrected the documentation that had claimed otherwise [repo: .github/CODEOWNERS header] [HANDOFF §2.5]. GitHub evaluates CODEOWNERS from the **base** branch, and a PR author's own approval never counts [verify] [repo: docs/plans/depi-phase-f-capstone-complete.md F7].

Before Phase F, many paths had a single owner: every S1 path, `/app/` and the data and identity modules for S2, and every S3 path. With "Require review from Code Owners", a PR by that sole owner could never be approved. All four existing PRs are by @ahklsfg and touch S3-only paths [repo: docs/plans/depi-phase-f-capstone-complete.md F7]. Phase F (D11, approved as plan question Q1) gives every single-owner path a second owner from another role:

| Path group | Owners after D11 | Source |
|---|---|---|
| `*` (default), `/infra/`, bootstrap, network, compute, edge, `/Makefile`, `/.pre-commit-config.yaml` | `@ELSHAHALY @ahklsfg` | [repo: .github/CODEOWNERS] |
| `/app/`, `modules/data`, `modules/identity` | `@YasseenAbdelghany @ELSHAHALY` | same |
| `/soar/`, `/detection/`, `/attack-sim/`, `modules/soar`, `modules/log-archive` | `@ahklsfg @ELSHAHALY` | same |
| `/docs/` (new), `/docs/adr/`, `/.github/CODEOWNERS` | all three | same |

Cross-domain paths such as `/.github/`, `ci-push.tf` and `security-groups.tf` keep their earlier two owners [repo: .github/CODEOWNERS].

### 9.3 Protection rules (D10)

Branch protection is applied **last**, after the Phase F PR merges. It cannot be applied earlier for two reasons: #1–#3 have no `gate: app` job, and every PR is by @ahklsfg, while `enforce_admins: true` would bar any bypass [repo: docs/plans/depi-phase-f-capstone-complete.md D10]. The settings:

| Setting | Value |
|---|---|
| Required status checks (7, exact names) | `gate: secrets (gitleaks)`, `gate: sast (semgrep)`, `gate: sca (trivy fs)`, `gate: iac (terraform + checkov)`, `gate: soar (ruff + pytest)`, `gate: app (lint + typecheck + test + build)`, `gate: image (trivy image + sbom)` |
| Not required | `gate: dast (zap baseline)` (skipped on PRs, so it would block every merge), `terraform plan (dev)` (skipped until the AWS variables are set), `app-smoke (docker compose, optional)` |
| `strict` | `true`: a branch must be up to date with `main`, so every PR needs "update branch" from now on |
| Reviews | 2 approvals, code-owner review, dismiss stale reviews |
| Admins | `enforce_admins: true` (S1 cannot push straight to `main` either) |
| Other | Conversation resolution required. No force pushes, no deletions. Optional `app_id: 15368` per check, so that only GitHub Actions can satisfy it [verify]. |

Sources: [repo: docs/plans/depi-phase-f-capstone-complete.md D10] [repo: docs/runbooks/repo-admin-setup.md §3]. `gate: soar` was missing from both the README check list and the runbook. Phase F adds it to both [repo: docs/plans/depi-phase-f-capstone-complete.md F5].

### 9.4 Cutover runbook

[`docs/runbooks/final-merge-and-cutover.md`](../runbooks/final-merge-and-cutover.md) implements plan §4 and decisions D8–D10, with REST equivalents in an appendix. S1 runs it on their own machine, because `gh pr` uses GraphQL, which the agent sandbox refuses [repo: docs/runbooks/final-merge-and-cutover.md §0–§7, Appendix] [repo: docs/plans/depi-phase-f-capstone-complete.md F6].

| § | Step | Key detail |
|---|---|---|
| 0 | Preconditions | Heads and bases match the expected stack, `compare` reports `behind_by = 0` for each pair, and no run summary shows a fail-open line. Each PR has 2 approvals from the two non-authors. |
| 1 | Prove, then enforce (D9) | `scripts/gate-selftest.sh all` with "NOT caught: 0 skipped: 0", then `gh variable set ENFORCE_GATES --body true` |
| 2 | Merge loop (D8) | **Merge commits only**, strictly #1 → #2 → #3 → #4 → Phase F PR: `gh pr merge N --merge --match-head-commit <sha>`. Then retarget the next PR to `main` explicitly and run **update-branch**. A base change triggers no CI, but update-branch creates a `synchronize` event and therefore a fresh run against `main`. Then wait for the new head's checks. No `--admin`, no force push, no branch deletion until the whole stack is merged. |
| 3 | Verify `main` | Every CI-proven head SHA (`b28c75d`, `7d6c677`, `247643a`, `9adc96d`, the Phase F head) is an ancestor of `origin/main`, and the push run on `main` is green. Then delete the branches. |
| 4 | Branch protection (D10) | The JSON payload with the 7 names, applied with `PUT …/branches/main/protection` and read back |
| 5 | Post-cutover checks | A no-op docs PR shows all 7 checks and "Review required". `ENFORCE_GATES` reads `true`. Optional submission tag. |
| 6 | Rollback | `git revert -m 1 <merge-sha>` through a PR. Never rewrite `main`. |

Sources: [repo: docs/runbooks/final-merge-and-cutover.md] [repo: docs/plans/depi-phase-f-capstone-complete.md §4, D8–D10, F1, F27].

**Why merge commits.** Squash and rebase create new commits that the next stacked branch does not contain, so its diff would replay the earlier PR, and the CI-tested SHAs would vanish from `main`. Merge commits keep every audited SHA on `main`, a chain of custody for the code [repo: docs/plans/depi-phase-f-capstone-complete.md D8].

---

## 10. Evidence

### 10.1 CI runs per PR

The authors read the job and step conclusions below through the GitHub REST API on 17 Oct 2026 (`GET /repos/ELSHAHALY/Cloud-Shield/actions/runs/<id>/jobs`). "Report skipped" means the `Report (fail-open)` step did not run, so the scan step succeeded.

| PR | Branch @ head | Run | secrets | sast | sca | iac | soar | app | image | app-smoke | dast | plan |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| #1 | `feat/s3-soar-playbooks` @ `b28c75d` | [CI: run 38478422214, PR #1, b28c75d] | ✓ report skipped | ✓ report skipped | ✓ report skipped | ✓ report skipped | ✓ | — (job not yet in the workflow) | ✓ (no Dockerfile, scan skipped) | — | skipped | skipped |
| #2 | `feat/s3-detection-athena-sims` @ `7d6c677` | [CI: run 38486109181, PR #2, 7d6c677] | ✓ report skipped | ✓ report skipped | ✓ report skipped | ✓ report skipped | ✓ | — | ✓ (no Dockerfile, scan skipped) | — | skipped | skipped |
| #3 | `feat/s1-s2-edge-identity-waf` @ `247643a` | [CI: run 38930049163, PR #3, 247643a] | ✓ report skipped | ✓ report skipped | ✓ report skipped | ✓ report skipped | ✓ | — | ✓ (build and scan skipped, no Dockerfile) | — | skipped | skipped |
| #4 | `feat/s2-app-soc-ui-grc` @ `9adc96d` | [CI: run 38984704551, PR #4, 9adc96d] | ✓ report skipped | ✓ report skipped | ✓ report skipped | ✓ report skipped | ✓ | ✓ | ✓ build, Trivy and SBOM success, report skipped, push skipped (PR) | ✓ | skipped | skipped |

`gate: dast` and `terraform plan (dev)` are skipped by design (no `STAGING_URL`, no `AWS_PLAN_ROLE_ARN`). The Phase F PR's own run is recorded in chapter 07 Appendix B once it exists.

### 10.2 Local record

- The previous local record (Linux, CI-pinned versions, after the Phase E audit fixes): Checkov 953 terraform + 202 dockerfile passed, 0 failed. Trivy fs and image clean. Gitleaks clean. hadolint and actionlint clean [HANDOFF §13].
- Gate self-test: secrets and IaC tripped. SAST is unconfirmed. SCA, image and DAST have not run [HANDOFF §5].
- Phase F `make verify-all`: chapter 07 §3 and Appendix A carry the summary, with commit, date, environment and every tool version, including WARNs. This chapter does not repeat those numbers, so that the report has one source for each figure.

---

## 11. Limitations

| # | Limitation | Effect | Mitigation or follow-up | Source |
|---|---|---|---|---|
| 1 | **Semgrep packs.** Registry packs are fetched at run time and gated at ERROR severity only. The KPI §2.4 SQLi seed is not confirmed to be in the CI packs. Semgrep cannot run in the sandbox or on Windows. | A rule-set change can alter the result for the same commit. KPI §2.4 is not yet demonstrated. | CI is the authority. Confirm the seed (step 0 item 7). Consider pinning a local rules file [inferred]. | [repo: .github/workflows/ci.yml lines 99–112] [HANDOFF §5, §13] |
| 2 | **ZAP is passive.** Four header rules are `FAIL`. It does not find SQLi. It runs only on `main` with `STAGING_URL`, has never run, and uses a floating image tag. | DAST adds header hygiene only. It cannot block a PR. | Semgrep is the SQLi gate. Set `STAGING_URL` after the first deployment. | [repo: .zap/rules.tsv] [repo: .github/workflows/ci.yml lines 599, 616] |
| 3 | **No Checkov severity data.** "Fail on HIGH" is impossible, so the gate fails on any check, with 121 inline skips. | Skip creep would weaken the gate silently. | Every skip carries a reason. Skips sit next to code that has a code owner. Audits review them. | [repo: .github/workflows/ci.yml lines 327–329] [HANDOFF §3 gap 4] |
| 4 | **The plan role uses `ReadOnlyAccess`.** Any same-repository PR can assume it. | Broad read of the account from a PR workflow [inferred] | Accepted for now, to be replaced in Sprint 3 with a generated least-privilege policy. The `job_workflow_ref` subject customisation is a follow-up. | [repo: infra/terraform/bootstrap/main.tf lines 178–185] [repo: README.md gap 8] [repo: docs/runbooks/repo-admin-setup.md §2b] |
| 5 | **No apply role** (gap 9). Deploys are local S1 applies. | No automated CD and no drift detection until the plan job's variables are set | Deliberate: add an apply role behind a GitHub Environment with required reviewers | [repo: infra/terraform/bootstrap/main.tf lines 217–219] [HANDOFF §3 gap 9] |
| 6 | **The fail-open window.** Until `ENFORCE_GATES=true`, scan findings do not block a merge. | A vulnerable or secret-bearing commit could have merged during the bootstrap period. | The real-outcome outputs block the image push. The four PR runs show the scans passing. D9 flips the variable before the merges. Protection comes last. | [repo: .github/workflows/ci.yml lines 429–461] [repo: docs/plans/depi-phase-f-capstone-complete.md D9, D10] |
| 7 | **Most seeds are unproven.** SAST, SCA, image, DAST and Dockerfile. | Those gates are believed, not shown, to trip | Run `scripts/gate-selftest.sh all` on a machine with Docker and registry access (cutover §1) | [HANDOFF §5, §13] |
| 8 | **Pinning gaps.** Trivy pinned by tag. Gitleaks downloaded without a checksum. No Dependabot for pip. CI env pins bumped by hand. | A compromised upstream release would not be detected by the pin [inferred] | Pin by digest or checksum. Add a pip ecosystem. | §6.2 |
| 9 | **No signed provenance.** The SBOM and `build-info.json` are unsigned. | SLSA Build L0 (§6.3) | A provenance statement per pushed digest [inferred] | §6.3 |
| 10 | **`verify-all` does not cover Semgrep, Trivy or ZAP** | A green local run is not a green pipeline | Stated in the summary footer. CI remains the authority. | [repo: scripts/verify-all.sh line 132] |

---

## Rubric mapping

The DEPI Fall 2026 rubric is not in the repository. The rows below give the items the team must map. The content cells are left empty on purpose.

| Rubric criterion | Where this chapter addresses it |
|---|---|
| [source: plan PDF, not in repo — team to verify] | |
| [source: plan PDF, not in repo — team to verify] | |
| Plan §5 / Figure 5.1 pipeline: fidelity of this chapter to the figure [source: plan PDF, not in repo — team to verify] | |

## 12. References

Only sources from the approved list are cited (plan §6.4). Edition, date and URL are given as the authors believe them, and none has been checked yet. Access date: "accessed —, to be filled when verified".

- **[L1]** NIST. *SP 800-218, Secure Software Development Framework (SSDF) Version 1.1.* National Institute of Standards and Technology, 2022. https://csrc.nist.gov/pubs/sp/800/218/final. Accessed —, to be filled when verified. [verify: edition, date, URL; link not checked]
- **[L2]** NIST. *SP 800-204C, Implementation of DevSecOps for a Microservices-based Application with Service Mesh.* National Institute of Standards and Technology, 2022. https://csrc.nist.gov/pubs/sp/800/204/c/final. Accessed —, to be filled when verified. [verify: edition, date, URL; link not checked]
- **[L3]** NIST. *SP 800-190, Application Container Security Guide.* National Institute of Standards and Technology, 2017. https://csrc.nist.gov/pubs/sp/800/190/final. Accessed —, to be filled when verified. [verify: edition, date, URL; link not checked]
- **[L4]** OWASP Foundation. *OWASP Top 10* (2021 edition; check whether a newer edition is final). https://owasp.org/Top10/. Accessed —, to be filled when verified. [verify: edition, date, URL; link not checked]
- **[L5]** OWASP Foundation. *OWASP DevSecOps Guideline.* https://owasp.org/www-project-devsecops-guideline/. Accessed —, to be filled when verified. [verify: edition, date, URL; link not checked]
- **[L6]** OpenSSF. *SLSA Specification v1.0* (check whether v1.1 is current). https://slsa.dev/spec/v1.0/. Accessed —, to be filled when verified. [verify: edition, date, URL; link not checked]
- **[L7]** Ecma International / OWASP CycloneDX. *ECMA-424, CycloneDX Bill of Materials Specification.* https://cyclonedx.org/specification/overview/. Accessed —, to be filled when verified. [verify: edition, date, URL; link not checked]
- **[L8]** Center for Internet Security. *CIS Amazon Web Services Foundations Benchmark v3.0.0.* https://www.cisecurity.org/benchmark/amazon_web_services. Accessed —, to be filled when verified. [verify: edition, date, URL; link not checked]

[L1] and [L2] frame the pipeline as secure-development practice. [L3] informs §7. [L4] and [L5] name the vulnerability classes and gate types. [L6] is the yardstick in §6.3, and [L7] the SBOM format. [L8] is the source of the default-security-group rule cited in `modules/network` (CIS AWS 5.4) [repo: infra/terraform/modules/network/main.tf lines 46–47]. This chapter uses no statistic from any of these sources.
