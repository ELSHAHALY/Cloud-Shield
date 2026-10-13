# CloudShield — Handoff

**As of:** 14 Oct 2026 (updated after the S3 SOAR build)  **Repo state:** scaffold on `main`; CI fix and SOAR work on branches, PRs pending (§10)
**For:** @ELSHAHALY (S1), @YasseenAbdelghany (S2), @ahklsfg (S3), and anyone picking this up next.

This file records everything done so far, every decision made, what is proven, what is not, and exactly what to do next. Read this first, then `README.md`, then the three ADRs.

---

## 1. Status at a glance

| Area | State |
|---|---|
| Design (Phase 3) | Reviewed. Sound, with gaps documented (§3). |
| Repo scaffold | **Done.** CI, bootstrap, 5 Terraform modules, tests, docs. |
| Independent security audit | **Done.** PASS WITH FIXES; all major findings fixed. |
| Pushed to GitHub | **Yes** (14 Oct, `1019669`). History restarts there: the zip carried no `.git`. |
| Deployed to AWS | **No.** Nothing has been applied. |
| `terraform validate` / `test` | **Pass locally** (TF 1.16.5, §10). The first CI run failed `terraform test`; fixed on `fix/ci-terraform-test-mocks`. |
| App code (S2) | Not started. |
| SOAR Lambda code (S3) | **Built and audited** on `feat/s3-soar-playbooks` (§10). Still switched off: no package uploaded, dry-run on. |
| **Team-size waiver (G1)** | **Unknown. This is still the top risk (R1, H×H).** |

---

## 2. What was done, in order

### 2.1 Design review (8 Oct)

The plan (`CloudShield_Capstone_Plan_and_Architecture.pdf`) was reviewed against the empty repo.

**Verdict:** a strong design. Its two biggest strengths are the separate security account and an automation boundary that stops at CONTAINED. It was implementation-ready, with these gaps:

- The plan's own top risk, R1/G1 (3-person team versus the DEPI minimum of 4), was unresolved.
- G2: the account model was undecided and on the critical path.
- The timeline is aggressive for 3 people. Recommendation: make PB-01 the single flagship playbook; PB-02, PB-03 and PB-05 come only if time allows.
- "Autonomous" in the title overstates the design. It is *automated containment with human-gated eradication*; say exactly that in the viva.
- Missing from the plan: Terraform state location, runtime secrets handling, a steady-state cost model, and the plumbing for ECS Exec.

### 2.2 Scaffold v1 (8 Oct): commit `30ec367`

- **CI pipeline** (`.github/workflows/ci.yml`, originally `security-gates.yml`): six gates, in this order:
  1. Gitleaks (full history)
  2. Semgrep
  3. Trivy fs
  4. Terraform fmt/validate + Checkov
  5. Trivy image + CycloneDX SBOM
  6. ZAP baseline

  The gates are **fail-open** until the repo variable `ENFORCE_GATES=true`. Actions are pinned to commit SHAs. `terraform plan` runs through **GitHub OIDC** with a read-only role, so no AWS keys exist anywhere.
- **`bootstrap/`** (run once, local state):
  - S3 + KMS state bucket with S3-native locking (no DynamoDB table needed)
  - GitHub OIDC provider and a read-only plan role scoped to `ELSHAHALY/Cloud-Shield`
  - Budget alerts at 50%, 100% and forecast 100%
  - EBS encryption by default
- **`modules/network`**: VPC `10.20.0.0/16`, the 4 subnet tiers from §4.4, one NAT, free S3/DynamoDB gateway endpoints, and Flow Logs as Parquet with Hive partitions.
- **`modules/log-archive`**: KMS-encrypted S3 archive with the flow-log delivery policy.
- **Repo files:** ADR-0001, CODEOWNERS, Dependabot, PR template, pre-commit, Makefile.

### 2.3 Planning step (8 Oct)

A separate planning agent produced a delta plan. TB0–TB5 are defined only inside Figure 7.1, so they were read from the figure itself rather than guessed. The team then decided four things (§4).

### 2.4 Build (8 Oct): commit `ea39d48`

- **`network`**: added NLB, app and worker security groups, plus an empty **quarantine** group for PB-01.
- **`compute`**:
  - Always on: ECR (immutable tags, scan on push, KMS), ECS cluster with ECS Exec, and least-privilege execution/task roles.
  - Flag-gated: an internal NLB and Fargate service (needs a digest-pinned image), and the EC2 report-worker (IMDSv2, carries the SOAR scope tag).
- **`data`**:
  - Documents table and audit table, both with point-in-time recovery and KMS.
  - Documents bucket: TLS-only, rejects foreign KMS keys and the SSE-S3 header, and caps pre-signed URL age.
  - The data-plane policy is attached to the app task role.
- **`soar`**:
  - Always on: SNS, incidents table, evidence bucket, SSM dry-run switch (default **on**), and the GuardDuty EventBridge rule. While playbooks are off, findings go straight to SNS email.
  - Flag-gated: 4 Lambdas and the Step Functions state machine `cs-ir-router`.
- **Also added:** CODEOWNERS for all three roles, ADR-0002, offline `terraform test` suites, and `scripts/gate-selftest.sh`.

### 2.5 Independent audit (8 Oct): commit `67e414c`

A separate agent that had not seen the build audited it. Verdict: **PASS WITH FIXES** (10 major, 10 minor). All major findings were fixed:

| ID | Problem | Fix |
|---|---|---|
| M1 | The safety guard **failed open**: a `"false"` string or `null` let the playbook run. | The router now fails closed at three points: guard `allowed`, `dry_run`, and the playbook's `contained`. |
| M2 | KMS for the state machine's logs was missing a grant. | Added a log-delivery decrypt grant. *Unverified, about 70% confidence.* |
| M3 | Lambda trust had an `aws:SourceAccount` condition Lambda doesn't populate, which makes the role unassumable. | Removed. |
| M4 | **PB-01 was unreachable in scenario A**: the IMDS-theft finding is typed `AccessKey`, and Portscan is Medium severity. | That finding type now routes to PB-01. Scenario finding types bypass `min_severity`. |
| M5 | CONTAINED was recorded even if the playbook did nothing. | New `CheckContained` state requires `contained: true`. |
| M6 | Docs claimed the audit table was "append-only" by IAM. That is false: `PutItem` can overwrite. | Docs corrected; a table stream added as tamper evidence. |
| M7 | Docs claimed CODEOWNERS enforced multi-owner review. GitHub accepts any **one** listed owner. | Docs corrected. Two-person review comes from branch protection = 2 approvals. |
| M8 | The gate self-test counted any non-zero exit as a pass. | Now requires the seeded finding to appear in the tool output. |
| M9 | Dedupe stopped re-runs after FAILED or dry-run. | Re-runs are allowed from those states. |
| M10 | SOAR could escalate IAM: `Put*Policy` accepts any document. | Added the `soar-target-boundary` permissions boundary. Playbooks can write policies only onto principals carrying it. |

Of the minor findings, these were fixed: the Lambda concurrency default is now unreserved (new-account quota), the SSE-S3 header is denied, Checkov skip reasons were made honest, and docs were corrected (S3 ABAC wording, the manifest hash goes on the incident row).

---

## 3. Gaps and findings (status)

| # | Finding | Status |
|---|---|---|
| 1 | No Terraform state location in the plan | Handled: S3 + KMS + lockfile |
| 2 | A literal "deny-all" forensics NACL locks the analyst out too | Handled: intra-subnet only. **Decide** how analysts reach evidence. |
| 3 | Hive-partitioned flow logs break the bucket-policy path from the AWS docs | Handled |
| 4 | Open-source Checkov can't do "fail on HIGH" | Fail on any check; every skip has a reason |
| 5 | Interface endpoints cost about $100/month | Off by default |
| 6 | Account-level S3 Block Public Access would stop scenario C from firing | Deliberately not set |
| 7 | One account has weaker isolation than the designed Security account | Accepted (ADR-0001); present multi-account as the target state |
| 8 | The plan role uses `ReadOnlyAccess` | Accepted; tighten in Sprint 3 |
| 9 | No apply role in CI | Deliberate, for now |
| 10 | **PB-01 security-group swap doesn't cut existing connections** | **Handled (ADR-0003):** a deny-all on the dedicated worker-tier NACL, add-only IAM. Residual risk: DNS via the Resolver isn't filtered (follow-up: DNS Firewall). |
| 11 | Tenant isolation lives in the API, not IAM | Accepted; stretch goal: STS session tags with `LeadingKeys` |
| 12 | PB-03 is bounded by bucket-name prefix, not tag | Accepted; the scenario C bucket must be named `cloudshield-dev-*` |
| 13 | Sample findings conflict with the safety guard | Resolved: dry-run only |
| 14 | The ZAP gate could never fail | Fixed: header rules set to FAIL |
| 15 | Audit table is insert-only by convention only | Mitigated: no Update/Delete permission, conditional write, stream, PITR |
| 16 | No S3 access logs on the documents and evidence buckets | **Open (S3):** CloudTrail data events come with `detection` |
| 17 | New-account Lambda quota rejects reserved concurrency | Default unreserved |

---

## 4. Decisions log

| Date | Decision | Where recorded |
|---|---|---|
| 8 Oct | **Single AWS account first.** Module boundaries allow a later split. | ADR-0001 |
| 8 Oct | Scaffold = **real resources only**. Code-dependent pieces are written in full but **off behind flags**. | ADR-0002 §2 |
| 8 Oct | Roles: **S1 @ELSHAHALY, S2 @YasseenAbdelghany, S3 @ahklsfg** | CODEOWNERS, README |
| 8 Oct | **MTTC** runs from the EventBridge event `time` to the `MarkContained` state. GuardDuty's `createdAt` is also stored. Evidence capture runs after CONTAINED and doesn't count. | ADR-0002 §3 |
| 8 Oct | Ingress: **internal NLB with a REST API Gateway VPC Link** | ADR-0002 §4 |
| 8 Oct | PB-01 is the flagship playbook; finish it end to end before the others | soar/README.md |
| 14 Oct | Lambda runtime stays **python3.13** (as in the audited TF), not 3.12 | soar/pyproject.toml |
| 14 Oct | Gap 10: **subnet-level deny-all on a dedicated worker NACL**. A per-IP NACL rule can't match the instance's own traffic; an SSM kill was rejected. | ADR-0003 |
| 14 Oct | PB-03 handles **only `Policy:S3/Bucket*`**; other S3 findings go to an analyst. Its evidence is a post-CONTAINED router step. | state-machine.tf, soar/README.md |

---

## 5. Verification record (what is actually proven)

| Check | Result |
|---|---|
| Checkov | ✅ 540 passed / 0 failed / 52 skips, each with a reason |
| HCL format (same library as `terraform fmt`) | ✅ clean |
| actionlint on `ci.yml` | ✅ |
| State-machine graph | ✅ 19 states, all reachable. CONTAINED is reachable only through `CheckContained`, playbooks only through the guard. |
| Full-history Gitleaks on the repo | ✅ no leaks, no account IDs |
| Gate seed: secrets, IaC | ✅ tripped on the planted finding |
| Gate seed: SAST | ⚠️ trips Semgrep `tainted-sql-string`. Not yet confirmed to be in the `p/owasp-top-ten` / `p/nodejs` packs. |
| Gate seeds: SCA, image, DAST | ❌ not run (Trivy DB, Semgrep registry and Docker blocked in the build environment) |
| `terraform validate`, `terraform test` | ❌ **not run.** The first CI push is the real test. |
| Unverified AWS behaviour | KMS log-delivery grant for Step Functions (M2); the `iam:PermissionsBoundary` condition on `Put*Policy`; whether KMS sees `aws:SourceAccount` when EventBridge publishes to the encrypted SNS topic (if notifications fail, drop that condition) |

---

## 6. Next actions

### Everyone, first

- [ ] **G1:** get the written ministry waiver for the 3-person team, or add a 4th member. Nothing else matters if the submission is invalid.
- [ ] **G4:** confirm the real AWS budget, then set `monthly_budget_usd` in `bootstrap/terraform.tfvars`.

### S1: @ELSHAHALY

- [ ] Push the repo. Unzip into your clone, keep the 4 commits, and `git push`.
- [ ] Invite @YasseenAbdelghany and @ahklsfg as collaborators with **Write** access.
- [ ] Watch the first CI run; this is where `validate` and `test` run for the first time. Fix anything red.
- [ ] `bootstrap/`: `terraform apply`. Back up its local state. Confirm the budget emails.
- [ ] `environments/dev`: `terraform apply`. Then run `aws guardduty create-detector --enable`.
- [ ] Set the repo variables `AWS_PLAN_ROLE_ARN`, `TF_STATE_BUCKET`, `TF_STATE_KMS_KEY_ARN` and `AWS_REGION`.
- [ ] Branch protection on `main`: 2 approvals, Code Owner review, the 5 gate checks required, no force push.
- [ ] Run `scripts/gate-selftest.sh all` on a laptop with Docker. Every gate must show ✓. Then set `ENFORCE_GATES=true`.
- [ ] Build the `edge` module: REST API Gateway + VPC Link → `module.compute.nlb_arn`, WAF ×2, CloudFront. Add an ECR push role (OIDC, `main` only, push by digest).

### S2: @YasseenAbdelghany

- [ ] Write `app/openapi.yaml` (contract first).
- [ ] Build `app/docs-api/`: Express, a `Dockerfile` (non-root, works with a read-only root filesystem, writes only to `/tmp`), `/healthz`, Cognito JWT checks, a tenant claim on every key, and audit writes using `attribute_not_exists(eventKey)`.
- [ ] Build the `identity` module (Cognito, MFA, RBAC groups).
- [ ] Point `container_image` at the pushed `@sha256:` digest.

### S3: @ahklsfg

- [ ] Write `soar/safety_guard` with **pytest first**. Follow the rule order and return contract in `soar/README.md`.
- [ ] Write PB-01 `isolate` and `snapshot`. Choose the established-connection fix (gap 10) and add its IAM.
- [ ] Zip the package, set `soar_playbook_package` with `soar_dry_run = true`, and test with GuardDuty sample findings.
- [ ] Set `enable_report_worker = true` and run scenario A in dry-run. Then flip dry-run off and measure MTTC.
- [ ] Build the `detection` module: GuardDuty detector, CloudTrail with S3 data events, Glue tables, an Athena workgroup with a scan cap, and Config rules.

---

## 7. How to resume

```bash
# Local checks (needs terraform, checkov, gitleaks, semgrep, trivy)
make fmt validate test        # format, validate every root+module, offline tests
make iac                      # + checkov
scripts/gate-selftest.sh all  # prove each gate trips

# Deploy (S1)
cd infra/terraform/bootstrap && terraform init && terraform apply
cd ../environments/dev
cp backend.hcl.example backend.hcl && cp terraform.tfvars.example terraform.tfvars
terraform init -backend-config=backend.hcl && terraform plan -out=tfplan && terraform apply tfplan

# Stop paying when idle (~$37/month otherwise)
terraform destroy
```

### Feature flags (`environments/dev` variables, all off by default)

| Variable | Turns on |
|---|---|
| `container_image` (digest-pinned) | NLB + Fargate service |
| `enable_report_worker` | EC2 forensic target |
| `soar_playbook_package` | Lambdas + `cs-ir-router` |
| `soar_dry_run = false` | Playbooks really act |
| `allow_worker_lab_scan` | Scenario A port-scan window only |

---

## 8. Gotchas worth knowing

- **Never** put the `cloudshield:soar-scope` tag in provider `default_tags`. That would make every resource fair game for automation.
- The SOAR router **fails closed**. Lambdas must return real booleans (`allowed`, `dry_run`, `contained`). Anything else is recorded as BLOCKED, WOULD_CONTAIN or FAILED.
- `AKIAIOSFODNN7EXAMPLE` is allowlisted by Gitleaks. Don't use it to test the secrets gate.
- ZAP baseline is passive and won't find SQLi. Semgrep is the gate for that.
- Object Lock (log archive, evidence) is off by default because it blocks `terraform destroy`. Turn it on only for the graded run.
- Terraform 1.16 and AWS provider v6: `data.aws_region.*.region`, not `.name`.

---

## 9. Reference map

| What | Where |
|---|---|
| Setup steps, feature flags, testing, MTTC | `README.md` |
| Single-account decision and its trade-offs | `docs/adr/0001-single-account-first.md` |
| Module map, flags, MTTC, NLB, known limits | `docs/adr/0002-module-map-and-scaffold-strategy.md` |
| SOAR handler contract, guard rules, PB-01 notes | `soar/README.md` |
| Attack-sim rules (AWS Abuse risk R4) | `attack-sim/README.md` |
| Ownership | `.github/CODEOWNERS` |
| Source design | `CloudShield_Capstone_Plan_and_Architecture.pdf` (not in repo) |

---

## 10. Update 14 Oct: CI fix + S3 SOAR build

### CI (branch `fix/ci-terraform-test-mocks`)

- **What failed:** the first run on `1019669` failed only in the iac gate at `terraform test`. The other gates passed.
- **Cause:** a bare `mock_provider "aws" {}` returns random strings, so every IAM policy JSON and every ARN failed provider validation.
- **Fix:** pin realistic mock values.
- **Also on this branch:** `docs/runbooks/repo-admin-setup.md`, with `gh` commands for collaborators, repository variables and branch protection (S1).

### SOAR (branch `feat/s3-soar-playbooks`)

**The pipeline:** Planner → Builder → Independent Auditor → fixes → Validator.

**What was built:**
- `soar/`: the core object model, the safety guard, and PB-01, PB-02 and PB-03.
- 144 pytest + moto tests at 97% branch coverage.
- `make package-soar`, which builds a deterministic zip.
- A hard-failing CI job, `gate: soar (ruff + pytest)`. Semgrep now also runs `p/python`.

**Audit:** PASS WITH FIXES, 3 MAJOR and 9 MINOR findings, all addressed.

| ID | Finding | Fix |
|---|---|---|
| A1 | PB-03 marked any S3 finding contained, including exfiltration that BPA can't stop | Router + PB-03 accept `Policy:S3/Bucket*` only |
| A2 | PB-02 treated a refused session revocation as success | Session revoke is part of `verified`; `ASIA` keys deactivate the long-term keys |
| A3 | PB-01 could contain credential exfiltration without revoking the stolen role | The role must exist and match the finding's role id; revoke read back via `GetRolePolicy` |
| A4 | PB-03 evidence counted toward MTTC and could time out | New `PB03Evidence` router step after CONTAINED; single-attempt pre-state reads; timeout 30 s |
| A5 | Checkov | NACL skips with reasons; `DescribeInstanceAttribute` scoped to instances. Result: 546 passed, 0 failed |
| A6 | IAM breadth | Evidence writes limited to `incidents/*`; pre-empting NACL entries detected; the rest documented as accepted risk |
| A7 | ADR-0003 silent on what the NACL can't block | Limits documented |
| A8 | Retries weren't idempotent | Snapshot reuse; append-only evidence records with the first hash kept; no duplicate `previousGroups` |
| A9 | No allowance for eventual consistency | Verify retries 3× at 1 s |
| A10 | Tests couldn't see IAM content | `tests/iam.tftest.hcl` renders real policies, mutation-checked; env-var drift parser fixed |
| A11 | Docs overclaimed | Corrected |
| A12 | Revoke cutoff had milliseconds | Whole seconds, rounded up |

**Proven locally** (Windows, CI-pinned versions):
- ruff passes; pytest 144/144.
- `terraform fmt` is clean; `validate` passes in all 7 dirs; `test` passes 18/18.
- Checkov 3.3.26: 0 failed.
- Gitleaks 8.30.1: no leaks in history.
- The zip is byte-identical across two builds.

**Not proven:**
- Semgrep: `semgrep-core` crashes on Windows, so the first PR's CI run is the proof.
- No AWS apply yet. Live IAM behaviour stays unverified until the dry-run replay below.

### Next for S3

1. Merge both PRs. Add `gate: soar (ruff + pytest)` to the required checks.
2. Upload the zip to a versioned bucket. Set `soar_playbook_package` with dry-run **on**.
3. Replay GuardDuty sample findings; each must end `WOULD_CONTAIN_DRY_RUN`. Then run scenario A in dry-run.
4. Flip dry-run off and measure MTTC.
5. Follow-ups: a DNS Firewall quarantine (ADR-0003); the honeytoken user with the SOAR target boundary (PB-02 needs it to count as contained).

---

## 11. Update 14 Oct: S3 Phase C — detection, Athena hunting, attack sims

Branch `feat/s3-detection-athena-sims` (off `feat/s3-soar-playbooks`). Pipeline: Planner → Builder → Independent Auditor → fixes → Validator. Plan: `docs/plans/s3-detection-athena-sims.md`.

### What was built

- **`modules/detection`** (new): GuardDuty detector (+ findings export to the log archive; paid S3/runtime/malware protections off), Security Hub (off; CIS v3.0.0 + PCI DSS v3.2.1 behind flags), AWS Config (recorder scoped to `AWS::S3::Bucket` for cost, the two S3 public-access rules, NON_COMPLIANT → SOAR topic), multi-region CloudTrail with **S3 data events on exactly the evidence and documents buckets** (closes gap 16), and the **`<name>-cs-forensics` Athena workgroup** (enforced 1 GiB/query scan cap, KMS results) with a Glue catalog (partition projection) for `cloudtrail`, `vpc_flow_logs` and `guardduty_findings`.
- **`modules/log-archive`**: added per-service delivery statements (CloudTrail, Config, GuardDuty export) on the bucket and key, each scoped to its own prefix + `aws:SourceArn`/`aws:SourceAccount`. Output `depends_on` the policies so a first-apply delivery can't race.
- **`modules/lab-targets`** (new, `enable_lab_targets`, default off): a honeytoken IAM user (SOAR target boundary, scope tag, **no access key in state**) and a tagged `*-lab-exposure` bucket (BPA on at rest). For scenarios B and C.
- **`detection/athena-queries/`**: three parameterised hunt queries (FR-8), one per scenario, each partition-filtered under the scan cap.
- **`soar/tools/generate_ir_report.py`**: IR report from an incident id. Recomputes every evidence SHA-256 from S3 (chain-of-custody check; exit 2 on mismatch) and MTTC vs the 60 s target. `make ir-report INCIDENT=<id>`.
- **`soar/sims/`**: R4-gated attack-sim suite. `replay --target local` drives an in-process router (CI); `replay --target aws` StartExecutions the real `cs-ir-router` and asserts **MTTC < 60 s**; `live-aws` is operator-run. Scenario A uses live containment with replayed detection (decision D4): credentials never leave the instance. `make sim`.

### Decisions (14 Oct)

| # | Decision |
|---|---|
| D1 | SQL in `detection/athena-queries/`; Python tools + sims under `soar/` (shared `core/`, one CI job). |
| D2 | Gated `lab-targets` module; no access key in Terraform state (sim creates/deletes it at runtime). |
| D3 | Core detection on (GuardDuty, CloudTrail, Config-S3, Athena); Security Hub + paid GuardDuty protections off. |
| D4 | Scenario A live = real PB-01 containment + synthetic detection; no credential leaves the instance. |

### Audit: PASS WITH FIXES (1 MAJOR, 5 MINOR), all fixed

| ID | Finding | Fix |
|---|---|---|
| A1 | The per-target scope gate (`assert_in_scope`) was **dead code**: the sim reached `StartExecution` without checking the target's prefix/tag. | `sims.safety.verify_targets` reads each target's live tags and refuses anything out of scope, before any pipeline call — independent of the SOAR guard. |
| A2 | Region gate skipped when the client region was unset. | Fail closed on an unresolved region. |
| A3 | `replay --target aws` passed on CONTAINED when MTTC couldn't be computed. | CONTAINED now requires a real MTTC < 60 s. |
| A4 | The "router parity" test asserted strings, never calling `_route`. | It now routes every scenario event and compares to `state-machine.tf`. |
| A5 | `detection.tftest.hcl` mocked away all policy JSON. | New `tests/policies.tftest.hcl` renders the real Config role/trust and Athena key policies and asserts their scoping. |
| A6 | `--target local` silently used live AWS. | Documented; the A1 gate now runs there too. |

Audit confirmed sound: the delivery IAM/KMS/bucket policies (least-privilege, per-prefix, SourceArn-scoped), the apply-ordering `depends_on`, the enforced Athena scan cap, the Glue schemas vs the real log layouts, the three queries, and the IR report's hash/MTTC logic.

### Proven locally (Windows, CI-pinned versions)

- ruff clean; pytest **182** at 95% branch coverage (tools + sims included).
- `terraform fmt` clean; `validate` all dirs; `terraform test` **32/32** (detection 12, lab-targets 1, log-archive 2, soar 11, compute 5, data 2 — minus duplicates).
- Checkov 3.3.26: **0 failed** (Config-S3-only and GuardDuty-single-account skips documented).
- Gitleaks: no leaks. Lambda zip still byte-identical (tools/sims are not shipped in it).

**Not proven:** Semgrep (crashes on Windows → first CI run); no AWS apply, so live GuardDuty/Config/Athena behaviour and real MTTC stay unverified until a dry-run replay in the lab.

### Next for S3

1. Merge PR #1 (SOAR engine) first, then this PR.
2. Deploy: `enable_lab_targets = true`, upload the SOAR zip, set `soar_playbook_package` with dry-run **on**.
3. `make sim SCENARIO=c MODE=replay TARGET=aws ...` → expect `WOULD_CONTAIN_DRY_RUN`; then dry-run off and measure MTTC; run the three hunt queries; generate the IR report.
4. If a detector/recorder already exists in the region, import it or set `manage_guardduty_detector = false` / `enable_config = false` (detection/README.md).
