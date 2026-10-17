# CloudShield — Handoff

**As of:** 17 Oct 2026 (updated after Phase F)  **Repo state:** scaffold on `main`; PRs #1 → #2 → #3 → #4 → Phase F PR stacked and pending review (§10–§14). The merge and cutover steps are in [final-merge-and-cutover.md](runbooks/final-merge-and-cutover.md).
**For:** @ELSHAHALY (S1), @YasseenAbdelghany (S2), @ahklsfg (S3), and anyone picking this up next.

This file records everything done so far, every decision made, what is proven, what is not, and exactly what to do next. Read this first, then `README.md`, then the six ADRs.

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
| App code (S2) | **Built and audited** on `feat/s2-app-soc-ui-grc` (PR #4, §13): docs-api, SPA (portal + SOC + GRC hub), local compose. Not deployed. |
| SOAR Lambda code (S3) | **Built and audited** on `feat/s3-soar-playbooks` (§10). Still switched off: no package uploaded, dry-run on. |
| Capstone deliverables (Phase F) | **Written** (§14): reports 01–07 in `docs/reports/`, the live demo runbook, a 20-slide deck outline, `make verify-all` and the cutover runbook. |
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

---

## 12. Update 16 Oct: Phase D — edge, identity, WAF, PB-04/PB-05, SOAR enhancements

Branch `feat/s1-s2-edge-identity-waf` (stacked on #2). Plan: `docs/plans/s1-s2-edge-identity-waf.md`. Design records: **ADR-0004** (edge, identity, WAF) and **ADR-0005** (PB-04 / PB-05). Pipeline: Planner → Builder (3 stages) → Independent Auditor → Validator (fixes + gates).

### What was built

| Area | Owner | Summary |
|---|---|---|
| `modules/identity` | S2 | Cognito: TOTP MFA (`ON` default, `OPTIONAL` allowed), admin-only sign-up, 14-char passwords, user-existence errors prevented, immutable non-writable `custom:tenant_id`, SPA client (no secret, SRP + refresh), groups `admin` / `member` / `auditor` / `secops-analyst`. Always on. |
| `modules/edge` | S1 | One CloudFront distribution (`/*` → private SPA bucket via OAC; `/api/*` → REGIONAL REST API + VPC Link + Cognito authorizer). CloudFront WAF: SoarBlockedIps (PB-05), IP reputation, `SoarApiRateLimit` (`/api/*`, feeds PB-05), site-wide `RateLimitPerIp` (429), Common, KnownBadInputs. Regional WAF: origin-verify header, KnownBadInputs, SQLi. CSP + security headers; no `custom_error_response`. Behind `enable_edge` (default **off**, ≈ $20/month). Requires region us-east-1 (no provider alias: TF 1.16.5 standalone `validate` fails with `configuration_aliases`). |
| CI / compute | S1 | GitHub-OIDC ECR push role (exact `main` ref); the image is pushed only when Trivy **and** the secrets/SAST/SCA scans really passed, even in fail-open mode. PB-04 prerequisites: `stopTimeout = 2`, optional scope tag on the ECS service. |
| WAF logs + hunting | S3 | `aws-waf-logs-*` bucket (Authorization / cookie / origin header redacted), Glue `waf_logs` table, hunt query `04`. |
| **PB-04** ECS containment | S3 | Proves task ↔ service membership with `ListTasks`, captures task metadata, `StopTask`, `forceNewDeployment`, verifies the specific new deployment + dead processes; evidence after CONTAINED. Needs GuardDuty Runtime Monitoring (off by default). |
| **PB-05** edge IP block | S3 | Dedicated event bus (Deny for unlisted publishers); harvester publishes an IP only after **2 consecutive** harvests of the `/api/*` rate rule; PB-05 re-checks the IP rules and never-block list and **corroborates with WAF's own rate-limited keys** before an add-only, lock-token `UpdateIPSet` + read-back. **Auto-expiry sweeper** lifts blocks after `blockExpiresAt` (24 h), remove-only. |
| Enhancements | S3 | ChatOps notifier (webhook URL from SSM SecureString; https + exact host allow-list, no redirects/proxies; never raises into SNS; 4-grant IAM). IR report: executive triage (ATT&CK, impact, eradication/recovery) + PB-03 Terraform remediation snippet. Opt-in LLM summary (`tools/ai_summary.py`; off by default; redacted; `claude-opus-5-5` via the Messages API; never in the Lambda zip). |
| Sims D / E | S3 | Replay-local only, dry-run forced (cannot act even if the SSM switch flips mid-run). |

### Decisions (16 Oct, beyond the plan)

| # | Decision |
|---|---|
| D18 | Scope tag stays `cloudshield:soar-scope=in-scope` (the brief's `soar-enabled=true` was not adopted). |
| D9′ | No provider alias in `modules/edge`; region preconditions instead. |
| D15′ | **Auto-expiry** of PB-05 blocks (user choice, audit A2): a sweeper removes only expired, row-tracked addresses. Automation still stops at containment; workload recovery stays human. |

### Audit: FAIL → fixed (2 MAJOR, 9 MINOR)

| ID | Finding | Fix |
|---|---|---|
| A1 | PB-05 trusted caller-written "edge / fresh" fields: anyone able to start the router could block any public IP. | PB-05 corroborates with `GetRateBasedStatementManagedKeys`, re-reads never-block, re-checks IP rules; edge type allow-list. |
| A2 | A short rate-limit became an indefinite block for everyone behind a shared IP. | `/api/*`-scoped feeding rule, 2-harvest persistence, auto-expiry sweeper; shared-egress risk documented. |
| A3 | Untracked blocks possible; tool advised removing still-wanted blocks. | Row written before `UpdateIPSet`; tool groups by address, reports expired / lost / orphan. |
| A4 | PB-04 ownership "proof" forgeable via `group`/`startedBy`. | `ListTasks(serviceName)` membership. |
| A5 | Routing by `type`, guard by target. | Type-based choices also require `resourceType`; bus rule pinned to `CloudShield:IPAddress/`. |
| A6 | Router-parity test could pass for the wrong reason. | Shared `route_choices.json` asserted by both terraform test and pytest. |
| A7 | ID tokens visible in WAF sampled requests. | Sampling off on both ACLs. |
| A8 | Untrue Checkov reason (SPA bucket). | SPA bucket added to CloudTrail data events. |
| A9 | CI could push an image from a commit that failed other gates. | Push requires every gate's real outcome; OIDC `job_workflow_ref` customisation documented as follow-up. |
| A10 | Dry-run race in sims D/E. | Dry-run forced for D/E. |
| A11 | Recreating the IP sets drops blocks silently. | Documented; tool reports "lost". |

### Proven locally (Windows, CI-pinned versions)

- ruff clean; pytest **622** passed, coverage **97.45 %** (gate 95 %).
- `terraform fmt` clean; `validate` in bootstrap, dev and all 10 modules; `terraform test` **84/84** (compute 12, data 2, detection 14, edge 11, identity 8, lab-targets 1, log-archive 3, soar 33).
- Checkov 3.3.26: **922 passed, 0 failed** (117 skips, each with a reason). Gitleaks: no leaks. actionlint clean. Lambda zip deterministic (`core`, `notifier`, `playbooks`, `safety_guard`).

**Not proven:** Semgrep (Windows) → PR #3 CI; nothing applied to AWS. The verify-on-first-apply list is in ADR-0004 §9 / ADR-0005 (ECS condition keys, `ListTasks` resource type, WAF alarm dimensions for CLOUDFRONT scope, rate-key listing on a scoped rule, bus Deny vs an admin, KMS on the new DynamoDB tables, `CloudFront-Viewer-Address` forwarding, webhook delivery, the Messages API request).

### Next

1. Review/merge **#1 → #2 → #3** (CODEOWNERS now spans S1/S2/S3 on edge, identity and compute).
2. S1: apply `bootstrap` (new output `github_oidc_provider_arn`), set `AWS_ECR_PUSH_ROLE_ARN` / `ECR_REPOSITORY`; optionally customise the OIDC subject (runbook).
3. Lab apply with `enable_edge = true` only when needed (cost); run `docs/runbooks/edge-waf-demo.md` against our own distribution; work through the verify-on-apply list.
4. Phase E: Node `docs-api` (decoy route publishes a **corroborated** edge type to the PB-05 bus), React SOC dashboard (`secops-analyst`), `docker-compose`.

## 13. Update 17 Oct: Phase E — docs-api, SPA (portal + SOC), Regional GRC hub, local stack

Branch `feat/s2-app-soc-ui-grc` → **PR #4** (stacked on #3; merge #1 → #2 → #3 → #4). Plan: `docs/plans/s2-app-soc-ui-grc.md`. Design record: **ADR-0006** (decisions D1–D28, build-time deviations, audit amendments, residual risks, follow-ups); ADR-0005 and ADR-0002 §5 amended. Pipeline: Planner → Builder (3 stages) → Independent Auditor → Validator.

### What was built

| Area | Owner | Summary |
|---|---|---|
| Terraform deltas | S1 / S2 / S3 | Data policy narrowed to `tenants/*` (+ `GetObjectVersion`, `DeleteObjectVersion`). Compute: ECR posture read on the app repo only; task-definition env injects `APP_IMAGE`, filters and refuses every local-mode key (`AUTH_LOCAL_*`, `AWS_ENDPOINT_URL[_*]`, `S3_PUBLIC_ENDPOINT`, `CLOUDSHIELD_ENV≠aws`). `soar/app-integration.tf`: read-only SOC policy (GetItem; Query on the GSI only; evidence reads under `incidents/*`; `kms:Decrypt` via DynamoDB/S3/SSM; dry-run parameter) and a `PutEvents` grant pinned to source + detail-type; the bus publisher list is derived. Edge: `enable_decoy_route` (off). Dev: `enable_decoy_route` / `enable_decoy_publisher` (off), `spa_build_environment` output. |
| SOAR | S3 | `EDGE_NOTIFY_ONLY_TYPES = {DecoyRouteHit}`: the guard records + notifies, never allows; PB-05 still refuses it. `tools/export_attack_table.py` feeds docs-api triage (CI `--check`). Golden chain-of-custody fixtures shared by pytest and Jest. |
| `app/openapi.yaml` | S2 | OpenAPI 3.1 contract: the request validator, the test-time response validator, and generated types for both packages (CI drift check). |
| `app/docs-api` | S2 | Express 5 / TS on distroless Node 24 (Debian 13), 1000:1000, read-only rootfs. Cognito ID-token re-verification; tenant from the token only; RBAC + ABAC; documents (upload through the API with SHA-256 + magic bytes + SSE-KMS; version-pinned pre-signed downloads; tombstone delete; every change + its audit event in one transaction); insert-only audit; click-through DPA/SLA acceptance gating writes; **notify-only decoy**; **SOC read model** (one GSI query per status, allow-listed projection, MTTC + CoC parity with the Python IR tool, posture); GRC rules engine. |
| `app/spa` | S2 | React 19 + Vite + Tailwind. Portal (documents, audit, onboarding), **SecOps SOC dashboard** (posture banner, MTTC gauge, ATT&CK bars, incidents, SOAR timeline, evidence + IR report download), **Regional GRC hub** (EG / EU / SA) and shared-responsibility matrix. Amplify v6 SRP + TOTP with `sessionStorage`; no inline script/style; the local sign-in is compiled out of production builds. |
| `app/grc` | S2 / S3 | Ruleset `2026.10.0` (32 rules: EG-PDPL, EG-CBE, EU-GDPR, SA-PDPL, SA-NCA), matrix (AWS built; Azure/GCP mapped), platform facts, DPA/SLA **templates**. **Not legal advice**; every non-GDPR citation is `verify`. Residency/transfer rules report GAP for EG/SA/EU tenants by construction (us-east-1). |
| Local stack | S2 / S1 | `docker-compose.local.yml`: moto 5.2.4, dev-only local IdP, idempotent seed (refuses non-local endpoints), the production docs-api image in local mode, the SPA on nginx at `http://localhost:3000`. `make local-up local-smoke local-down` ([runbook](runbooks/local-dev.md)). |
| CI | S1 | New hard-failing **`gate: app (lint + typecheck + test + build)`** (moto service, Jest + Vitest coverage gates, OpenAPI drift, cognito build without `local-idp`, hadolint, compose config). Image built with context `app/` and the real gate outcomes as build args; push also needs `app`. Semgrep `p/typescript` + `p/react`; Checkov `--framework dockerfile`; optional `app-smoke`. Dependabot npm ×3, docker ×3, docker-compose. |

### Audit: PASS WITH FIXES (0 critical, 0 high, 2 medium, 8 low, 2 info)

All fixed in commit `b1d4543`, each with a regression test (table in ADR-0006 "Audit amendments"). The two medium ones:

- **E1**: a title cut mid-surrogate made every download of that document a 500, after an audit event had already been written.
- **E2**: the orphan-upload cleanup needed `s3:DeleteObjectVersion`, so orphans would never have been erased.

The lows tighten the pre-auth limiter (E3), DynamoDB error mapping (E4), honest ECR (E5) and evidence (E6) wording, decoy audit flooding via IPv6 rotation (E7), the Terraform env filter (E8), input echo in errors (E9) and cursor validation (E10). The audit found tenant isolation, authz, the local-auth coupling and the notify-only decoy path sound.

### Proven

- **Linux CI on PR #4 (`471a0e4`): every job green**, including `gate: app` and `app-smoke`. The scan steps really passed (not fail-open): Semgrep 95 rules, 0 findings (first run of `p/typescript` / `p/react`); Trivy image 0 fixable CRITICAL/HIGH; SBOM uploaded; Dependabot config accepted (`docker-compose` ecosystem valid).
- Locally after the audit fixes (Linux, CI-pinned versions): docs-api Jest **290 tests / 17 suites** on moto (94.5 % lines, 86.8 % branches; gates 90 / 85); SPA Vitest **50** (96.3 % lines); local-dev Jest 5; `make local-smoke` **8/8**; SPA renders with no console/CSP errors (headless Chromium); `terraform test` **110/110** (compute 22, data 6, detection 14, edge 14, identity 8, lab-targets 1, log-archive 3, soar 42); `validate` 11/11; `fmt` clean; Checkov 953 terraform + 202 dockerfile passed, 0 failed; Trivy fs and image clean; Gitleaks clean; hadolint + actionlint clean; ruff clean, pytest 97.6 %.

**Not proven:** nothing applied to AWS. moto does not enforce IAM, KMS key ids, bucket policies or Object Lock retention reads. The verify-on-first-apply list is plan §16 / ADR-0006 (viewer address through HTTP_PROXY incl. IPv6; NONE decoy routes vs `{proxy+}`; conditioned `PutEvents` vs the bus Deny; GSI Query with `kms:Decrypt` via DynamoDB; Object Lock error codes; pre-signed SSE-KMS + `VersionId` downloads; cross-table transactions; distroless 1000:1000; Amplify SRP + TOTP under the CloudFront CSP; ZAP; `/soc/posture` gates).

**Open [verify] legal items** (UI shows a badge on each): Egypt PDPL article content and Executive Regulations status; all CBE instruments; KSA PDPL amendments, dates, transfer and breach rules; NCA ECC-2:2024 / CCC / NDMO; AWS EU–US DPF participation; Egypt E-Signature Law No. 15 of 2004.

### Environment notes (build sandbox)

The build sandbox blocked `registry.terraform.io` and `semgrep.dev`, and intercepts TLS. Terraform ran from a local provider mirror (aws 6.69.1, random 3.9.1 from releases.hashicorp.com); images were built from scratch copies of the Dockerfiles that only add the proxy CA as a BuildKit secret (the committed Dockerfiles are unchanged). CI is the authority for both.

### Next

1. Review/merge **#1 → #2 → #3 → #4**. CODEOWNERS now asks S2 + S1 on auth/config/Dockerfile/compose, and S2 + S3 on soc/, decoy/, grc/ and `app-integration.tf`.
2. Repo admin: add the required check **`gate: app (lint + typecheck + test + build)`** (runbook `repo-admin-setup.md`); set `ENFORCE_GATES=true` once `scripts/gate-selftest.sh all` is green (now including the dockerfile seeds). Install the Claude GitHub App on the repo if PR events should reach agent sessions.
3. First lab apply with `container_image` + `enable_edge`: deploy the SPA (`docs/runbooks/spa-deploy.md`), create each tenant's first admin (`tenant-provisioning.md`, tenant-id format D7, onboarding D26), work through the verify list. Decoy flags stay off until verify items 1–3 pass.
4. Before the demo: have every `verify` legal item checked against the official text, or present it explicitly as unverified.
5. Follow-ups recorded in ADR-0006: a WAF-corroborated decoy block, an audit-stream tamper consumer, STS session tags with `dynamodb:LeadingKeys`, a separate SOC read service, GuardDuty Malware Protection for uploads, and a decoy attack sim.

---

## 14. Final Capstone Completion (17 Oct): Phase F — verify-all, cutover, reports, demo, deck

Branch `feat/depi-phase-f-capstone-complete`, from `feat/s2-app-soc-ui-grc` @ `9adc96d`. It becomes the Phase F PR, stacked on PR #4. Plan: [`docs/plans/depi-phase-f-capstone-complete.md`](plans/depi-phase-f-capstone-complete.md), with Planner → Builder → Independent Auditor → Validator, as in earlier phases. Almost no product code changed: no API, no Lambda and no IaC behaviour changed apart from one opt-in variable.

### What was built

| Deliverable | Where | Notes |
|---|---|---|
| One local gate run | `scripts/verify-all.sh`, `make verify-all` | Runs preflight → terraform → soar → docs-api → spa → checkov (+ hadolint) → gitleaks → actionlint → local-smoke, each mirroring its CI job, and stops at the first failure. Prints a summary per domain (colour on a TTY only, `NO_COLOR` honoured). Exit codes: 0 pass, 1 check failed, 2 prerequisite missing, 3 tree changed. `VERIFY_ALLOW_SKIP=1` skips a domain whose tool is missing and reports INCOMPLETE. `VERIFY_COMPOSE_NO_BUILD=1` uses pre-built images. Terraform runs on a scratch copy, so no lock files land in the tree. Not covered: Semgrep, Trivy, ZAP (CI is the authority). |
| Merge and cutover runbook | `docs/runbooks/final-merge-and-cutover.md` | Merge commits only, in the order #1 → #2 → #3 → #4 → Phase F. Each PR is retargeted explicitly and then updated (`update-branch`) so CI runs fresh. `ENFORCE_GATES=true` is set after `gate-selftest.sh all` and **before** the merges. Branch protection comes **last**, with 7 required checks. Includes REST equivalents for agent sessions. |
| Compliance Readiness Pack | `app/spa/src/grc/readinessPack.ts`, GRC hub buttons | A client-side Markdown/JSON export of the loaded assessment. It carries the banner "Not legal advice. Not an audit or certification.", the server disclaimer, provenance (ruleset version + SHA-256, profile version, generated/exported times), per-framework tables with a VERIFY marker on every unverified citation, customer actions and the residency note. All ruleset text is escaped. No API change; not audited and not signed. |
| Object Lock pass-through | `environments/dev` `evidence_object_lock_days` (default 0) | Must be set before the first apply. Needed for demo act 5 on the AWS track. |
| Capstone reports | `docs/reports/README.md`, `01`–`07` | One legend, one numbers policy and one MTTC definition (classes M0–M4). Every number cites a file, a CI run or this file. Items from the plan PDF, rubric or WBS that are not in the repo carry `[source: plan PDF, not in repo — team to verify]`. External sources are limited to the approved list, all marked `[verify]` (links not checked from the sandbox). |
| Live demo runbook | `docs/runbooks/live-demo-runbook.md` | 15 minutes, 5 acts. The **offline track is primary**; the AWS lab track is used only if it was applied and rehearsed by T-24h. Dry-run is restored on every path. Includes a Q&A crib. |
| Deck outline | `docs/presentation/deck-outline.md` | 20 slides with speaker, visual, talking points, and a "claims we never make" box. |
| Governance and wording | CODEOWNERS, README, Makefile, ci.yml label, repo-admin-setup, edge-waf-demo, detection README, sims README, local-dev, ADR-0002 note | Every CODEOWNERS path now has owners from two roles (D11), and `/docs/` has all three. README: the MTTC claim is now a target "not yet measured on AWS", the audit is "insert-only by convention", the cost line says 5 KMS keys, and the required-checks list has 7 entries. `TARGET=local` is no longer called offline. |

### Decisions (plan §2; user answers 17 Oct)

- **D1–D7:** `verify-all` as specified.
- **D8:** merge commits, with explicit retarget and update-branch.
- **D9:** enforce the gates before merging; the fallback is documented.
- **D10:** protection last, with **7 checks**: secrets, sast, sca, iac, soar, app, image (user Q2).
- **D11:** second code owners (user Q1).
- **D12:** the "Compliance Readiness Pack" (user Q3), client-side.
- **D13:** Object Lock pass-through.
- **D14:** honesty fixes.
- **D15–D20:** report and demo rules.
- **D21:** PR base `feat/s2-app-soc-ui-grc`.
- **D22:** file names as the user gave them.
- Q4 (viva date, lab apply) and Q5 (plan PDF items) are unanswered. The defaults are offline-first and placeholders.

### Step 0 outcomes and deviations

1. `cd soar && python -m pytest --cov` passes; the gate lives in `pyproject.toml` (95 %).
2. The offline IR tool against the compose moto works: `cd soar && AWS_ENDPOINT_URL=http://127.0.0.1:5000 AWS_ACCESS_KEY_ID=local-only AWS_SECRET_ACCESS_KEY=local-only AWS_DEFAULT_REGION=us-east-1 python -m tools.generate_ir_report <id> --table cloudshield-local-soar-incidents` exits **2** for `local-c-public-bucket` (BROKEN) and **0** for `local-a-cred-exfil`. **Deviations from the plan:** boto3 needs `AWS_DEFAULT_REGION`, because `AWS_REGION` alone gives `NoRegionError`; and `make ir-report` hides the tool's exit code behind make's own 2, so the demo calls python directly.
3. actionlint pinned to `rhysd/actionlint:1.7.12@sha256:b1934ee5…`. Docker Hub rate-limited the shellcheck image (429), so shellcheck 0.11.0 came from `pip install shellcheck-py`.
4. The sandbox provider mirror was used via `TF_CLI_CONFIG_FILE` (outside the repo).
5. Checkov `-d app --framework dockerfile` gives 202 passed / 0 failed with `node_modules` present, the same count as CI. No skip-path is needed.
6. Mermaid: all 13 blocks in `docs/reports/` parse with mermaid 11.4.1 under jsdom, installed in the scratchpad. GitHub's renderer was not tested.
7. **Found while building verify-all:** `modules/detection` reads `../../../../detection/athena-queries`, so the scratch copy must include `detection/`; the first run failed the detection tests until it did. local-dev Jest needs moto, as CI's `app` job provides, so verify-all starts one for it.

### Proof

<!-- VALIDATOR-FILL: final verify-all run, auditor outcome, Phase F PR CI run -->

### Not proven

- Nothing has been applied to AWS. No M3 or M4 MTTC exists, and no GuardDuty, Step Functions, Lambda, Athena, Object Lock or WAF behaviour has been observed.
- The cutover runbook's `gh pr …` commands were not run: the sandbox has no GraphQL, and the merge is S1's action. Its flags were checked against gh 2.89 `--help`.
- External references and links are unverified (`[verify]` throughout).
- The readiness pack download was tested in jsdom (Vitest), not in a browser under the nginx CSP.

### Next

1. **S1:** run [final-merge-and-cutover.md](runbooks/final-merge-and-cutover.md): approvals, `gate-selftest.sh all`, `ENFORCE_GATES=true`, the merges in order, branch deletion, then protection with 7 checks.
2. **First lab apply** (with `evidence_object_lock_days` set first, if act 5 needs it). Then fill the `PENDING (first lab apply)` tables in chapter 07, using the commands written next to each table.
3. **Team:** supply R7, FR-1/6/7, plan §1.1, the rubric criteria and the WBS Chapter 7 structure from the PDF, replacing every `[source: plan PDF, not in repo — team to verify]` row. Check every `[verify]` reference and legal item.
4. **G1 (team-size waiver):** still open and still the top risk.
5. **Doc and code follow-ups found by the writers:**
   - `soar/sims` documents a `cleanup` command that `runner.py` does not implement;
   - no code creates the honeytoken key the sims README describes;
   - the A/B/C replay tests check the exit code but not the status string;
   - A-recon has no dedicated replay-local test;
   - the data module's audit PutItem statement still has the sid `AuditAppendOnly` (the wording only; the behaviour is insert-only by convention);
   - query 04's header still names `RateLimitPerIp` as the harvester feed (now `SoarApiRateLimit`);
   - the `gate-selftest.sh dockerfile` seed has no recorded result.
