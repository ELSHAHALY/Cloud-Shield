# CloudShield capstone report: index, legend and evidence rules

| Field | Value |
|---|---|
| Document | Index of the CloudShield capstone report (DEPI AWS Cloud Security, Fall 2026) |
| Version | 1.0 |
| Date | 17 Oct 2026 |
| Status | DRAFT |
| Maintainers | S1 @ELSHAHALY, S2 @YasseenAbdelghany, S3 @ahklsfg |
| Reviewers | The Phase F Independent Auditor (plan §11) |
| Governing plan | [`docs/plans/depi-phase-f-capstone-complete.md`](../plans/depi-phase-f-capstone-complete.md) (§6 report rules, §7 evidence and MTTC) |

This file is the single place where the report defines its citation marks, its numbers policy, its evidence classes and its MTTC measurement classes. The seven chapters link here instead of repeating these definitions.

> **What is measured vs pending (whole report)**
> - **Measured:** CI runs on PRs #1–#4 with the scan steps really passing; local test, coverage and policy-scan results recorded in HANDOFF §13; the Phase F `make verify-all` run (filled into chapter 07 §3 by the Validator).
> - **Synthetic or seeded, never a result:** the golden chain-of-custody fixtures (class M0) and the seeded local demo incidents (class M1).
> - **Pending first apply:** everything on AWS. Nothing has ever been applied to AWS [repo: docs/HANDOFF.md §1]. No AWS measurement exists, so the report presents none.

---

## 1. Chapters

| # | File | Owner(s) | Scope (one line) |
|---|---|---|---|
| 01 | [`01_project_charter_and_management.md`](01_project_charter_and_management.md) | All three (S1, S2, S3) | Charter, scope, team and RACI derived from repo ownership, delivery timeline from `git log`, governance and audit outcomes, risk register, cost model. |
| 02 | [`02_literature_review_and_benchmarking.md`](02_literature_review_and_benchmarking.md) | All three (S1, S2, S3) | Standards and primary sources the design draws on, and a qualitative benchmark against a single-loop pipeline, commercial SOAR platforms and AWS samples. |
| 03 | [`03_system_analysis_and_architecture.md`](03_system_analysis_and_architecture.md) | All three (S1, S2, S3) | Requirements and traceability, use cases, trust boundaries TB0–TB5, VPC, module map, logical data model, sequences and the `cs-ir-router` state machine. |
| 04 | [`04_devsecops_shift_left_pipeline.md`](04_devsecops_shift_left_pipeline.md) | S1 @ELSHAHALY | The CI gates one by one, fail-open to enforced, gate self-tests, CI identity through OIDC, supply chain, container hardening, branch protection. |
| 05 | [`05_secure_cloud_application_and_identity.md`](05_secure_cloud_application_and_identity.md) | S2 @YasseenAbdelghany | Cognito and the token contract, RBAC/ABAC, tenant isolation, encryption, the audit trail, edge, decoy, SOC read model and the GRC hub with the Compliance Readiness Pack. |
| 06 | [`06_detection_telemetry_and_soar_engine.md`](06_detection_telemetry_and_soar_engine.md) | S3 @ahklsfg | Telemetry and log archive, Athena hunting, the SOAR router and safety guard, PB-01…PB-05, the automation boundary, MTTC, chain of custody, IR report. |
| 07 | [`07_verification_attack_simulations_and_qa.md`](07_verification_attack_simulations_and_qa.md) | All three; S3 for the SOAR and forensics parts | Verification strategy, measured results, independent audits, attack simulations A–E, MTTC results by class, QA, chain-of-custody report, verify-on-first-apply list. |

Ownership follows the Phase F plan [repo: docs/plans/depi-phase-f-capstone-complete.md "Owners"].

### Companion documents

| Document | Purpose |
|---|---|
| [`docs/runbooks/live-demo-runbook.md`](../runbooks/live-demo-runbook.md) | The live demo: the offline track (default) and the AWS lab track, minute by minute. |
| [`docs/presentation/deck-outline.md`](../presentation/deck-outline.md) | The viva deck outline. Its claims match the chapter text on MTTC, FR-3, FR-4, the account model and the automation wording. |
| [`docs/runbooks/final-merge-and-cutover.md`](../runbooks/final-merge-and-cutover.md) | Merging the PR stack with merge commits, enforcing the gates, and protecting `main`. |
| [`docs/HANDOFF.md`](../HANDOFF.md) | The project's running record: what was built, decided, proven and not proven, per phase. |
| [`docs/adr/`](../adr/) | Architecture decision records ADR-0001 to ADR-0006. |

---

## 2. Sources and marks legend

Every chapter uses these marks. A statement without a mark is either a definition, a description of the repository that the cited section supports, or design intent worded as such.

| Mark | Meaning | Example |
|---|---|---|
| `[repo: path §/line]` | Read from this repository at the cited file, section or line. | `[repo: infra/terraform/bootstrap/main.tf L224–255]` |
| `[CI: run <id>, PR #n, <sha>]` | A GitHub Actions run on this repository. | `[CI: run 38984704551, PR #4, 9adc96d]` |
| `[local: verify-all 2026-10-17, <sha>, sandbox]` | A dated local run of `make verify-all` (`scripts/verify-all.sh`) at the stated commit, in the stated environment. | Filled in by the Validator in chapter 07 §3. |
| `[HANDOFF §n]` | A prior record in `docs/HANDOFF.md`. Used for earlier measurements, labelled "previous record". | `[HANDOFF §13]` |
| `[L<n>]` | An external source, defined in that chapter's References list. The `L` prefix avoids a clash with the risk ids R1–R7. | `[L3]` |
| `[verify]` | An edition, date, version, product name, legal or behavioural claim that must be checked against the official source before the report is final. The mark stays until it is checked. | "CIS AWS Foundations Benchmark v3.0.0 [verify]" |
| `[inferred]` | The authors' best understanding, not verified. Each one is either a rehearsal or first-apply item or is worded as unverified. | "lab-session estimate [inferred]" |
| `[source: plan PDF, not in repo — team to verify]` | An item from the original plan PDF (`CloudShield_Capstone_Plan_and_Architecture.pdf`), the DEPI rubric or the WBS that is not in this repository. The report never invents its content: the row is present and its content cell is left empty for the team. | R7, FR-1, FR-6, FR-7, rubric criteria |

The plan PDF, the DEPI Fall 2026 rubric and WBS Chapter 7 are not in the repository [repo: docs/HANDOFF.md §9; docs/plans/depi-phase-f-capstone-complete.md F22]. External links in the References lists could not be checked from the build sandbox (its proxy refused the outbound connection on 17 Oct 2026), so each one carries `[verify: edition, date, URL; link not checked]`.

---

## 3. Numbers policy

1. **No number without a source.** Every digit-bearing claim carries one of the marks above. Identifiers (`PB-01`, `TB3`, `ADR-0004`, `T1530`, `SP 800-61`, `us-east-1`) are names, not claims.
2. **AWS behaviour that was not observed is design intent.** It is written as "is designed to", "the target is" or "should". Nothing has been applied to AWS [repo: docs/HANDOFF.md §1], and moto (the local AWS emulator) does not enforce IAM, KMS key ids, bucket policies or Object Lock retention reads [repo: docs/HANDOFF.md §13 "Not proven"].
3. **Previous records are labelled.** Figures from HANDOFF §13 are cited `[HANDOFF §13]` and called "previous record". Chapter 07 §3 re-measures them in Phase F and gives the new figures with a `[local: …]` or `[CI: …]` mark.
4. **Every MTTC figure states its class** (M0–M4, §5). Only M3 and M4 would be MTTC on AWS, and neither exists yet.
5. **Seeded numbers are called "seeded".** Golden-fixture numbers are called "synthetic oracle" and are never reported as a result.
6. **No statistics, market figures or prices from external sources.** Prices appear only as figures this repository already states (with their citation) or as `[verify: AWS pricing page, accessed —]` placeholders (chapter 01 §8).
7. **Placeholders are visible.** Pending data appears as table cells reading `PENDING (first lab apply)`, each with the command that fills it.
8. **Gaps in the source material are visible.** Content that only the plan PDF, the rubric or the WBS holds is a row with the `[source: plan PDF, not in repo — team to verify]` mark and an empty content cell.

### Fixed wording

The chapters use these formulations verbatim, because an auditor checks them:

| Topic | Wording |
|---|---|
| Audit table (FR-4) | "insert-only by convention"; the audit stream consumer "is a follow-up" |
| Tenant isolation (FR-3) | "tenant isolation is enforced in the API, not by IAM or cryptography (the SSE-KMS context is the bucket ARN under S3 Bucket Keys)" |
| Account model | "single AWS account (ADR-0001); the multi-account design is the target state" |
| Data store | "DynamoDB only; the data model shows a logical view of item types, not relational tables" |
| Automation boundary | "automated containment with human-gated eradication" |
| Evidence retention | "Object Lock is off by default (`evidence_object_lock_days = 0`)"; Phase F adds a dev pass-through (plan D13) |
| `make sim … TARGET=local` | Not offline: it drives the real handlers with the configured AWS credentials. CI's replay evidence is pytest under moto (`soar/tests/test_sims.py`). |
| GRC export | The "Compliance Readiness Pack": "a self-assessment, not an audit"; "Not legal advice. Not an audit or certification." Generated client-side, not audited and not signed. |

---

## 4. Evidence classes

From plan §7.1 [repo: docs/plans/depi-phase-f-capstone-complete.md §7.1]. The class column is what a chapter must say about any result it quotes.

| Evidence | Class | Where it lives |
|---|---|---|
| CI runs on PRs #1–#4 and the Phase F PR; in each, the `Report (fail-open)` steps were skipped, so the scans really passed | **CI** | Runs 38478422214 (PR #1, `b28c75d`), 38486109181 (PR #2, `7d6c677`), 38930049163 (PR #3, `247643a`), 38984704551 (PR #4, `9adc96d`) [repo: docs/plans/depi-phase-f-capstone-complete.md F1, F2]; the Phase F PR run is added by the Validator |
| pytest with coverage, Jest, Vitest, local-dev Jest, `terraform test` / `validate` / `fmt`, Checkov, Gitleaks, actionlint, hadolint | **local-measured / CI** | `make verify-all` (Phase F, chapter 07 §3); previous record [HANDOFF §13] |
| `make local-smoke` | **local-measured / CI `app-smoke`** | `make verify-all`; [CI: run 38984704551, PR #4, 9adc96d] |
| Replay-local scenarios A/B/C reach `CONTAINED`; D/E reach `WOULD_CONTAIN_DRY_RUN`; safety-gate refusals | **CI (pytest under moto)** | [repo: soar/tests/test_sims.py] |
| Golden chain-of-custody cases (intact, tampered, missing object, base64 mismatch, versioned, not contained, no evidence in dry-run) with Python/TypeScript parity | **synthetic oracle** | [repo: soar/tests/fixtures/coc_golden.json] and the tests that read it |
| Seeded SOC incidents, including scenario C with a **BROKEN** chain of custody | **seeded demo data** | [repo: app/local-dev/src/seed.ts] |
| Gate self-test: secrets and IaC proven to trip; SAST, SCA, image and DAST not yet | **local** | [HANDOFF §5]; Phase F may extend it |
| **Anything on AWS:** GuardDuty, Step Functions, Lambda, Athena, Object Lock, WAF, MTTC | **pending first apply** | — |

---

## 5. MTTC: definition and measurement classes

From plan §7.2 [repo: docs/plans/depi-phase-f-capstone-complete.md §7.2], implemented in [repo: infra/terraform/modules/soar/state-machine.tf] (states `RecordDetected` and `MarkContained`) and reported by [repo: app/docs-api/src/soc/metrics.ts].

### 5.1 Definition

For a run *r* of the `cs-ir-router` state machine:

```
MTTC(r) = containedAt(r) − eventTime(r)        (seconds; defined only when r ends CONTAINED)
```

- `eventTime(r)` is the `time` of the EventBridge event that started run *r*. `RecordDetected` writes it; `firstEventTime` and `findingCreatedAt` keep the first sighting for audit.
- `containedAt(r)` is `$$.State.EnteredTime` of `MarkContained`. The router enters that state only after the playbook returns a boolean `contained: true` from a read-back verification (`CheckContained`).
- **Excluded by design:** attacker action to GuardDuty detection; GuardDuty `createdAt` to EventBridge delivery (stored and reported separately as detection latency); evidence capture after `CONTAINED`; dry-run runs (`WOULD_CONTAIN_DRY_RUN`). `BLOCKED_BY_GUARD`, `FAILED` and `NO_PLAYBOOK_ANALYST_REVIEW` runs have no MTTC; they are reported as counts and as a containment rate.
- **KPI:** each graded scenario run must have MTTC below the 60 s target, as `sims.runner` asserts [repo: soar/sims/runner.py L37, L137]. Over a window the report gives n, the median (p50), p90 and the maximum, with the nearest-rank percentile used by `metrics.ts`. It never gives a mean alone.
- **Validity threats:** the EventBridge `time` has whole-second resolution [inferred]; `replay-aws` stamps `time` on the operator's clock and skips the EventBridge hop, so its result is "router MTTC, synthetic detection" and needs NTP-synchronised clocks [repo: docs/plans/depi-phase-f-capstone-complete.md F17]; the first run after a deploy includes cold starts and is reported separately; n is small.

### 5.2 Classes

| Class | What it measures | Status |
|---|---|---|
| **M0** synthetic oracle | The golden chain-of-custody fixture, e.g. `mttc_seconds: 18.0` in the `intact` case [repo: soar/tests/fixtures/coc_golden.json]. | Exists. A test oracle that pins the Python and TypeScript calculations to the same answer. **Never** reported as a result. |
| **M1** seeded | Hand-authored times on the local demo incidents: 9 s to 40 s across seven CONTAINED incidents [repo: app/local-dev/src/seed.ts]. | Exists. **Always** labelled "seeded". |
| **M2** replay-local | The in-process router and the real playbook code under moto (`soar/tests/test_sims.py`). It yields test durations, **not MTTC**. | Exists (CI). |
| **M3** replay-aws | The real router, Lambdas and AWS APIs with a synthetic detection event (`make sim … MODE=replay TARGET=aws`). | **PENDING (first lab apply).** No MTTC measured on AWS exists yet. |
| **M4** live-aws | End to end, including GuardDuty detection. | **PENDING (first lab apply).** No MTTC measured on AWS exists yet. |

---

## 6. Rubric mapping (whole report)

The DEPI Fall 2026 rubric is not in the repository, so no criterion is stated here [repo: docs/plans/depi-phase-f-capstone-complete.md F22].

| Rubric criterion | Where the report addresses it |
|---|---|
| [source: plan PDF, not in repo — team to verify] | |
| [source: plan PDF, not in repo — team to verify] | |

The WBS Chapter 7 structure is also not in the repository; the chapter split above follows plan D22 [repo: docs/plans/depi-phase-f-capstone-complete.md D22]. If the WBS prescribes a different split, the team re-maps it here: [source: plan PDF, not in repo — team to verify].

---

## 7. Updating the report

- A chapter moves from DRAFT to FINAL only when every `[verify]` mark in it has been checked or deliberately kept, every `PENDING` cell is either filled or explained, and its "Rubric mapping" table is filled in by the team.
- A new measurement replaces a placeholder only with its class, its date, its commit and its environment.
- When a fact in `docs/HANDOFF.md` or an ADR changes, the chapter that cites it changes in the same PR.
