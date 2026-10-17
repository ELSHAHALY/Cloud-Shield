# CloudShield viva deck: outline (20 slides)

| Field | Value |
|---|---|
| Version | 1.0 |
| Date | 17 Oct 2026 |
| Status | DRAFT |
| Owners | All three. Speakers follow ownership: S1 @ELSHAHALY (pipeline, edge), S2 @YasseenAbdelghany (app, identity, GRC), S3 @ahklsfg (detection, SOAR, forensics) [repo: docs/plans/depi-phase-f-capstone-complete.md "Owners", D20] |
| Companion | [live-demo-runbook.md](../runbooks/live-demo-runbook.md) (the five demo acts), [docs/reports/](../reports/README.md) (the seven chapters) |

**How to read this outline.** Each slide gives its title, a one-sentence takeaway, the visual and the chapter it comes from, three talking points, the speaker and the source. Chapter references use the section numbers of the chapters (chapter 01 uses `1.x` numbering). Where a chapter was still being written on 17 Oct 2026, the reference follows its outline in the Phase F plan §6.3 [repo: docs/plans/depi-phase-f-capstone-complete.md §6.3], and is re-checked when that chapter is final. A slide claim on MTTC, FR-3, FR-4, the account model or automation must match the chapters word for word (plan D20). The fixed wording is listed in [docs/reports/README.md §3](../reports/README.md#fixed-wording).

> **Claims we never make**
>
> - ✗ "Autonomous". Say: **automated containment with human-gated eradication**.
> - ✗ "MTTC under 60 s" as a result. Say: **a 60 s target; no MTTC measured on AWS exists yet** (M3/M4 pending first apply). Seeded figures are always called **seeded** (M1). Replay under moto is **not MTTC** (M2).
> - ✗ "Immutable audit log" or "append-only audit". Say: the audit table is **insert-only by convention**; the audit stream consumer is a follow-up.
> - ✗ "Cryptographic tenant isolation". Say: **tenant isolation is enforced in the API, not by IAM or cryptography (the SSE-KMS context is the bucket ARN under S3 Bucket Keys)**.
> - ✗ "Multi-account security account". Say: **single AWS account (ADR-0001); the multi-account design is the target state**.
> - ✗ "Relational database" or "tables with joins". Say: **DynamoDB only; the data model shows a logical view of item types, not relational tables**.
> - ✗ "Evidence is WORM-protected". Say: **Object Lock is off by default (`evidence_object_lock_days = 0`)**; a lab can turn it on before its first apply.
> - ✗ "Audit pack" or "compliance certified". Say: the **Compliance Readiness Pack, a self-assessment, not an audit**: "Not legal advice. Not an audit or certification."
> - ✗ "`make sim` runs offline". `TARGET=local` drives the real handlers with the configured AWS credentials. CI's replay evidence is pytest under moto.
> - ✗ Any AWS cost, latency or detection figure presented as observed. Nothing has been applied to AWS [HANDOFF §1].
> - ✗ Any statistic, market figure or price from outside the repository.

---

## Timing plan

The viva slot length is not in the repository [source: plan PDF, not in repo — team to verify]. The plan below is a proposal [inferred] and is scaled to the real slot once it is known.

| Block | Slides | Proposed time | Notes |
|---|---|---|---|
| Opening and status | 1–3 | 3:00 | Slide 3 is the honesty slide: do not shorten it |
| Architecture and pipeline | 4–7 | 4:00 | |
| Demo act 1 | 8 | 2:00 | Runbook §4, 00:00–02:00 |
| App, identity, GRC | 9–10 | 2:00 | |
| Demo acts 2 and 3 | 11–12 | 5:00 | Runbook §4, 02:00–07:00 |
| Detection and SOAR | 13–16 | 4:00 | |
| Demo acts 4 and 5 | 17–18 | 8:00 | Runbook §4, 07:00–15:00 |
| Results, risks, close | 19–20 | 2:00, then Q&A | Runbook §7 is the Q&A crib |
| **Total before Q&A** | | **30:00** | 15:00 of it is the demo (runbook §4); 15:00 is slides [inferred] |

If the slot is shorter, cut slides 7, 13 and 15 to one sentence each (their content stays in chapters 04 and 06). Never cut slide 3 or slide 16.

---

## Slides

### Slide 1: CloudShield: automated DevSecOps and cloud incident response
- **Takeaway:** a three-person DEPI capstone that puts two defensive loops around a multi-tenant document API on AWS.
- **Visual:** title, team table (S1, S2, S3 with handles and roles) from chapter 01 §1.4.1.
- **Talking points:**
  1. The team and roles: S1 platform and CI/CD, S2 app, identity and data, S3 SecOps, SOAR and forensics [repo: README.md "Team"].
  2. The repository is the deliverable: code, Terraform, tests, ADRs and seven report chapters [repo: docs/reports/README.md §1].
  3. Region `us-east-1`, a single AWS account (ADR-0001); the multi-account design is the target state.
- **Speaker:** all (S1 opens).
- **Source:** chapter 01 §1.2, §1.4.

### Slide 2: The problem and our answer: two loops
- **Takeaway:** shift-left stops known-bad changes before merge; shift-right is designed to contain an incident automatically and keep evidence, with eradication left to a human.
- **Visual:** the two-loop overview, from the chapter 03 §4.2 component diagram, simplified to the two loops and their links.
- **Talking points:**
  1. Shift-left: a GitHub Actions pipeline of security gates [repo: .github/workflows/ci.yml].
  2. Shift-right: GuardDuty → EventBridge → Step Functions `cs-ir-router` → Lambda playbooks, all behind a fail-closed safety guard [repo: soar/README.md].
  3. The loops are linked: the SOC posture banner shows the build gates; the image is pushed only when the gates really passed; the PB-03 IR report emits a Terraform snippet that feeds back into the code (chapter 02 §5(a)).
- **Speaker:** S1.
- **Source:** chapter 01 §1.2; chapter 02 §5; chapter 03 §1.1.

### Slide 3: Honest status: built, audited, not yet applied
- **Takeaway:** everything is built, tested and independently audited, and nothing has been applied to AWS, so no AWS measurement exists.
- **Visual:** a three-column table: "measured locally / in CI", "synthetic or seeded", "pending first apply". From docs/reports/README.md "What is measured vs pending" and chapter 07 §2.
- **Talking points:**
  1. Five phases each closed with an independent audit; every major finding was fixed (chapter 07 §4; [HANDOFF §2.5, §10–§13]).
  2. CI was green on PRs #1–#4 with the scans really passing: the fail-open report steps were skipped (chapter 07 Appendix B).
  3. Pending first apply: GuardDuty, Step Functions, Athena, Object Lock, WAF and any MTTC on AWS (chapter 07 §9 lists 40 items to verify).
- **Speaker:** S1.
- **Source:** chapter 01 §1.2; chapter 07 §2, §4, §9.

### Slide 4: Architecture and trust boundaries TB0–TB5
- **Takeaway:** each Terraform module is one trust boundary, and every boundary crossing is authenticated.
- **Visual:** the chapter 03 §4.2 component diagram (one subgraph per TB, flows labelled with protocol and authentication). Caption: redrawn from the README trust-boundary table (Figure 7.1 of the plan, fidelity [source: plan PDF, not in repo — team to verify]).
- **Talking points:**
  1. TB1 edge and identity (CloudFront, WAF, API Gateway, Cognito); TB2 private compute; TB3 data at rest; TB4 supply chain; TB5 the security domain (SOAR, evidence, detection) [repo: README.md trust-boundary table].
  2. VPC `10.20.0.0/16` across 2 AZs, with a dedicated worker-tier NACL for PB-01 quarantine (chapter 03 §5).
  3. Ingress is an internal NLB behind a REST API Gateway VPC Link (ADR-0002 §4).
- **Speaker:** S1.
- **Source:** chapter 03 §4, §5.

### Slide 5: One account now, multi-account target
- **Takeaway:** single AWS account (ADR-0001); the multi-account design is the target state, and the module boundaries are drawn so that the split stays possible.
- **Visual:** the chapter 03 §10.1 target diagram next to the "what one account loses" table from chapter 03 §10.2.
- **Talking points:**
  1. Why one account: cost, team size, and the unknown DEPI account model (G2) (ADR-0001; chapter 01 §1.3.5).
  2. What it loses: an account admin can rewrite the edge-bus policy, and the SOC read path shares the workload account (ADR-0005; ADR-0006 residual risks).
  3. TB5 is "Security account" in the target and a set of modules in one account today (chapter 03 §4.1).
- **Speaker:** S1.
- **Source:** chapter 03 §10; ADR-0001.

### Slide 6: Six security gates, fail-open → enforced
- **Takeaway:** the gates fail open until `ENFORCE_GATES=true`. We proved that they trip before enforcing them, and then made seven checks required on `main`.
- **Visual:** the chapter 04 §1 job table (order, tool and version, threshold, hard vs fail-open).
- **Talking points:**
  1. The six security gates are secrets (gitleaks, full history), SAST (Semgrep), SCA (Trivy fs), IaC (Checkov), image (Trivy image + SBOM) and DAST (ZAP, passive). The `soar` and `app` correctness gates always hard-fail [repo: .github/workflows/ci.yml].
  2. The seven required checks are secrets, sast, sca, iac, soar, app and image (plan D10; the cutover runbook §4).
  3. Proven to trip: secrets and IaC (CKV_AWS_24). SAST trips locally, but its pack membership is unconfirmed; SCA, image and DAST seeds have not run yet [HANDOFF §5; chapter 07 §7.2].
- **Speaker:** S1.
- **Source:** chapter 04 §1–§4.

### Slide 7: Supply chain and CI identity (OIDC)
- **Takeaway:** no long-lived AWS keys exist anywhere, and every artefact is pinned by digest.
- **Visual:** a flow from the chapter 04 §5 and §6 content: GitHub OIDC → read-only plan role / ECR push role (exact `main` ref) → ECR → task definition by digest.
- **Talking points:**
  1. The plan role is read-only; the ECR push role trusts only `repo:…:ref:refs/heads/main` by exact match, never a wildcard [repo: infra/terraform/modules/compute/ci-push.tf L33–L37].
  2. Actions are pinned to commit SHAs, Dependabot covers npm and Docker, and images are pinned by digest. The CycloneDX SBOM artefact is kept for 90 days [repo: .github/workflows/ci.yml L421].
  3. The image is pushed only when Trivy and the secrets, SAST and SCA scans really passed, even in fail-open mode [HANDOFF §12].
- **Speaker:** S1.
- **Source:** chapter 04 §5, §6.

### Slide 8: Demo act 1: the shift-left block
- **Takeaway:** a planted secret and a planted open-SSH security group are both caught, and the PR cannot be merged.
- **Visual:** live terminal (`scripts/gate-selftest.sh secrets`) and the demo PR page (red `gate: iac`, CKV_AWS_24 annotation, "Merging is blocked"). Fallback: recording.
- **Talking points:**
  1. The fake token is built at runtime in a temp directory and deleted, and no secret is ever committed (runbook §0).
  2. The demo PR carries an IaC seed in `infra/terraform/demo-seed/main.tf` on `demo/shift-left-<date>`. It is never merged (runbook §3 T-60).
  3. If the cutover has not happened yet, the job is green with a fail-open warning, and we say so (runbook §3).
- **Speaker:** S1.
- **Source:** runbook §4 act 1; chapter 04 §4.

### Slide 9: Identity and the token contract
- **Takeaway:** the API trusts only a re-verified Cognito ID token, and the tenant comes from the token alone.
- **Visual:** the chapter 05 §1.2 request-path figure, with the token checks called out.
- **Talking points:**
  1. Cognito: TOTP MFA, admin-only sign-up, 14-character passwords, a non-writable `custom:tenant_id`, and 4 groups [HANDOFF §12; chapter 05 §2.1].
  2. The API re-verifies signature, `iss`, `aud` and `token_use` behind the API Gateway authorizer (chapter 05 §2.2).
  3. The SPA uses SRP with tokens in `sessionStorage`, never `localStorage` [repo: app/spa/src/auth/cognito.tsx L1–L2].
- **Speaker:** S2.
- **Source:** chapter 05 §2.

### Slide 10: Tenant isolation (FR-2), encryption (FR-3), audit (FR-4)
- **Takeaway:** isolation is real but lives in the API; encryption is real but not per tenant; the audit table is insert-only by convention.
- **Visual:** the chapter 03 §7.2 logical item model ("Logical view of DynamoDB item types (no joins, no foreign keys)") next to a three-row claim table.
- **Talking points:**
  1. FR-2/FR-3: tenant isolation is enforced in the API, not by IAM or cryptography (the SSE-KMS context is the bucket ARN under S3 Bucket Keys). Cross-tenant reads answer 404 (chapter 05 §3.3, §4, §5).
  2. FR-4: the audit table is insert-only by convention. It uses conditional writes, no Update or Delete permission, a table stream and PITR, and the audit stream consumer is a follow-up (chapter 05 §6.2).
  3. DynamoDB only; the data model shows a logical view of item types, not relational tables (chapter 03 §7.1).
- **Speaker:** S2.
- **Source:** chapter 05 §4–§6; chapter 03 §7.

### Slide 11: Demo act 2: multi-tenant portal and the Compliance Readiness Pack
- **Takeaway:** another tenant's document is invisible (404), and the GRC hub exports a readiness pack that says plainly what it is not.
- **Visual:** live local stack (alice, mallory, dina tabs); the downloaded pack opened in an editor. Fallback: smoke check 3 and a pre-exported pack. Screenshots, if used, come from the local stack and are captioned "seeded".
- **Talking points:**
  1. The local stack runs the production docs-api image in local mode against moto (runbook §1).
  2. mallory gets 404 for Acme's "Quarterly report"; dina's document writes are refused with `AGREEMENT_REQUIRED` until the agreements are accepted (runbook §4 act 2).
  3. The Egypt PDPL / CBE Compliance Readiness Pack is a self-assessment, not an audit: "Not legal advice. Not an audit or certification." It is built in the browser, not signed, with a VERIFY marker on every unverified citation (chapter 05 §10.4).
- **Speaker:** S2.
- **Source:** runbook §4 act 2; chapter 05 §10.

### Slide 12: The decoy route (notify-only) and demo act 3
- **Takeaway:** a decoy admin path answers like any denial, audits the hit, and notifies, but never blocks.
- **Visual:** the chapter 03 §8.3 sequence diagram (decoy hit, notify-only), then the live terminal.
- **Talking points:**
  1. `GET /api/admin/backup` answers 403, the same as any RBAC denial; the hit lands in the `_platform` audit and on the edge bus (smoke 4a–4c) [repo: app/local-dev/src/smoke.ts L45–L58].
  2. The SOAR guard records `DecoyRouteHit` and notifies; it never allows a playbook, because the source address could be forged (ADR-0006 residual risks).
  3. The SOC incident shown is seeded; the local stack has no router (runbook §4 act 3).
- **Speaker:** S2, then S3.
- **Source:** chapter 05 §8; runbook §4 act 3.

### Slide 13: Detection telemetry and hunting
- **Takeaway:** GuardDuty, CloudTrail with S3 data events, Config and flow logs feed a KMS-encrypted archive that Athena can hunt under a scan cap.
- **Visual:** the chapter 06 §1 telemetry figure; one hunt query (`03_s3_public_exposure_audit.sql`) on screen.
- **Talking points:**
  1. CloudTrail S3 data events cover exactly the evidence, documents and lab buckets (plus the SPA bucket when the edge is on) [repo: infra/terraform/environments/dev/main.tf `data_event_bucket_arns`].
  2. There are 4 parameterised hunt queries, partition-filtered, in a workgroup with an enforced 1 GiB per-query scan cap [HANDOFF §11, §12].
  3. The queries are tested statically only; none has run against data yet (chapter 07 §9).
- **Speaker:** S3.
- **Source:** chapter 06 §1, §2.

### Slide 14: The SOAR router and the safety guard
- **Takeaway:** the router fails closed, and every playbook sits behind a guard that is double-bound by the scope tag and by IAM.
- **Visual:** the chapter 03 §9 `stateDiagram-v2` of `cs-ir-router`.
- **Talking points:**
  1. Fail-closed at three points: guard `allowed`, `dry_run`, and the playbook's boolean `contained` [HANDOFF §2.5 M1, M5].
  2. The guard checks the scope tag `cloudshield:soar-scope=in-scope` on the live resource; IAM conditions and a permissions boundary bound what a playbook may change (chapter 06 §4).
  3. The routing table lives in one file, asserted by both `terraform test` and pytest (chapter 07 §5.3).
- **Speaker:** S3.
- **Source:** chapter 06 §3, §4; chapter 03 §9.

### Slide 15: PB-01…PB-05 and what "contained" means
- **Takeaway:** a run is CONTAINED only after the playbook has read back its own change, and everything after that is evidence or human work.
- **Visual:** the chapter 06 §5 playbook table (trigger, action, read-back, evidence step, not covered).
- **Talking points:**
  1. PB-01 NACL quarantine and session revoke; PB-02 key deactivation; PB-03 BPA restore; PB-04 ECS task stop and redeploy; PB-05 edge IP block with an auto-expiry sweeper (chapter 06 §5).
  2. This is automated containment with human-gated eradication. The sweeper is expiry, not recovery (chapter 06 §6).
  3. What PB-01 does not block: DNS through the Resolver, IMDS, Time Sync and traffic within the same subnet (ADR-0003).
- **Speaker:** S3.
- **Source:** chapter 06 §5, §6.

### Slide 16: MTTC: definition, and what is measured vs pending
- **Takeaway:** MTTC has one precise definition and five measurement classes, and neither M3 nor M4 (MTTC measured on AWS) exists yet.
- **Visual:** the class table from chapter 07 §6.2 (M0–M4), with the M3 and M4 rows highlighted as PENDING.
- **Talking points:**
  1. MTTC(r) = containedAt (entering `MarkContained`) − the EventBridge event time, only for CONTAINED runs. Reported as n, p50, p90 and max, nearest-rank, never a mean alone (chapter 07 §6.1).
  2. What exists: M0 golden oracle values (never results), M1 seeded values of 9–40 s (always "seeded") [repo: app/local-dev/src/seed.ts L214–L225], and M2 replay-local, which is not MTTC.
  3. The 60 s figure is a target. M3 (router MTTC, synthetic detection) and M4 (live) are pending first apply (chapter 07 §6.4).
- **Speaker:** S3.
- **Source:** chapter 06 §7; chapter 07 §6.

### Slide 17: Demo act 4: automated containment
- **Takeaway:** the real playbook code reaches CONTAINED against a moto account, and that proves the logic, not the speed.
- **Visual:** live terminal (`pytest tests/test_sims.py -k "replay_local_scenario_c_contains or replay_local_scenario_a_contains" -s -v`), the JSON with `"status": "CONTAINED"` and `"mttc_seconds": null`; then the SOC MTTC gauge captioned **seeded**. AWS track: the Step Functions graph and the printed M3 MTTC.
- **Talking points:**
  1. In-process router, real playbooks, moto: class M2, not MTTC (runbook §4 act 4).
  2. The SOC gauge reads seeded rows (M1), and we say so on screen.
  3. AWS track only: dry-run off for the run, then immediately back to `true`, read back on screen (runbook §0 rule 3).
- **Speaker:** S3.
- **Source:** runbook §4 act 4; chapter 07 §5.3.

### Slide 18: Chain of custody and demo act 5
- **Takeaway:** evidence integrity is checked by recomputing every SHA-256, and a tamper turns the chain BROKEN with exit code 2.
- **Visual:** the SOC evidence panel (A intact, C BROKEN); the IR-tool exit codes in the terminal; the golden-case table from chapter 07 §8.2.
- **Talking points:**
  1. Hashes are recorded on the incident row; verification downloads, recomputes and compares, with version pinning (chapter 06 §8; chapter 07 §8.1).
  2. On the seeded local stack: exit 2 for `local-c-public-bucket`, exit 0 for `local-a-cred-exfil` (chapter 07 §8.3, run 17 Oct 2026).
  3. Object Lock is off by default (`evidence_object_lock_days = 0`). The AWS track shows GOVERNANCE retention and a refused delete, which is pending first apply (chapter 07 §8.5).
- **Speaker:** S3.
- **Source:** chapter 06 §8; chapter 07 §8; runbook §4 act 5.

### Slide 19: Verification and QA results
- **Takeaway:** every layer from static gates to the local end-to-end run is green and cited, and the live layer is the one that is missing.
- **Visual:** chapter 07 Figure 7.1 (the verification layers) next to the chapter 07 §3 summary (the Phase F verify-all and CI figures, filled by the Validator).
- **Talking points:**
  1. Phase F figures come from one `make verify-all` run and the Phase F PR's CI, each with its commit and environment (chapter 07 §3, Appendix A). Do not quote the previous record as current.
  2. Audits found tests that passed for the wrong reason, and we fixed them (chapter 07 §4).
  3. Threats to validity: moto does not enforce IAM, KMS key ids, bucket policies or Object Lock; the data is seeded; Semgrep evidence is CI only (chapter 07 §10).
- **Speaker:** all (S1 for the gates, S2 for the app suites, S3 for SOAR).
- **Source:** chapter 07 §1, §3, §4, §10.

### Slide 20: Risks, limits, future work; Q&A
- **Takeaway:** the top risk is outside the code (team size, G1), and the next technical step is the first lab apply with its verify list.
- **Visual:** the chapter 01 §1.7.1 risk register (R1–R7, with R7 shown as "[source: plan PDF, not in repo — team to verify]") and a short "next" list.
- **Talking points:**
  1. R1, team size (H × H), is still open; R2–R6 ratings come from the plan PDF and are marked as such (chapter 01 §1.7.1).
  2. Limits: DNS-channel exfiltration after quarantine, PB-05 shared egress, tenant isolation in the API, and the audit stream consumer as a follow-up (chapter 01 §1.7.2).
  3. Next: the cutover, the first lab apply, the 40-item verify list, filling the chapter 07 placeholders, and checking the legal verify items (chapter 01 §1.10; chapter 07 §9).
- **Speaker:** all.
- **Source:** chapter 01 §1.7, §1.10; chapter 07 §9; runbook §7 (Q&A crib).
