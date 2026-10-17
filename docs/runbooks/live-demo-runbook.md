# Runbook: live demo (15 minutes, 5 acts)

- **Owners:** S1 @ELSHAHALY (act 1, the demo PR, the AWS lab apply), S2 @YasseenAbdelghany (acts 2 and 3), S3 @ahklsfg (acts 3, 4 and 5; dry-run custody on the AWS track) [repo: docs/plans/depi-phase-f-capstone-complete.md "Owners", §8.1]
- **Relates to:** report chapter 07 (evidence classes, MTTC classes M0–M4), [final-merge-and-cutover.md](final-merge-and-cutover.md) (`ENFORCE_GATES`, branch protection), [local-dev.md](local-dev.md), [edge-waf-demo.md](edge-waf-demo.md), [pb04-pb05-recovery.md](pb04-pb05-recovery.md), ADR-0003 (PB-01 recovery)
- **Default track: offline.** Nothing has been applied to AWS [HANDOFF §1], so the AWS lab track is only used if section 1's conditions hold at T-24h.

---

## 0. Rules (read aloud at the rehearsal)

1. **R4, our own resources only.** Every AWS command targets this project's lab account and resources named `cloudshield-dev-*` that carry `cloudshield:soar-scope=in-scope`. The sims enforce this before any call (`soar/sims/safety.py`). Never point a tool at a host or account we do not own.
2. **No real secret, ever.**
   - The act-1 secrets seed is a fake token that `scripts/gate-selftest.sh` builds in a temp directory at runtime and deletes afterwards [repo: scripts/gate-selftest.sh L4–L9, L46–L52].
   - The demo PR carries an **IaC** seed (a security group), not a token.
   - Nothing secret is committed, pasted into a terminal that is being shared, or shown on screen.
   - Do not use `AKIAIOSFODNN7EXAMPLE`: gitleaks allow-lists it, so it would not trip [repo: scripts/gate-selftest.sh L47–L48].
3. **Dry-run stays on.** The SOAR dry-run parameter reads `true` at all times, except inside act 4's window on the AWS track (and the T-30 warm-up run). Every path that turns it off, including every failure fallback, ends by setting it back to `true` and reading it back (section 4, act 4; section 6).
4. **Wording.**
   - Say "seeded" for the local stack's data, "replayed" for replay runs, and "pending" for anything that needs an AWS apply.
   - Say "automated containment with human-gated eradication".
   - The GRC export is the "Compliance Readiness Pack", "a self-assessment, not an audit". Its banner reads "Not legal advice. Not an audit or certification." [repo: app/spa/src/grc/readinessPack.ts L7].
   - Tenant isolation is enforced in the API, not by IAM or cryptography (the SSE-KMS context is the bucket ARN under S3 Bucket Keys).
   - The audit table is insert-only by convention.
   - Single AWS account (ADR-0001); the multi-account design is the target state.
5. **No number without its class.** Any MTTC shown is M1 (seeded), M2 (replay-local, not MTTC) or M3 (replay-aws: router MTTC, synthetic detection). No M4 run exists. Chapter 07 §6 has the definitions.
6. **`make sim … TARGET=local` is not offline.** It drives the real handlers with whatever AWS credentials are configured [repo: Makefile `sim` comment; soar/sims/README.md]. The offline track never calls `make sim`. It uses pytest under moto.

---

## 1. Track decision at T-24h

| Question | Yes → | No → |
|---|---|---|
| Has the lab been applied with the section 2 flags, **including `evidence_object_lock_days = 1` set before the first apply**? | next question | **offline track** |
| Have acts 4 and 5 been rehearsed end to end on the lab at least once, including restoring dry-run? | next question | **offline track** |
| Do short-lived credentials (SSO) work on the demo laptop, and are the budgets confirmed? | **AWS lab track** for acts 4–5 | **offline track** |

- Acts 1–3 are the same on both tracks.
- Acts 2–3 always run on the local stack, which runs the **production docs-api image** in local mode against moto [repo: docs/runbooks/local-dev.md]. Say so on stage.
- Record the decision and who made it in the team channel.

**Feasibility notes** (what each track can and cannot show):
- `make ir-report` and `make sim TARGET=aws` need AWS. The one exception is the IR tool run directly with Python against the compose moto (act 5 offline) [repo: Makefile `ir-report`, `sim`].
- Step Functions, Athena and Object Lock exist only on the lab track. Offline, Athena is shown as SQL and explained, not run.
- A live GuardDuty finding (class M4) is assumed to take minutes to arrive [inferred], so live-aws is never attempted in a 5-minute slot [repo: docs/plans/depi-phase-f-capstone-complete.md §8.2]. Show a pre-run recording if one exists, and say it is a recording.
- `make ir-report` reports any tool failure as make's own exit code 2, so it hides the difference between the tool's exit 1 and exit 2. Wherever an exit code is the point, call the tool with `python -m tools.generate_ir_report`.

---

## 2. Prerequisites

**Laptop (both tracks)**
- Docker with Compose v2.20 or later, and Node 24 (`app/.nvmrc`) [repo: docs/runbooks/local-dev.md "Start, check, stop"].
- Python 3.13 with `pip install -r soar/requirements-dev.txt` (moto 5.2.4, pytest, pytest-cov, ruff) [repo: soar/requirements-dev.txt].
- `gh` authenticated as a collaborator; `jq` (used to read the `lab_targets` output); a browser.
- The repo checked out at the submission tag (`capstone-2026-fall` if the cutover created it [repo: docs/runbooks/final-merge-and-cutover.md §5]).
- Host ports `127.0.0.1:3000` (SPA) and `127.0.0.1:5000` (moto) must be free. `make local-moto` also binds 5000, so stop it first (`docker stop cloudshield-moto`) [repo: docker-compose.local.yml L29–L30, L112–L113; Makefile `local-moto`].

**Offline track**
- Images pre-built. The first `make local-up` builds images and pulls base images, so run it at T-60, not on stage.

**AWS lab track (only if section 1 says so)**
- `bootstrap` and `environments/dev` applied with these `terraform.tfvars` values [repo: infra/terraform/environments/dev/variables.tf]:

  ```hcl
  enable_lab_targets        = true   # honeytoken user + *-lab-exposure bucket (scenarios B, C)
  soar_playbook_package     = { s3_bucket = "<versioned bucket>", s3_key = "<key>", s3_object_version = "<version>" }
  soar_dry_run              = true   # at rest; act 4 flips the SSM parameter, not this variable
  evidence_object_lock_days = 1      # set BEFORE the first apply: only settable at bucket creation;
                                     # GOVERNANCE; locked versions cannot be deleted for 1 day.
                                     # Changing it on an ALREADY-APPLIED lab is expected to replace
                                     # the evidence bucket and delete its contents [verify]: run
                                     # terraform plan and stop if module.soar.aws_s3_bucket.evidence
                                     # shows "must be replaced".
  enable_report_worker      = false  # true only if scenario A is used
  enable_edge               = false  # about US$20/month when on (variables.tf); not needed for the demo
  ```

- GuardDuty and CloudTrail (with S3 data events on the evidence, documents and lab buckets) come from the `detection` module [repo: infra/terraform/environments/dev/main.tf `data_event_bucket_arns`].
- Credentials: short-lived (SSO) only. Export `AWS_REGION=us-east-1` and `AWS_DEFAULT_REGION=us-east-1`, because the sim's region gate fails closed on an unresolved region [repo: soar/sims/safety.py `require_lab`].
- Cost: read the cost note in report chapter 01 §1.8. The steady-state baseline is about US$33/month for the NAT gateway plus about US$5/month for the 5 default KMS keys [repo: README.md L136]. The budgets must be confirmed in the console (`bootstrap` alarms) before the session.
- Shell variables used below (run in `infra/terraform/environments/dev`):

  ```bash
  ACCT=$(aws sts get-caller-identity --query Account --output text)
  P=$(terraform output -raw soar_dry_run_parameter)
  SM=$(terraform output -raw soar_state_machine_arn)      # null if soar_playbook_package is unset: stop, use offline
  BUCKET=$(terraform output -json lab_targets | jq -r .lab_bucket)
  EVB=$(terraform output -raw soar_evidence_bucket)
  WG=$(terraform output -raw athena_workgroup)
  DB=$(terraform output -raw glue_database)
  ```

  All seven outputs exist in `infra/terraform/environments/dev/outputs.tf`. `lab_targets` is `null` unless `enable_lab_targets = true`.

---

## 3. Checklists

### T-24h
- [ ] Track decision (section 1) recorded.
- [ ] Full rehearsal on the chosen track, timed against section 4.
- [ ] Screen recordings of **every act** saved locally (offline-playable). These are the fallbacks named in section 4.
- [ ] Offline track: with Wi-Fi **off**, run `make local-down && make local-up && make local-smoke` (images already built) to confirm the stack needs no network after the build [inferred until this check passes].
- [ ] Pre-export one readiness pack as dina (`cloudshield-grc-readiness-t-nile-02-2026.10.0.md` [repo: app/spa/src/grc/readinessPack.ts L30–L32; app/grc/rules/2026.10.0.json]) and keep it as the act-2 fallback.
- [ ] Every `verify` legal item in the GRC hub is either checked against the official text or presented as unverified [HANDOFF §13 "Next" #4].

### T-60
- [ ] `make local-up && make local-smoke`. Expect 8 PASS lines and `local smoke: all checks passed` [repo: app/local-dev/src/smoke.ts L36–L66].
- [ ] **Open the demo PR** (S1). It is never merged:

  ```bash
  git fetch origin && git switch -c "demo/shift-left-$(date +%Y%m%d)" origin/main
  mkdir -p infra/terraform/demo-seed
  cat > infra/terraform/demo-seed/main.tf <<'HCL'
  # DEMO ONLY (live-demo-runbook.md act 1): CKV_AWS_24 seed. Never merge.
  resource "aws_security_group" "demo_open_ssh" {
    name        = "demo-seed-open-ssh"
    description = "demo seed"
    vpc_id      = "vpc-00000000"
    ingress {
      description = "demo seed"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  HCL
  terraform fmt -check -diff infra/terraform/demo-seed     # must print nothing: gate: iac runs fmt -check first
  git add infra/terraform/demo-seed/main.tf
  git commit -m "demo: CKV_AWS_24 seed for the live demo (DO NOT MERGE)"
  git push -u origin HEAD
  gh pr create --base main --title "DEMO ONLY: shift-left block (do not merge)" \
    --body "Live-demo act 1. Carries a Checkov CKV_AWS_24 seed (SSH open to 0.0.0.0/0). Never merged; closed and deleted after the demo."
  ```

  The resource body is the same as the self-test's IaC seed [repo: scripts/gate-selftest.sh L92–L103]. Checked in the build sandbox on 17 Oct 2026: `terraform fmt -check` is clean, and Checkov fails CKV_AWS_24 and also CKV2_AWS_5 (the group is attached to nothing). `infra/terraform/demo-seed/` is outside the `terraform validate` loop (`bootstrap`, `environments/*/`, `modules/*/`) and has no `tests/`. It is inside `terraform fmt -check -recursive infra/terraform` and `checkov -d infra/terraform` [repo: .github/workflows/ci.yml L297–L337]. So the PR fails at Checkov and nowhere earlier.
- [ ] Confirm the PR is red and blocked: `gh pr checks <n>` shows `gate: iac (terraform + checkov)` failing, and `gh pr view <n> --json mergeStateStatus --jq .mergeStateStatus` prints `BLOCKED`. This needs `ENFORCE_GATES=true` and branch protection on `main` (cutover runbook §1 and §4). **If the cutover has not happened yet**, the job is green with the warning "Checkov failed checks. Not blocking only because ENFORCE_GATES != true." [repo: .github/workflows/ci.yml L341–L344]. In that case, say so on stage and show the warning instead.
- [ ] Browser tabs, one per user (local sign-in keeps the token in `sessionStorage`, which is per tab [repo: app/spa/src/auth/local.tsx L44]): alice, mallory, dina and sam on `http://localhost:3000`; the demo PR; and the `ci` run page. Open each tab fresh; do not duplicate tabs.
- [ ] Terminal 1 at the repo root; terminal 2 in `soar/`. AWS track: terminal 3 in `infra/terraform/environments/dev` with the section 2 variables set, and a fourth terminal held by S1 for the dry-run restore only.

### AWS track, T-30 (warm-up for act 5)

Run scenario C once so that CloudTrail has delivered the management and data events for act 5's query 03 by the time it is needed.

```bash
cd infra/terraform/environments/dev    # terminal 3, variables from section 2
aws s3api delete-public-access-block --bucket "$BUCKET"   # optional: our own lab bucket, no data, no public policy
aws ssm put-parameter --name "$P" --value false --overwrite
( cd ../../../.. && make sim SCENARIO=c MODE=replay TARGET=aws ACCOUNT="$ACCT" \
    SIM_ARGS="--state-machine-arn $SM --bucket-name $BUCKET" ); rc=$?
aws ssm put-parameter --name "$P" --value true --overwrite          # runs whatever the sim did
aws ssm get-parameter --name "$P" --query Parameter.Value --output text   # must print: true
aws s3api get-public-access-block --bucket "$BUCKET"                # all four flags true (PB-03 restored them)
echo "sim exit $rc"; date -u +%Y-%m-%dT%H:%M:%SZ                     # note the time for query 03's window
```

- Note the incident id (`sim-c-<epoch>`) from the JSON. The id format is `sim-<scenario>-<epoch seconds>` [repo: soar/sims/scenarios.py `build_event`].
- If any BPA flag is not `true`, restore it now with `aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`.
- If the sim is interrupted (Ctrl-C), the shell may drop the lines after it: run the two `aws ssm` lines again by hand.
- If `get-parameter` does not print `true`, **stop**: S1 sets it from terminal 4, and the team switches to the offline track for acts 4–5.

### T-5
- [ ] `NO_COLOR` unset (the self-test and verify-all print ✓/✗ symbols; colour is optional) and `TERM` not `dumb`.
- [ ] Terminal font size large enough for the back row; notifications off.
- [ ] Offline track: Wi-Fi off. In terminal 2, `unset AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN`, so that nothing can reach a real account by accident. The pytest fixtures set their own fake credentials [repo: soar/tests/conftest.py L31–L38].
- [ ] AWS track: `aws ssm get-parameter --name "$P" --query Parameter.Value --output text` prints `true`.

---

## 4. Minute by minute (15:00)

| Time | Act | Speaker | Steps (exact) | Expected | Fallback |
|---|---|---|---|---|---|
| 00:00–02:00 | **1 Shift-left block** | S1 | Terminal 1: `scripts/gate-selftest.sh secrets`. Say: "the fake token was generated in a temp dir and is already deleted". Switch to the demo PR: the red `gate: iac (terraform + checkov)`, the Checkov annotation naming **CKV_AWS_24**, and "Merging is blocked". Mention `ENFORCE_GATES=true` and the 7 required checks (secrets, sast, sca, iac, soar, app, image) [repo: docs/runbooks/final-merge-and-cutover.md §4]. | `✓ secrets: tripped on the seeded finding (exit 1, matched /github-pat/)` and `---- tripped: 1   NOT caught: 0   skipped: 0` [repo: scripts/gate-selftest.sh L35, L144]; red check; merge blocked | Recording of the PR. If gitleaks is missing, the line reads `- secrets: SKIPPED (tool not installed)`: say so and show the recording. Pre-cutover: show the fail-open warning (T-60 note) |
| 02:00–05:00 | **2 Multi-tenant + GRC** | S2 | alice tab: **Documents** lists Acme's documents. mallory tab: open `http://localhost:3000/documents/0192b3c4-0000-7000-8000-00000000a001` (Acme's "Quarterly report" [repo: app/local-dev/src/seed.ts L56]). The API answers **404**, not 403, so a probe cannot tell "exists" from "not yours". dina tab: **Onboarding** shows agreements pending; document writes are refused with `AGREEMENT_REQUIRED` (do **not** accept them on stage). dina → **GRC hub** → the assessment (EG-PDPL, EG-CBE; explain the residency GAP: us-east-1 by construction) → **Download readiness pack (Markdown)** → open the file: the banner, the server disclaimer, the "⚠ VERIFY against the official text" markers, and the ruleset SHA-256 in the provenance. Say: "the Egypt PDPL / CBE Compliance Readiness Pack: a self-assessment, not an audit; generated in the browser, not signed". | 404 for mallory; pack downloaded as `cloudshield-grc-readiness-t-nile-02-2026.10.0.md` | Terminal: `make local-smoke` line 3 (`PASS 3 mallory (t-nile-02) gets 404 for an acme document`); open the pre-exported pack file |
| 05:00–07:00 | **3 Decoy trap** | S2 + S3 | Terminal 1: `curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3000/api/admin/backup`. nginx strips `/api` and docs-api mounts the decoy at `/admin`, before authentication [repo: app/spa/nginx/default.conf L24–L25; app/docs-api/src/app.ts L41]. Then `make local-smoke` and point at lines 4a, 4b and 4c (the smoke run has no subset option; all 8 lines print). sam tab: **SOC** → the seeded decoy incident `edge-decoy-203-0-113-66-<yyyyMMddHH>`, status `BLOCKED_BY_GUARD`, reason "notify-only edge finding (decoy route hit): analyst review" [repo: app/local-dev/src/seed.ts L210, L220]. Explain why it never blocks: the source address can be forged by anyone holding the origin secret, so a decoy hit only notifies (ADR-0006 residual risks). Say that the incident shown is **seeded**: the local stack has no router, and our curl's event lands in the capture queue that check 4c reads. | `403`; `PASS 4a`, `PASS 4b`, `PASS 4c` | Recording of the smoke output |
| 07:00–12:00 | **4 Automated IR (containment)** | S3 | **Offline:** terminal 2: `python -m pytest tests/test_sims.py -k "replay_local_scenario_c_contains or replay_local_scenario_a_contains" -s -v`. Scroll the JSON: `"status": "CONTAINED"`, `"playbook": "pb03-s3-restore-bpa"`, `"guard": {"allowed": true, "dry_run": false, …}`, `"containment": {"contained": true, "verified": {…all four BPA flags true…}}`, and `"mttc_seconds": null`. Say: "an in-process copy of the router against moto; this proves the routing and containment logic; it is **not MTTC** (class M2)". Then sam's SOC **MTTC gauge**, called **seeded** (class M1). Say "automated containment with human-gated eradication": the report's eradication and recovery checklists are for an analyst.<br>**AWS:** terminal 3 (variables from section 2). `aws ssm put-parameter --name "$P" --value false --overwrite`, then `( cd ../../../.. && make sim SCENARIO=c MODE=replay TARGET=aws ACCOUNT="$ACCT" SIM_ARGS="--state-machine-arn $SM --bucket-name $BUCKET" ); rc=$?`, then **immediately and unconditionally** `aws ssm put-parameter --name "$P" --value true --overwrite && aws ssm get-parameter --name "$P" --query Parameter.Value --output text` (→ `true`). Show the Step Functions execution graph for `$SM`, the incident row, the printed `mttc_seconds`, and the `< 60 s` verdict (`"passed": true`). Say: "M3: real router and real containment, synthetic detection, router MTTC". | Offline: 2 passed, `CONTAINED`. AWS: `CONTAINED`, `"passed": true`, dry-run reads `true` | Sim hangs or errors: Ctrl-C, then run the restore line anyway (it is not chained to the sim). S1 confirms from terminal 4 with `get-parameter`. Then switch to the offline steps above. If `get-parameter` cannot be read (credentials expired), S1 re-authenticates and restores before anything else; `terraform apply` also restores `soar_dry_run = true` [repo: infra/terraform/modules/soar/main.tf L320–L327]. Last resort: recording |
| 12:00–15:00 | **5 Forensics** | S3 | **Offline:** sam tab → incident `local-a-cred-exfil` → **Verify evidence** → "Chain of custody: intact", SHA-256 shown; incident `local-c-public-bucket` → **Verify evidence** → "Chain of custody: BROKEN" (recorded ≠ recomputed on `prestate.json`); **Download report (Markdown)** [repo: app/spa/src/soc/EvidencePanel.tsx L28–L29, L85–L90]. Terminal 2: `AWS_ENDPOINT_URL=http://127.0.0.1:5000 AWS_ACCESS_KEY_ID=local-only AWS_SECRET_ACCESS_KEY=local-only AWS_DEFAULT_REGION=us-east-1 python -m tools.generate_ir_report local-c-public-bucket --table cloudshield-local-soar-incidents --format md > /tmp/ir-c.md; echo "exit $?"` → `exit 2`; then the same with `local-a-cred-exfil` → `exit 0` [repo: soar/tools/generate_ir_report.py L19–L20, L383; chapter 07 §8.3]. (`AWS_DEFAULT_REGION` is required; `AWS_REGION` alone gives `NoRegionError`.) Show `detection/athena-queries/03_s3_public_exposure_audit.sql` and explain the partition filter (parameters 1–2 are partition days) and the workgroup's enforced 1 GiB per-query scan cap [HANDOFF §11].<br>**AWS:** Athena console, workgroup `$WG`, database `$DB`: `PREPARE h03 FROM <contents of 03_s3_public_exposure_audit.sql>;` then `EXECUTE h03 USING '<yyyy/MM/dd>', '<yyyy/MM/dd>', '<window start ISO>', '<window end ISO>', '<lab bucket>';` with the T-30 window. Then terminal 2 (in `soar/`, with the lab credentials and `AWS_DEFAULT_REGION=us-east-1`): `python -m tools.generate_ir_report <sim-c-id> --table cloudshield-dev-soar-incidents --format md > /tmp/ir-aws.md; echo "exit $?"` → `exit 0`. Terminal 3: `aws s3api list-object-versions --bucket "$EVB" --prefix "incidents/<sim-c-id>/" --query 'Versions[].[Key,VersionId]' --output text`; `aws s3api get-object-retention --bucket "$EVB" --key <key> --version-id <vid>` → `GOVERNANCE` until …; `aws s3api delete-object --bucket "$EVB" --key <key> --version-id <vid>` → `AccessDenied`. **Never pass a governance-bypass flag.** | Offline: intact / BROKEN; exit 2 then 0. AWS: query rows (PB-03's `PutBucketPublicAccessBlock`, plus the T-30 `DeleteBucketPublicAccessBlock` if that step was done); exit 0; GOVERNANCE; AccessDenied | Recordings. If query 03 returns no rows, CloudTrail delivery may not have arrived [inferred]; say so and show the SQL |

**Timing guard.** If an act overruns by 30 s, skip its optional step: in act 2 the onboarding view, in act 3 the smoke re-run (the curl suffices), in act 5 the second IR-tool call. Act 4 on the AWS track has no optional step that may be skipped **after** dry-run is turned off: the restore line always runs.

---

## 5. Full offline fallback

If anything AWS-related, or the network, fails at any point, the whole demo runs from `docker-compose.local.yml` and the repo:

| Act | Offline form |
|---|---|
| 1 | `scripts/gate-selftest.sh secrets` (and `scripts/gate-selftest.sh iac` to show CKV_AWS_24 tripping locally); the PR page from a recording |
| 2 | the local stack, as in section 4 |
| 3 | the local stack, as in section 4 |
| 4 | the pytest replay, as in section 4 (offline) |
| 5 | the SOC evidence panel and the Python IR tool against the compose moto, as in section 4 (offline) |

- No network is needed after the images are built [inferred: confirmed only by the T-24h Wi-Fi-off check].
- If Docker itself fails: acts 1 and 4 still run (gitleaks/Checkov and pytest need no containers), and acts 2, 3 and 5 come from the recordings.
- **If the switch to offline happens mid-act-4 on the AWS track**, the dry-run restore line from act 4 runs first, and S1 confirms `true` from terminal 4 before the offline steps start.

---

## 6. Afterwards (same day)

- [ ] **Demo PR:** `gh pr close <n> --delete-branch` (or close it in the UI and delete `demo/shift-left-<date>`). It was never merged. Confirm with `git ls-remote --heads origin 'demo/*'`, which should print nothing.
- [ ] **Dry-run (AWS track):** `aws ssm get-parameter --name "$P" --query Parameter.Value --output text` must print `true`. If it does not, `aws ssm put-parameter --name "$P" --value true --overwrite`, then run `terraform apply` with `soar_dry_run = true` to re-assert the managed value.
- [ ] **Lab bucket:** `aws s3api get-public-access-block --bucket "$BUCKET"`: all four flags `true` (restore with the `put-public-access-block` command from the T-30 checklist).
- [ ] **Scenario A, only if it was used:** the ADR-0003 recovery [repo: docs/adr/0003-pb01-nacl-quarantine.md "Consequences"]:

  ```bash
  aws ec2 delete-network-acl-entry --network-acl-id <worker NACL id> --rule-number 10 --ingress
  aws ec2 delete-network-acl-entry --network-acl-id <worker NACL id> --rule-number 10 --egress
  aws ec2 modify-instance-attribute --instance-id <worker> --groups <previousGroups from the incident row's sg-swap action>
  aws iam delete-role-policy --role-name cloudshield-dev-report-worker --policy-name cloudshield-soar-revoke-older-sessions
  ```

  The worker NACL id comes from the incident row, or from `aws ec2 describe-network-acls --filters Name=association.subnet-id,Values=<id from terraform output private_worker_subnet_ids>`.
- [ ] **Sim cleanup.** The sims README describes a `cleanup` command [repo: soar/sims/README.md "Cleanup"], but `sims.runner` has no such option today [repo: soar/sims/runner.py `build_parser`]. Clean up by hand with the steps above, and delete any honeytoken key created for a scenario-B run (`aws iam list-access-keys --user-name <honeytoken>`, then `aws iam delete-access-key`).
- [ ] `make local-down`. This removes the containers and moto's data [repo: Makefile `local-down`].
- [ ] **Teardown:** `terraform destroy` in `environments/dev` when the lab is no longer needed. Evidence versions written under Object Lock stay locked until their retention ends (1 day with `evidence_object_lock_days = 1`), so the evidence bucket cannot be emptied before then. Plan the teardown for the next day, and do not use a governance bypass to force it.
- [ ] **Budgets:** check the budget alarms and the billing console the next day.
- [ ] Fill chapter 07 §5.4 / §6.4 / §8.5 rows from any AWS-track run (date, commit, incident id, status, times, MTTC, IR report file), following chapter 07 Appendix C.

---

## 7. Q&A crib (honest answers)

| Question | Answer |
|---|---|
| "Is it autonomous?" | No. It is automated containment with human-gated eradication. Automation stops at CONTAINED, after a read-back verification. Eradication and recovery are analyst steps, and the IR report lists them [HANDOFF §2.1; repo: soar/tools/generate_ir_report.py]. |
| "Is MTTC measured on AWS?" | Not yet. Nothing has been applied, so no M3 or M4 run exists. What you saw is seeded (M1) or a replay under moto (M2, not MTTC). The 60 s figure is a target with a precise definition: containedAt (entering `MarkContained`) minus the EventBridge event time, nearest-rank percentiles (chapter 07 §6). |
| "Is the audit immutable?" | No. It is insert-only by convention: the app writes with `attribute_not_exists`, the role has no Update or Delete permission, and a table stream and PITR give tamper evidence. IAM cannot force a conditional `PutItem` [HANDOFF §2.5 M6, §3 gap 15]. The stream consumer that would alarm on changes is a follow-up [repo: docs/adr/0006-app-soc-grc-local.md "Follow-ups"]. |
| "Is tenant isolation cryptographic?" | No. Tenant isolation is enforced in the API, not by IAM or cryptography (the SSE-KMS context is the bucket ARN under S3 Bucket Keys). The tenant comes only from the verified token, and cross-tenant reads answer 404 (act 2; smoke check 3). STS session tags with `dynamodb:LeadingKeys` are the recorded stretch goal [HANDOFF §3 gap 11]. |
| "Why one account?" | Single AWS account (ADR-0001); the multi-account design is the target state. One account is cheaper and fits a three-person team. The cost is weaker isolation between the security tooling and the workload; for example, an account admin could rewrite the edge-bus policy [repo: docs/adr/0001-single-account-first.md; docs/adr/0005-pb04-pb05-edge-and-ecs-containment.md]. |
| "Is the GRC output legal advice?" | No. The Compliance Readiness Pack is a self-assessment, not an audit: "Not legal advice. Not an audit or certification." Every non-GDPR citation carries a verify mark, the pack is built in the browser, and it is not audited or signed [repo: app/spa/src/grc/readinessPack.ts L7–L8; HANDOFF §13]. |
| "What does PB-01 not block?" | The quarantine NACL and security group cannot filter traffic to the Route 53 Resolver (DNS), to instance metadata (IMDS) or to Amazon Time Sync, or traffic within the same subnet. A DNS-tunnelled channel survives isolation. The follow-up is a DNS Firewall rule group [repo: docs/adr/0003-pb01-nacl-quarantine.md "Consequences"]. |
| "Is Object Lock on?" | Object Lock is off by default (`evidence_object_lock_days = 0`), because it blocks teardown. The lab sets it before the first apply. The chain of custody is otherwise detect-on-recompute (exit 2), not prevent [repo: infra/terraform/modules/soar/variables.tf L101–L104]. |
| "Did the scans really pass, or were they fail-open?" | They really passed: in the CI runs of PRs #1–#4, the `Report (fail-open)` steps were skipped [repo: docs/plans/depi-phase-f-capstone-complete.md F2; chapter 07 Appendix B]. |
