# S3 Phase C: detection, Athena threat hunting, attack simulations

**Branch:** `feat/s3-detection-athena-sims` (from `feat/s3-soar-playbooks` @ `b28c75d`) · **Owner:** @ahklsfg · **Status:** APPROVED 14 Oct, building

Sources: WBS §6.1, §6.2, §6.5, §7, FR-8; `detection/README.md`; `attack-sim/README.md` (risk R4 rules); HANDOFF §3 (gaps 6, 12, 16) and §10; ADR-0001/0002/0003.

---

## 1. Facts that shape the design, and the decisions needed

| # | Fact or conflict | Plan |
|---|---|---|
| F1 | EventBridge `PutEvents` **rejects any `aws.*` source**, so a custom script can't inject a fake GuardDuty event into the bus. | Replay against AWS = `states:StartExecution` on `cs-ir-router`, using the same event shape EventBridge delivers. End-to-end detection checks use GuardDuty `CreateSampleFindings`. Sample findings are dry-run only, by guard rule 2. |
| F2 | The router consumes **GuardDuty findings only**. Config compliance events have a different shape, and no playbook takes them. | Config rule results → EventBridge → the SOAR SNS topic (analyst notification). Scenario C's *containment* stays driven by GuardDuty `Policy:S3/BucketBlockPublicAccessDisabled`. Replaying Config events checks the notification rule only, not containment. |
| F3 | Live B and C need targets that don't exist yet. PB-02 is only "contained" on a user that carries the SOAR target boundary (audit A2), and PB-03 only acts on a tagged `cloudshield-dev-*` bucket (gap 12). | **Decision D2:** a gated `lab-targets` module creates a honeytoken IAM user (boundary + scope tag, **no access key in Terraform state**: the sim creates and deletes the key at runtime) and a tagged lab bucket. |
| F4 | Requested locations are `soar/queries/` and `soar/sims/`, but the repo already documents `detection/athena-queries/` (FR-8 home) and `attack-sim/` (R4 rules). | **Decision D1.** |
| F5 | Requested tag is `cloudshield:soar-enabled=true`. The repo's scope tag (IAM conditions, guard, playbooks) is `cloudshield:soar-scope=in-scope`. | Keep the repo tag. Sims read it from the same setting. |
| F6 | GuardDuty has **one detector per region**. HANDOFF §6 tells S1 to run `aws guardduty create-detector`. If someone already did, `apply` fails. | `manage_guardduty_detector` (default `true`), plus an import command in the README for an existing detector. |
| F7 | `InstanceCredentialExfiltration.OutsideAWS` requires the stolen credentials to be **used from outside AWS**. A real trigger means moving the worker role's credentials to the operator's laptop. GuardDuty IAM-user anomaly findings (scenario B) need an ML baseline and may not fire within a demo window. | **Decision D4.** |
| F8 | Requested workgroup name is `cs-forensics`. Repo convention prefixes everything with `${var.name}`. | `${var.name}-cs-forensics` (e.g. `cloudshield-dev-cs-forensics`). |

**Decisions (14 Oct):**

- **D1 Hybrid:** SQL in `detection/athena-queries/`; Python tools and sims under `soar/` (shared `core/`, one CI job).
- **D2:** a gated `lab-targets` module, with no access key in state.
- **D3:** core detection services on; Security Hub and the paid GuardDuty protections off.
- **D4:** scenario A uses live containment with a replayed detection. Credentials never leave the instance.

## 2. Terraform

### 2.1 Module `modules/detection` (new, Security-account boundary per ADR-0001)

| File | Contents | Default |
|---|---|---|
| `guardduty.tf` | Detector (15-min finding frequency) and a **findings export** to the log archive (`guardduty/` prefix, KMS). Feature toggles: `S3_DATA_EVENTS`, `RUNTIME_MONITORING` (ECS Fargate agent), `EBS_MALWARE_PROTECTION`. | Detector **on**; all paid protections **off** |
| `securityhub.tf` | Account, plus subscriptions to CIS AWS Foundations v3.0.0 and PCI DSS v3.2.1, each behind its own flag. | **off** (per-check cost; needs Config) |
| `config.tf` | Recorder limited to `AWS::S3::Bucket` (cost), a delivery channel to the log archive (`config/`), an IAM role with `AWS_ConfigRole`, and the managed rules `S3_BUCKET_PUBLIC_READ_PROHIBITED` and `S3_BUCKET_PUBLIC_WRITE_PROHIBITED`. NON_COMPLIANT events → SNS (F2). | **on** |
| `cloudtrail.tf` | Multi-region trail, management events, log-file validation, KMS (log-archive key), delivered to the log archive (`cloudtrail/`). Advanced selectors log S3 **data events for exactly the evidence and documents buckets**. Closes gap 16: those S3 data events are the compensating control for the missing server access logs. | **on** |
| `athena.tf` | Query-results bucket (KMS, BPA, TLS-only, 30-day expiry), KMS key, workgroup `${name}-cs-forensics` with **enforced** config, `bytes_scanned_cutoff_per_query = 1 GiB` and CloudWatch metrics. Glue database `${name}_forensics` and the three tables (§2.2). One `aws_athena_named_query` per SQL file. | **on** |

Also in this change:
- **`modules/log-archive`:** bucket- and KMS-policy statements for CloudTrail, Config and GuardDuty delivery. Each is scoped by `aws:SourceAccount` / `aws:SourceArn` and toggled by inputs. The trail ARN is built as a string, so there's no dependency cycle.
- **`modules/soar`:** a new input, `extra_notify_rule_arns`, lets the Config rule publish to the SNS topic. The topic policy currently allows only the GuardDuty rule.

### 2.2 Glue tables (partition projection, no crawlers, no `MSCK REPAIR`)

| Table | Format | Projection |
|---|---|---|
| `cloudtrail` | CloudTrail SerDe (`com.amazon.emr.hive.serde.CloudTrailSerde`); full schema incl. `useridentity` struct, `requestparameters`, `resources` | `region` enum, `timestamp` date `yyyy/MM/dd`, template `cloudtrail/AWSLogs/<acct>/CloudTrail/${region}/${timestamp}` |
| `vpc_flow_logs` | Parquet; columns = the network module's v5 custom format (`pkt_srcaddr`, `flow_direction`, `tcp_flags`, `traffic_path`, …) | `year`/`month`/`day`/`hour` integer projection. The fixed `aws-account-id=`/`aws-service=`/`aws-region=` segments are hard-coded in the template rather than made into hyphenated partition keys. |
| `guardduty_findings` | JSON (OpenX SerDe); nested `resource` / `service` read as JSON strings, queried with `json_extract_scalar` | `dt` date `yyyy/MM/dd`, template `guardduty/AWSLogs/<acct>/GuardDuty/<region>/${dt}` |

**Confidence note:**
- The table layouts follow AWS-documented formats, but no real objects exist yet.
- The first `apply` must run one smoke query per table. The plan includes it in the validator checklist.
- The OpenX struct-as-string behaviour for GuardDuty is the least certain.

### 2.3 Module `modules/lab-targets` (decision D2, flag `enable_lab_targets`, default off)

- **Honeytoken user** `${name}-honeytoken`: SOAR target boundary, scope tag, **no policies** (it can do nothing), no key.
- **Lab bucket** `${name}-lab-exposure`: scope tag, KMS, versioning, BPA **on** at rest. Only the scenario C sim turns BPA off, for at most `--window` minutes, and always restores it.

## 3. Hunting queries (FR-8, success criterion 06)

One `.sql` per query. Each has a header giving the ATT&CK technique, scenario, tables, parameters and expected result. They are **parameterised** with Athena `?` placeholders (`EXECUTE ... USING`), so the same text is the named query and the one in the repo.

| File | Answers |
|---|---|
| `01_attacker_timeline_by_principal.sql` | Every CloudTrail event for an access key / principal / source IP in a window: time, API, source IP, user agent, error code. Covers A (stolen role session) and B (honeytoken key). |
| `02_imds_and_recon_flow.sql` | Worker ENI flows (accepted/rejected, distinct destination ports per minute = scan shape) joined to the worker role's CloudTrail calls from **outside** the VPC egress IP (A, T1552.005 + T1046) |
| `03_s3_public_exposure_audit.sql` | `PutBucketPublicAccessBlock` / `DeletePublicAccessBlock` / `PutBucketPolicy` / `PutBucketAcl` on the bucket, plus data events (`GetObject` by anonymous or unknown principals) inside the exposure window (C, T1530) |

Python tests check that each file:
- has the header;
- is a single `SELECT`/`WITH` statement (no DDL or DML, so it is safe to run);
- has a placeholder count matching its header;
- references only catalogued tables.

Terraform registers exactly the files it finds (fileset), and a test asserts the count.

## 4. IR report generator (`soar/tools/generate_ir_report.py`)

- **Input:** `incident_id` (plus `--table`, `--evidence-bucket`, `--format md|json`, and AWS profile/region).
- **Reads:** the incidents row (`IncidentRepository.get`).
  - For every `evidenceRecords[]` entry, it fetches the object and **recomputes SHA-256**, then compares it with the row. That makes the report a chain-of-custody verification, not a copy of what was claimed.
- **Computes:**
  - MTTC = `containedAt − eventTime` (ADR-0002 §3)
  - detection latency = `eventTime − findingCreatedAt`
  - the playbook verify time
  - pass/fail against the 60 s target
- **Emits:** Markdown (timeline of `actions[]`, verification map, evidence table with ✓/✗ hash match, MTTC) or JSON. It is read-only and needs only `dynamodb:GetItem` + `s3:GetObject`.
- **Tests:** moto, including a tampered-evidence case (hash mismatch → report marks FAIL and the exit code is non-zero) and a not-contained case (no MTTC).

## 5. Attack simulations (§7, MITRE map, risk R4)

### Safety gates, all required, checked before any AWS call

1. `sts:GetCallerIdentity` account ∈ `--allowed-account` (no default).
2. The region equals the lab region.
3. Every target carries `cloudshield:soar-scope=in-scope` **and** the `${name}-` prefix.
4. Live mode also needs `--confirm-live <account-id>`, the account typed again.
5. Cleanup sits in `finally:` and is also exposed as `cleanup` (idempotent).
6. No external hosts, ever. Scans and requests target only lab resources.

### Modes

| Mode | What it does | AWS needed |
|---|---|---|
| `replay --target local` | Feeds the scenario event through an **in-process router** (guard → route → playbook → contained check), using the same Python handlers against moto. The routing table is contract-tested against `state-machine.tf`. | No (runs in CI) |
| `replay --target aws` | `StartExecution` on `cs-ir-router` with the scenario event aimed at the **real** lab target, `time = now`. Polls the execution, reads the incident row, asserts the expected status and **MTTC < 60 s** (when dry-run is off). | Yes |
| `live-aws` | Performs the reversible attacker action and waits for GuardDuty's real finding to drive the pipeline (§5 table). | Yes |
| `cleanup` | Restores every lab change, idempotently: BPA on, honeytoken keys deleted, NACL entries and SGs as in the ADR-0003 runbook (with `--yes`). | Yes |

### Scenarios

| Scenario | ATT&CK | Replay event | Live action |
|---|---|---|---|
| A | T1552.005, T1046 | `Recon:EC2/Portscan` and `InstanceCredentialExfiltration.OutsideAWS`, naming the real worker and its role id | **D4** |
| B | T1078, T1552.001 | `UnauthorizedAccess:IAMUser/*` naming the honeytoken user and a key created for the run | Create a key, make low-value read calls with it, wait for a finding up to a timeout. If none arrives, report "no detection" honestly. Never claim it. |
| C | T1530 | `Policy:S3/BucketBlockPublicAccessDisabled` on the lab bucket | Turn the lab bucket's BPA off (no public policy, no data exposed) → GuardDuty `Policy:S3` finding and Config NON_COMPLIANT → PB-03 restores. The sim restores BPA itself if PB-03 hasn't within the window. |

Results are written to `build/sim-results/<run>.json` (scenario, mode, execution ARN, status, MTTC). The IR report generator reads the same incident id.

## 6. Quality gates

- **pytest:** coverage ≥ 90% on `tools/` and `sims/` too (pyproject coverage sources extended). Ruff stays clean.
- **Terraform tests:**
  - `modules/detection/tests/`: a mock suite (flags, defaults, scan cap, enforced workgroup, data-event selectors equal exactly the two buckets).
  - An IAM/policy-content suite (real provider + overrides, as in `soar/tests/iam.tftest.hcl`): log-archive statements scoped by SourceArn, Config role, KMS grants.
  - `modules/lab-targets` tests.
- **Checkov:** 0 failed; every skip has a reason.
- **New Makefile targets:** `make sim SCENARIO=a MODE=replay`, `make ir-report INCIDENT=<id>`.
- **Cost table in the README:** CloudTrail (first trail free; data events per 100k), Config (per item recorded, S3 only), GuardDuty (free trial, then per event), Athena (per TB, capped at 1 GiB/query), Security Hub (off).

## 7. Pipeline

1. **Builder:** log-archive delivery statements → detection → lab-targets → queries → IR report → sims → docs.
2. **Independent Auditor:** a fresh agent. Focus: R4 safety gates, least-privilege delivery policies, Athena cost cap, query correctness against the documented log schemas, and whether the sims could ever touch a non-lab resource.
3. **Validator:** ruff/pytest, terraform fmt/validate/test, Checkov, Gitleaks. Then push and open a PR (stacked on #1).
4. **Summary:** HANDOFF §11.
