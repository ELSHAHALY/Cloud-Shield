# S3 · SOAR engine and playbooks: implementation plan

**Branch:** `feat/s3-soar-playbooks` (from `main` @ `1019669`) · **Owner:** @ahklsfg · **Status:** BUILT + AUDITED 14 Oct (docs/HANDOFF.md §10). Approved: runtime 3.13, subnet deny-all NACL (ADR-0003)

Sources: `soar/README.md` (handler contract), `infra/terraform/modules/soar/{playbooks,state-machine,main}.tf`, ADR-0002, handoff §3 gap 10.

---

## 1. Where the request conflicts with the repo, and what this plan does

The repo's contract wins wherever the two disagree, because the Terraform (already audited) calls these exact names and tags.

| # | Request says | Repo says | Plan |
|---|---|---|---|
| C1 | Python **3.12** | `runtime = "python3.13"` in `playbooks.tf` | **Decision needed.** Default: 3.13, so Terraform and the code agree without touching audited IaC. |
| C2 | `pb01_ec2_containment`, `pb02_iam_revocation`, `pb03_s3_exposure` | Handlers `playbooks.pb01_ec2_isolate`, `pb02_iam_key_revoke`, `pb03_s3_restore_bpa` | Keep the repo names. A contract test fails if code and `playbooks.tf` drift. |
| C3 | Scope tag `cloudshield:soar-enabled = "true"` | `cloudshield:soar-scope = in-scope`, passed to Lambdas as `SCOPE_TAG_KEY/VALUE` and used in every IAM condition | Read the tag from env. No hard-coded tag anywhere in code. |
| C4 | Contract at `infra/modules/soar/README.md` | It is `soar/README.md` | Use the real path. |
| C5 | **Per-IP** NACL deny for the instance's private IP | A NACL is evaluated at the subnet boundary: inbound rules match the **source** IP and outbound rules the **destination**. A rule naming the instance's own IP, in its own subnet's NACL, never matches its traffic. | **Decision needed.** Default: subnet-level deny-all on a **dedicated** worker NACL (§3.3). |
| C6 | Detach from ASG / target group | The report-worker is a standalone `aws_instance`, in no ASG or target group | Detect and record only (`autoscaling:DescribeAutoScalingInstances`). No detach permissions: they would add mutating IAM for a case that can't occur in this design. |
| C7 | Write evidence "under Object Lock" | Object Lock is off by default (`evidence_object_lock_days = 0`) because it blocks `terraform destroy` | Code relies on the bucket's **default retention**. When the flag is on for the graded run, every object is locked without needing `s3:PutObjectRetention`. |
| C8 | Record `guardduty_created_at` and `event.time` | The router's `RecordDetected` already writes `eventTime` and `findingCreatedAt`, and `MarkContained` writes `containedAt` (ADR-0002 §3) | `Finding` exposes both times. Playbooks add `containmentVerifiedAt`. The official MTTC stays `containedAt − eventTime`. |
| C9 | `Notifier` class | The router's `Notify` state publishes to SNS. Lambdas have no `sns:Publish`. | Notification stays in the router. No Lambda-side SNS permission (least privilege). Figure 8.6's `Notifier` maps to that state. |

## 2. Package layout

Zip root = `soar/` minus tests, so the handler paths in `playbooks.tf` resolve unchanged.

```
soar/
  pyproject.toml                 ruff + pytest + coverage config
  requirements-dev.txt           pinned: pytest, pytest-cov, moto[ec2,iam,s3,dynamodb,ssm,autoscaling], ruff
  core/
    config.py                    Settings.from_env(): every env var in soar/README.md, validated
    finding.py                   Finding (frozen dataclass) + parse(event) -> Finding | raises MalformedFinding
    guard.py                     SafetyGuard (rules 1-5, in order) -> Decision(allowed, dry_run, reason)
    playbook.py                  abstract Playbook: run(action, state) -> dict; dry-run gate; verify() contract
    incidents.py                 IncidentRepository: append_action(), set_evidence(), mark_verified()
    evidence.py                  EvidenceCollector: put_manifest() with ChecksumAlgorithm=SHA256, returns hex + b64
    aws.py                       boto3 clients with fixed timeouts and retries (Lambda < 60 s budget)
  safety_guard/handler.py        lambda_handler -> {"allowed": bool, "dry_run": bool, "reason": str}
  playbooks/pb01_ec2_isolate.py  actions: isolate | snapshot
  playbooks/pb02_iam_key_revoke.py  action: revoke
  playbooks/pb03_s3_restore_bpa.py  action: restore
  tests/
    fixtures/                    GuardDuty events: Recon:EC2/Portscan, InstanceCredentialExfiltration.OutsideAWS,
                                 an IAMUser AccessKey finding, Policy:S3/BucketBlockPublicAccessDisabled, + sample variants
    conftest.py                  moto mock_aws, env, seeded VPC/instance/NACL/user/bucket/table/param
    test_finding.py  test_guard.py  test_pb01.py  test_pb02.py  test_pb03.py
    test_contract.py             return shapes are real bools; handler names match playbooks.tf
    test_packaging.py            two builds produce byte-identical zips
scripts/package_soar.py          deterministic zip builder
```

### Object model (Figure 8.6)

- **`Finding`**: `id`, `type`, `severity`, `resource_type`, `is_sample`, `event_time` (EventBridge `time`), `created_at` (GuardDuty), plus a `target` resolved to one of:
  - `Ec2Target(instance_id)`: from `instanceDetails`, or from `accessKeyDetails.principalId` (`AROA…:i-…`) for `InstanceCredentialExfiltration*`
  - `IamUserTarget(user_name, access_key_id)`: only when `userType == "IAMUser"`
  - `S3BucketTarget(bucket_name)`
  - `UnknownTarget`
- **`SafetyGuard`**: pure logic over `Finding` + injected tag-reader + dry-run reader, so it is unit-testable without AWS.
- **`Playbook`** (abstract): `execute()` / `verify()` / `plan()`. The base class enforces:
  1. Act only when the guard decision's `dry_run is False` **and** a fresh read of `DRY_RUN_PARAM` is `"false"`. Anything else is dry-run. This is defence in depth on top of the router.
  2. `contained` is `True` only when `verify()` returns `True`.
  3. Every step is appended to the incident row.
  4. AWS errors propagate, so the router records `FAILED`. Nothing is swallowed into a false `contained`.
- **`EvidenceCollector`**, **`IncidentRepository`**: thin, typed wrappers. Each is the only place its table or bucket name is used.

## 3. Behaviour per function

### 3.1 `safety_guard`

Rules in `soar/README.md` order:

1. Dry-run param on every call; unreadable → `allowed=false`.
2. Sample finding: allowed **only** in dry-run.
3. Scope tag on the resolved target, plus `BUCKET_NAME_PREFIX` for buckets.
4. Unknown target → `allowed=false`.
5. `dry_run` is always a bool.

The whole handler is wrapped: any exception or malformed payload returns `{"allowed": false, "dry_run": true, "reason": "guard error: <type>"}`. A guard bug is therefore recorded as `BLOCKED_BY_GUARD`, not as a raw `FAILED`. `AccessKey` findings whose `userType` isn't `IAMUser` (root, assumed role) are blocked as out of scope.

### 3.2 PB-01 `isolate` (Figure 6.5: containment before evidence; idempotent under the router's retries)

1. Resolve the instance. Re-check its scope tag (defence in depth).
2. Make sure it has exactly one ENI. Otherwise fail, because multi-ENI swaps need `ModifyNetworkInterfaceAttribute`.
3. **NACL deny**: insert ingress and egress `deny 0.0.0.0/0, all protocols` at rule numbers `QUARANTINE_NACL_RULE` (default 10, below the allow at 100) on the subnet's NACL. That NACL must be in the `QUARANTINE_NACL_IDS` allow-list. `InvalidNetworkAclEntry.Duplicate` counts as already done. NACLs are stateless, so this **cuts established flows**, which closes gap 10.
4. **SG swap**: `ModifyInstanceAttribute(Groups=[QUARANTINE_SG_ID])`.
5. **Protection**: `DisableApiTermination=True`, `DisableApiStop=True` (same IAM action, already granted on tagged instances).
6. **Revoke instance-role sessions**: instance profile → role (`iam:GetInstanceProfile`). The role must be in `REVOCABLE_ROLE_ARNS`. Then `PutRolePolicy` an inline deny-all with `DateLessThan aws:TokenIssueTime = now`.
7. Record ASG membership, if any, as `asgAttached` for the analyst. Detect only (C6).
8. **Verify**: re-describe the instance and NACL. The only SG is quarantine, both deny entries exist, and both protections are on. Return `contained: true`.

Steps 3–4 are the "network isolation" that `contained` depends on. If step 6 fails (role not revocable), the playbook raises, because stolen role credentials remaining valid is not containment in scenario A.

### 3.3 Established-connection fix (gap 10): dedicated worker NACL

- **network module**: new `aws_network_acl.private_worker` attached to the `private_worker` subnets, with allow-all rules at 100 (in and out). This is identical to today's behaviour on the default NACL, so nothing changes until PB-01 acts. Output its id.
- **Blast radius**: the deny covers the whole worker tier, i.e. both worker subnets. Today the only resource there is the report-worker. App subnets keep the default NACL and are untouched.
- **Recovery is human**: delete the two entries. A runbook goes in `soar/README.md`.

**Rejected:**
- SSM kill. The quarantine SG blocks the agent's own 443 egress, so it would have to run before the swap: slower, and the agent may already be compromised.
- Per-IP rules (C5). They don't match.

### 3.4 PB-01 `snapshot` (after CONTAINED)

1. `CreateSnapshot` per attached volume, tagged at creation with incident id, finding type, instance and execution ARN. The volume must carry the scope tag (IAM).
2. Build the manifest JSON: snapshot ids, volume ids, actor = execution ARN, UTC times.
3. `PutObject` to `EVIDENCE_BUCKET/incidents/<id>/manifest.json` with `ChecksumAlgorithm=SHA256`.
4. Compare the returned checksum with the locally computed one. Store hex + base64 on the incident row (`UpdateItem`).

### 3.5 PB-02 `revoke` (IAM user key)

1. `UpdateAccessKey(Status=Inactive)` for the finding's key.
2. `PutUserPolicy` deny-all on `aws:TokenIssueTime` < now. IAM allows it only when the user carries the SOAR boundary. An `AccessDenied` here is recorded as `sessionRevoke: denied-by-boundary-guardrail` and does **not** block containment, because the deactivated key is the containment.
3. **Verify**: `ListAccessKeys` shows the key `Inactive`, then `contained: true`.

### 3.6 PB-03 `restore` (bucket public exposure)

1. **Read the pre-state first**, because restoring overwrites the old BPA flags: `GetPublicAccessBlock`, `GetBucketPolicy` (`NoSuchBucketPolicy` → null), `GetBucketAcl`, `GetBucketPolicyStatus`.
2. `PutPublicAccessBlock` with all four flags `true`.
3. Verify with `GetPublicAccessBlock`; `contained: true` comes from here.
4. Write the pre-state JSON to `EVIDENCE_BUCKET/incidents/<id>/s3-prestate.json` (SHA-256), and record the hash on the row.

Because the evidence write comes after verify, it doesn't count toward MTTC. The router has no snapshot step for S3, so this all happens in one invocation.

## 4. IaC changes (owned by @ahklsfg; network module is co-owned with @ELSHAHALY)

| File | Change |
|---|---|
| `modules/network/main.tf`, `outputs.tf` | `aws_network_acl.private_worker` + rules 100 allow in/out (Checkov skip with reason) + output `private_worker_network_acl_id` |
| `modules/soar/variables.tf` | `quarantine_network_acl_ids` (list(string), default `[]`) |
| `modules/soar/playbooks.tf` pb01 | `ec2:CreateNetworkAclEntry` on exactly those NACL ARNs; `ec2:DescribeNetworkAcls`, `ec2:DescribeInstanceAttribute` (Describe, `*`); `iam:GetInstanceProfile` on `instance-profile/${name}-*`; `autoscaling:DescribeAutoScalingInstances` (`*`) |
| `modules/soar/playbooks.tf` pb03 | `s3:GetBucketPolicy`, `s3:GetBucketAcl`, `s3:GetBucketPolicyStatus` on `${name}-*`; `s3:PutObject` on the evidence bucket |
| `modules/soar/playbooks.tf` env | `QUARANTINE_NACL_IDS`, `QUARANTINE_NACL_RULE` |
| `environments/dev/main.tf` | Wire `module.network.private_worker_network_acl_id` → soar |
| `modules/soar/tests/soar.tftest.hcl` | Assert the NACL permission is scoped to the given NACL ARNs only, and that pb03 can write evidence |
| `docs/adr/0003-pb01-nacl-quarantine.md` | Records the gap-10 decision and its blast radius |

## 5. Quality gates

- **New CI job** `gate: soar (ruff + pytest)`:
  - Python 3.13, `ruff check`, `ruff format --check`, `pytest --cov=core --cov=safety_guard --cov=playbooks --cov-fail-under=90`.
  - **Hard-fails** like `terraform fmt`, because it is a correctness check and not a scanner finding.
  - Add it to branch protection after merge.
- **Semgrep**: the gate currently runs only `p/owasp-top-ten` + `p/nodejs`. Propose adding `p/python` so the new code is actually covered.
- **Trivy fs**: scans `soar/requirements-dev.txt`, so dependencies are pinned to current releases.
- **Gitleaks**: fixtures use the documented placeholder account `123456789012` and fake key ids (`ASIA…EXAMPLE`-style), never `AKIAIOSFODNN7EXAMPLE`.
- **Makefile**: `soar-lint`, `soar-test`, and `package-soar` → `build/soar-playbooks.zip` + its SHA-256.
  - The zip is deterministic: sorted entries, fixed 1980-01-01 mtimes, 0644 permissions, no `__pycache__`.
  - boto3 isn't vendored; the Lambda runtime provides it.

## 6. Test matrix (written before the code, guard first)

| Area | Cases |
|---|---|
| Guard | Dry-run param `true` / `false` / missing / garbage / SSM error; sample × dry-run on/off; tag present / absent / wrong value; exfiltration principalId parse (good, malformed, non-instance); IAM user tagged / untagged / non-IAMUser `userType`; bucket with and without prefix and tag; unknown resource type; empty, `None` and non-dict events; return types are exactly `bool` |
| PB-01 | Happy path (moto) with every verification true; dry-run makes **zero** mutating calls; NACL not in allow-list → raises; multi-ENI → raises; duplicate NACL entry → idempotent; role not in `REVOCABLE_ROLE_ARNS` → raises; `ClientError` on swap → raises; snapshot manifest hash matches the S3 checksum and lands on the row |
| PB-02 | Deactivates the key; boundary `AccessDenied` on `PutUserPolicy` is recorded and still `contained`; key not found → raises; dry-run makes no calls |
| PB-03 | Restores all 4 flags; pre-state captured **before** the restore (including a missing policy); wrong prefix → raises; evidence hash on the row |
| Contract | Handler module paths equal the `handler =` strings in `playbooks.tf`; every return value's `allowed` / `dry_run` / `contained` is a `bool` |

Stubber is used only where moto lacks an API, such as `DisableApiStop` if unsupported. This is confirmed during the build.

## 7. Phase A follow-ups (done / open)

- **Done.** The first CI run failed only in the iac gate, at `terraform test`: the bare `mock_provider` produced random strings that failed JSON-policy and ARN validation. Fixed on `fix/ci-terraform-test-mocks`. All 11 tests pass locally on TF 1.16.5, and `validate` passes in all 7 dirs. **Open:** CI only runs on a PR or on `main`, so a PR must be opened from that branch (no `gh` on this machine).
- **Done.** `docs/runbooks/repo-admin-setup.md`: collaborators, variables, branch protection.
- **Open, not in scope here.** There's no artifacts bucket in Terraform for the Lambda zip. Testing `soar_playbook_package` with `terraform plan` works offline in `terraform test`; a real apply needs a versioned bucket (S1).

## 8. Agent pipeline from here

1. **Builder**: IaC deltas → core + guard (tests first) → PB-01 → PB-02 → PB-03 → packaging + CI job.
2. **Independent Auditor**: a fresh agent that hasn't seen the build. It reviews fail-closed paths, IAM least privilege and contract drift.
3. **Validator**: ruff, pytest + coverage, `terraform fmt`/`validate`/`test`, Checkov on the changed modules, zip determinism.
4. **Orchestrator summary** + handoff update.
