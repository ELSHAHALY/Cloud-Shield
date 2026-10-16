# soar/ — S3 (SecOps / SOAR / Forensics) · @ahklsfg

The automated containment engine (plan §6.2–6.5, class model §8.6). The infrastructure is already in `infra/terraform/modules/soar/`. This folder holds the **Python code** that infrastructure runs. Package it as one zip and pass its S3 location as `soar_playbook_package` to switch the playbooks on.

## Layout and handler contract (must match `modules/soar/playbooks.tf`)

```
soar/
  core/                             shared object model (plan §8.6)
    finding.py                      Finding: parsed GuardDuty event + resolved target, both MTTC times
    guard.py                        SafetyGuard: rules 1-5 below, fail closed
    playbook.py                     abstract Playbook: dry-run gate, verify-before-contained, action log
    incidents.py                    IncidentRepository: action log + evidence fields (never `status`)
    evidence.py                     EvidenceCollector: canonical JSON, SHA-256 checked by S3
    config.py, aws.py               env settings; boto3 clients with short timeouts
    http.py                         post_json: the ONLY outbound-HTTPS call site (F27)
    attack.py                       finding type -> ATT&CK, impact, eradication, recovery (deterministic)
    notifier.py                     ChatOps parsing, card, webhook secret cache
  safety_guard/handler.py           lambda_handler(event, ctx) -> {"allowed": bool, "dry_run": bool, "reason": str}
  playbooks/pb01_ec2_isolate.py     lambda_handler(event, ctx), event = {"action": "isolate"|"snapshot", "event": <router state>}
  playbooks/pb02_iam_key_revoke.py  event = {"action": "revoke",  "event": ...}
  playbooks/pb03_s3_restore_bpa.py  event = {"action": "restore"|"evidence", "event": ...}
  playbooks/pb04_ecs_task_contain.py event = {"action": "contain"|"evidence", "event": ...}
  playbooks/pb05_waf_ip_block.py    event = {"action": "block", "event": ...}; also harvest_handler (the PB-05 publisher)
  notifier/handler.py               lambda_handler(SNS event, ctx) -> {"posted": bool, ...}; never raises
  tools/                            operator CLIs, NOT in the Lambda zip: generate_ir_report, ai_summary, list_expired_blocks
  sims/                             attack simulations (sims/README.md)
  tests/                            pytest + moto (no AWS credentials, no network); test_contract.py fails if this drifts from Terraform
```

| Terraform function (`<name>-…`) | Handler | Created when |
|---|---|---|
| `soar-safety-guard` | `safety_guard.handler.lambda_handler` | `soar_playbook_package` set |
| `soar-pb01-ec2-isolate` / `soar-pb02-iam-key-revoke` / `soar-pb03-s3-restore-bpa` | `playbooks.pb0N_….lambda_handler` | package set |
| `soar-pb04-ecs-task-contain` (55 s) | `playbooks.pb04_ecs_task_contain.lambda_handler` | package + `enable_pb04` |
| `soar-pb05-waf-ip-block` (20 s) | `playbooks.pb05_waf_ip_block.lambda_handler` | package + `enable_pb05` |
| `soar-pb05-harvester` | `playbooks.pb05_waf_ip_block.harvest_handler` | package + `enable_pb05` |
| `soar-notifier` | `notifier.handler.lambda_handler` | package + `chatops_webhook_param_name` |

The router state contains the original EventBridge event (`detail`, `time`, …) and `guard.decision`.

**Return contract.** The router treats anything else as a failure: it **fails closed**.

| Function | Must return | If it doesn't |
|---|---|---|
| safety guard | `{"allowed": true/false, "dry_run": true/false, "reason": "…"}` with real **booleans** | Anything but a boolean `allowed: true` is recorded as `BLOCKED_BY_GUARD`. Anything but a boolean `dry_run: false` is recorded as `WOULD_CONTAIN_DRY_RUN`. |
| playbook `isolate`/`revoke`/`restore` | `{"contained": true, ...details}` **only after verifying** the change (for example, re-describe the instance and confirm its only security group is quarantine) | Recorded as `FAILED` and never as CONTAINED, so no MTTC figure is produced. |
| playbook in dry-run | `{"contained": false, "would": "<action>"}` | — |

## Environment variables

**Guard and playbooks** (`lambda_env` in `playbooks.tf`): `DRY_RUN_PARAM`, `SCOPE_TAG_PARAM`, `SCOPE_TAG_KEY`, `SCOPE_TAG_VALUE`, `INCIDENTS_TABLE`, `EVIDENCE_BUCKET`, `QUARANTINE_SG_ID`, `QUARANTINE_NACL_IDS`, `QUARANTINE_NACL_RULE`, `REVOCABLE_ROLE_ARNS`, `BUCKET_NAME_PREFIX`, and the Phase D settings below. The Phase D settings are **optional**: empty means the feature is off, and the guard and PB-04 / PB-05 refuse (fail closed).

| Variable | Used by | Meaning |
|---|---|---|
| `ECS_CLUSTER_ARN`, `ECS_SERVICE_NAMES` | guard, PB-04 | the only cluster and services PB-04 may act on |
| `BLOCK_IP_SET_ARNS` | PB-05 | the CLOUDFRONT-scope IPv4 and IPv6 block lists |
| `BLOCK_IP_SET_MAX` (1–10,000, default 1,000), `BLOCK_TTL_HOURS` (1–168, default 24) | PB-05 | cap per IP set; `blockExpiresAt` = block time + TTL |
| `WAF_REGION` | PB-05 | `us-east-1` (CLOUDFRONT scope) |
| `NEVER_BLOCK_PARAM`, `EDGE_EVENT_SOURCE` | guard | never-block SSM parameter; `cloudshield.edge` |

**Harvester** (`edge-bus.tf`): `EDGE_BUS_NAME`, `EDGE_EVENT_SOURCE`, `WAF_WEB_ACL_NAME`, `WAF_WEB_ACL_ID`, `WAF_RATE_RULE_NAME`, `WAF_SCOPE`, `WAF_REGION`.

**Notifier** (`notify.tf`): `INCIDENTS_TABLE`, `CHATOPS_WEBHOOK_PARAM` (the parameter **name**, never the URL), `CHATOPS_ALLOWED_HOSTS` (comma-separated exact host names).

`test_contract.py` asserts that each set equals what the code reads.

## Safety guard rules (write these tests first; they are the R2 control)

Evaluate **in this order**. The first matching rule decides.

1. Read `DRY_RUN_PARAM` on **every** call. Never cache it across invocations. If it is unreadable, return `allowed=false`.
2. **Sample finding** (`detail.service.additionalInfo.sample == true`):
   - `dry_run=true`: `allowed=true`. Skip rule 3, because sample findings point at fake resources that can never carry the tag.
   - `dry_run=false`: `allowed=false` with reason `"sample finding"`.
3. A target without the scope tag gives `allowed=false`. The target is:
   - the instance; or
   - for `InstanceCredentialExfiltration*`, the instance parsed from `detail.resource.accessKeyDetails.principalId` (`AROA…:i-xxxxxxxx`); or
   - the IAM user; or
   - a bucket, which also needs the `BUCKET_NAME_PREFIX` prefix; or
   - **ECS task (PB-04):** see "Rule 3 for ECS" below; or
   - **IP address (PB-05):** an IP has no tags, so "Rule 3 for IPs" below replaces the tag check.
4. An unknown resource type gives `allowed=false`.
5. Always return `dry_run` as a boolean. The router uses it to choose `CONTAINED` or `WOULD_CONTAIN_DRY_RUN`.

IAM backs rule 3 independently, so a bug in the guard can't widen what a playbook may touch:

- EC2 instance and volume mutations and the IAM user mutations are conditioned on the scope tag.
- Role-session revocation is limited to `REVOCABLE_ROLE_ARNS` and needs the SOAR target boundary.
- NACL entries are limited to the given NACL ARNs.
- PB-03 is limited by the bucket-name prefix (gap 12).

**Rule 3 for ECS** (`resourceType = ECSCluster` with `ecsClusterDetails.taskDetails.arn`): refuse unless PB-04 is configured, the task was launched by a service (`group = service:<name>`), the finding's cluster equals `ECS_CLUSTER_ARN`, and the service is in `ECS_SERVICE_NAMES`. Then `DescribeTasks` on the **live** task: it must be in that cluster, its live `group` must match, and its live tags must carry the scope tag. Tags embedded in the finding are never trusted.

**Rule 3 for IPs** (only `source = cloudshield.edge` with `resourceType = IPAddress`; any other combination is an unknown target). The first failure refuses:

1. The event source is `EDGE_EVENT_SOURCE`, and its `time` is within [now − 15 min, now + 60 s].
2. Exactly one address: no `/`, no zone id; IPv4-mapped IPv6 is normalised to IPv4.
3. Global unicast only: `is_global`, and not multicast, unspecified or reserved. Private, loopback, link-local, shared (100.64/10) and documentation ranges are refused.
4. Not inside any CIDR of the never-block parameter (`NEVER_BLOCK_PARAM`), read on **every** call. Format: comma-separated CIDRs, each with an explicit prefix (`/32` for one host). Unset, unreadable, empty, or **any** invalid entry → every block is refused.

All playbooks also re-check the scope in code before acting. `SCOPE_TAG_PARAM` holds the same tag for operators; the code reads it from `SCOPE_TAG_KEY` / `SCOPE_TAG_VALUE`.

## PB-01 notes

- `isolate` runs **before** CONTAINED:
  - Swap the security group onto `QUARANTINE_SG_ID` with `ec2:ModifyInstanceAttribute`.
  - Revoke the instance role's sessions: an inline deny on `aws:TokenIssueTime` earlier than now, on roles in `REVOCABLE_ROLE_ARNS`. IAM allows this only on roles carrying the SOAR target permissions boundary.
  - Then verify, and return `contained: true`. Keep it well under 60 s.
  - The same function handles `InstanceCredentialExfiltration*` findings, which arrive with `resourceType = AccessKey`. Get the instance id from `accessKeyDetails.principalId`.
- **Established connections (gap 10): decided in ADR-0003.** Security groups are stateful, so the swap alone leaves tracked connections open. Before the swap, PB-01 adds deny-all entries (rule `QUARANTINE_NACL_RULE`, default 10) to the dedicated worker-tier NACL. It may only add entries, and only to NACLs in `QUARANTINE_NACL_IDS`. It also sets termination and stop protection. `contained: true` requires every one of these to read back correctly. Recovery is manual: see ADR-0003.
- Single-ENI instances only (a multi-ENI swap would need more IAM). ASG membership is recorded for the analyst, not changed.
- **Credential exfiltration** (`InstanceCredentialExfiltration*`): revoking the stolen role session *is* the containment. The instance must have a role, and its `RoleId` must equal the role id in the finding's `principalId`. Otherwise PB-01 refuses before making any change. The revocation is read back (`iam:GetRolePolicy`) as `roleSessionsRevoked`.
- Verification re-reads AWS up to 3 times, 1 s apart (eventual consistency), before it reports "not contained".
- `snapshot` runs **after** CONTAINED:
  - Snapshot each in-scope volume. Tags are written at creation.
  - Write a manifest to `EVIDENCE_BUCKET` with the snapshot IDs, actor (the execution ARN) and UTC times. Upload it with `ChecksumAlgorithm=SHA256`.
  - Store the returned SHA-256 **on the incident row** (`UpdateItem`). A file cannot contain its own hash.
  - The manifest plus the hash on the row form the chain-of-custody record.

## PB-02 and PB-03 notes

- **PB-02** revokes the user's sessions **and** deactivates the key, and reads both back.
  - Deactivating a key doesn't kill the `GetSessionToken` / `GetFederationToken` credentials already minted from it. So if the session revoke is refused (the user lacks the SOAR target boundary), the incident is **not** contained.
  - A temporary (`ASIA…`) key in the finding deactivates the user's long-term keys instead.
  - Not covered: sessions of roles the user assumed.
- **PB-03** acts only on `Policy:S3/Bucket*` findings. The router sends other S3 findings to an analyst (`NoPlaybook`), because Block Public Access doesn't stop an authenticated principal.
  - `restore` captures the pre-state with short single-attempt reads, restores all four BPA flags, verifies, and returns the pre-state.
  - The router step `PB03Evidence` (action `evidence`) stores it as hashed evidence **after** CONTAINED, outside the MTTC window.
- **Evidence records are append-only.** `evidenceRecords` collects every manifest. `evidenceSha256` keeps the first hash, so a re-run never displaces the original evidence.

## PB-04 notes (ECS task, ADR-0005)

- `contain` runs **before** CONTAINED (timeout 55 s):
  - Re-check the scope, then `DescribeServices`: the service must carry the scope tag, and the task's `startedBy` must be one of the service's `deployments[].id` (a forged `group` cannot redeploy the wrong service).
  - Capture the task and its task definition **in memory, before** `StopTask` (returned as `prestate`).
  - `StopTask` (already stopping: skipped), then `UpdateService(forceNewDeployment)` (skipped on a retry when a fresh PRIMARY deployment that is not the task's own already exists).
  - Verify every 2 s for about 45 s: desiredStatus STOPPED, every container STOPPED, task lastStatus DEPROVISIONING or STOPPED; **the specific new deployment** is PRIMARY; the service is still in scope.
- `evidence` runs **after** CONTAINED (router step `PB04Evidence`): the prestate becomes `incidents/<id>/pb04-ecs-task-<ts>.json` with SHA-256.
- Not automated: ECS Exec volatile capture and image eradication (`docs/runbooks/pb04-pb05-recovery.md`). `forceNewDeployment` redeploys the **same** image digest.
- Reachable only with GuardDuty Runtime Monitoring on, a container image, and `soar_scope_app_service = true`; Runtime findings route only at `>= min_severity` (D19).

## PB-05 notes (WAF IP block, ADR-0005)

- Events arrive only through the dedicated bus `<name>-soar-edge` (explicit Deny for any publisher not in `pb05_publisher_arns`). The harvester publishes one event per rate-limited key (at most 50, no `Time`); it strips only `/32` (IPv4) and `/128` (IPv6) and passes any other prefix through for the guard to refuse.
- `block`: `GetIPSet` → already present = idempotent success → cap check → add-only `UpdateIPSet` with the `LockToken` (at most 3 attempts on `WAFOptimisticLockException`) → read-back → `blockedCidr`, `ipSetArn`, `blockExpiresAt` on the row.
- Nothing removes a block automatically: `make expired-blocks` (`tools/list_expired_blocks.py`, read-only) lists overdue ones with the removal command.

## ChatOps notifier (plan §5.1)

- Subscribed to the incidents SNS topic when `chatops_webhook_param_name` is set (and the package exists). It parses exactly two shapes: the router's `Incident <id> | …` string, and (defensive, while playbooks are off) the raw GuardDuty event. Anything else, including Config notifications, is logged and ignored.
- Card: incident id, finding type, ATT&CK ids (`core/attack.py`), status, MTTC (`containedAt − eventTime`, or "—"), resource type. Slack markup is escaped; Discord mentions are disabled.
- The webhook URL lives only in an SSM **SecureString** under the SOAR key (`docs/runbooks/chatops-setup.md`). It is read with decryption, cached 5 minutes per container, and never logged: logs carry the host only. The AWS SDK loggers are pinned to INFO, because botocore logs response bodies (the decrypted value) at DEBUG.
- `core/http.post_json`: https only, host **exactly** in `CHATOPS_ALLOWED_HOSTS`, no userinfo, port absent or 443, no redirects (a 3xx is an error), no proxies, 3 s timeout, body ≤ 8 KiB, response read ≤ 4 KiB.
- Contract: **never raises into SNS** (async retries would re-post). Every failure returns `{"posted": false, "reason": …}`.
- IAM: exactly `ssm:GetParameter` on that parameter, `dynamodb:GetItem` on the incidents table, `kms:Decrypt` on the SOAR key, and its own logs. No X-Ray (Checkov CKV_AWS_50 skipped with that reason).

## IR report enhancements (plan §5.2)

`python -m tools.generate_ir_report <incident-id> [--format md|json] [--ai-summary]`

- **Executive summary:** status, MTTC verdict, impact, ATT&CK and tactic, eradication and recovery checklists with links to ADR-0003 / ADR-0005 / the recovery runbook. Deterministic, from `core/attack.py` (scenarios A, A-recon, B, C, D, E, and an "analyst review" default).
- **IaC remediation (PB-03 incidents):** a ready-to-apply `aws_s3_bucket_public_access_block` block plus the `terraform import` line, emitted only when PB-03 recorded exactly one bucket name that passes the S3 naming rules. The resource label is `[a-z0-9_]`-sanitised. Anything else: no snippet.
- **Optional AI summary (D17), off by default.** It runs only with `--ai-summary` **and** `CLOUDSHIELD_LLM_PROVIDER=anthropic` **and** `ANTHROPIC_API_KEY`. It sends a redacted projection (finding type, resource type, status, MTTC, step names; ARNs, account ids, IPs, emails, access key ids and bucket names replaced) to `https://api.anthropic.com/v1/messages` (model `claude-opus-5-5`, effort `low`, server-side refusal fallback `"default"`) through `core/http.py`. The output is labelled "AI-generated, advisory"; any error gives "AI summary unavailable" and never changes the exit code. `tools/` is not in the Lambda zip, so no Lambda can import it.

## Develop

```bash
cd soar
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
ruff check . && ruff format --check .
pytest --cov                                       # fails under 95 % coverage
cd .. && make package-soar                          # build/soar-playbooks.zip + its SHA-256
```

CI runs the same checks as `gate: soar (ruff + pytest)`.

To go live:

1. Upload the zip to a versioned S3 bucket.
2. Set `soar_playbook_package = { s3_bucket, s3_key, s3_object_version }`, keeping `soar_dry_run = true`.
3. Replay GuardDuty sample findings. They must end as `WOULD_CONTAIN_DRY_RUN`.
4. Only then flip `soar_dry_run = false`.

## Non-negotiables

- Automation stops at **CONTAINED**. Eradication and recovery stay human-gated (§6.4).
- Every action updates the incident row. MTTC = `containedAt − eventTime` (ADR-0002 §3).
