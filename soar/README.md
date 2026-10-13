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
  safety_guard/handler.py           lambda_handler(event, ctx) -> {"allowed": bool, "dry_run": bool, "reason": str}
  playbooks/pb01_ec2_isolate.py     lambda_handler(event, ctx), event = {"action": "isolate"|"snapshot", "event": <router state>}
  playbooks/pb02_iam_key_revoke.py  event = {"action": "revoke",  "event": ...}
  playbooks/pb03_s3_restore_bpa.py  event = {"action": "restore", "event": ...}
  tests/                            pytest + moto (no AWS credentials); test_contract.py fails if this drifts from playbooks.tf
```

The router state contains the original EventBridge event (`detail`, `time`, …) and `guard.decision`.

**Return contract.** The router treats anything else as a failure: it **fails closed**.

| Function | Must return | If it doesn't |
|---|---|---|
| safety guard | `{"allowed": true/false, "dry_run": true/false, "reason": "…"}` with real **booleans** | Anything but a boolean `allowed: true` is recorded as `BLOCKED_BY_GUARD`. Anything but a boolean `dry_run: false` is recorded as `WOULD_CONTAIN_DRY_RUN`. |
| playbook `isolate`/`revoke`/`restore` | `{"contained": true, ...details}` **only after verifying** the change (for example, re-describe the instance and confirm its only security group is quarantine) | Recorded as `FAILED` and never as CONTAINED, so no MTTC figure is produced. |
| playbook in dry-run | `{"contained": false, "would": "<action>"}` | — |

## Environment variables every function receives

`DRY_RUN_PARAM`, `SCOPE_TAG_PARAM`, `SCOPE_TAG_KEY`, `SCOPE_TAG_VALUE`, `INCIDENTS_TABLE`, `EVIDENCE_BUCKET`, `QUARANTINE_SG_ID`, `QUARANTINE_NACL_IDS`, `QUARANTINE_NACL_RULE`, `REVOCABLE_ROLE_ARNS`, `BUCKET_NAME_PREFIX`.

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
   - a bucket, which also needs the `BUCKET_NAME_PREFIX` prefix.
4. An unknown resource type gives `allowed=false`.
5. Always return `dry_run` as a boolean. The router uses it to choose `CONTAINED` or `WOULD_CONTAIN_DRY_RUN`.

IAM backs rule 3 independently, so a bug in the guard can't widen what a playbook may touch:

- EC2 instance and volume mutations and the IAM user mutations are conditioned on the scope tag.
- Role-session revocation is limited to `REVOCABLE_ROLE_ARNS` and needs the SOAR target boundary.
- NACL entries are limited to the given NACL ARNs.
- PB-03 is limited by the bucket-name prefix (gap 12).

All three playbooks also re-check the tag in code before acting. `SCOPE_TAG_PARAM` holds the same tag for operators; the code reads it from `SCOPE_TAG_KEY` / `SCOPE_TAG_VALUE`.

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

## Develop

```bash
cd soar
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
ruff check . && ruff format --check .
pytest --cov                                       # fails under 90 % coverage
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
