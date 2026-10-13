# soar/ — S3 (SecOps / SOAR / Forensics) · @ahklsfg

The automated containment engine (plan §6.2–6.5, class model §8.6). The infrastructure is already in `infra/terraform/modules/soar/`. This folder holds the **Python code** that infrastructure runs. Package it as one zip and pass its S3 location as `soar_playbook_package` to switch the playbooks on.

## Layout and handler contract (must match `modules/soar/playbooks.tf`)

```
soar/
  safety_guard/handler.py           lambda_handler(event, ctx) -> {"allowed": bool, "dry_run": bool, "reason": str}
  playbooks/pb01_ec2_isolate.py     lambda_handler(event, ctx), event = {"action": "isolate"|"snapshot", "event": <router state>}
  playbooks/pb02_iam_key_revoke.py  event = {"action": "revoke",  "event": ...}
  playbooks/pb03_s3_restore_bpa.py  event = {"action": "restore", "event": ...}
  tests/                            pytest; moto for AWS calls
```

The router state contains the original EventBridge event (`detail`, `time`, …) and `guard.decision`.

**Return contract.** The router treats anything else as a failure: it **fails closed**.

| Function | Must return | If it doesn't |
|---|---|---|
| safety guard | `{"allowed": true/false, "dry_run": true/false, "reason": "…"}` with real **booleans** | Anything but a boolean `allowed: true` is recorded as `BLOCKED_BY_GUARD`. Anything but a boolean `dry_run: false` is recorded as `WOULD_CONTAIN_DRY_RUN`. |
| playbook `isolate`/`revoke`/`restore` | `{"contained": true, ...details}` **only after verifying** the change (for example, re-describe the instance and confirm its only security group is quarantine) | Recorded as `FAILED` and never as CONTAINED, so no MTTC figure is produced. |
| playbook in dry-run | `{"contained": false, "would": "<action>"}` | — |

## Environment variables every function receives

`DRY_RUN_PARAM`, `SCOPE_TAG_PARAM`, `SCOPE_TAG_KEY`, `SCOPE_TAG_VALUE`, `INCIDENTS_TABLE`, `EVIDENCE_BUCKET`, `QUARANTINE_SG_ID`, `REVOCABLE_ROLE_ARNS`, `BUCKET_NAME_PREFIX`.

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

IAM enforces rule 3 independently: every mutating permission is conditioned on the scope tag. A bug in the guard can't widen what a playbook may touch.

## PB-01 notes

- `isolate` runs **before** CONTAINED:
  - Swap the security group onto `QUARANTINE_SG_ID` with `ec2:ModifyInstanceAttribute`.
  - Revoke the instance role's sessions: an inline deny on `aws:TokenIssueTime` earlier than now, on roles in `REVOCABLE_ROLE_ARNS`. IAM allows this only on roles carrying the SOAR target permissions boundary.
  - Then verify, and return `contained: true`. Keep it well under 60 s.
  - The same function handles `InstanceCredentialExfiltration*` findings, which arrive with `resourceType = AccessKey`. Get the instance id from `accessKeyDetails.principalId`.
- The security-group swap **does not cut established connections**, because security groups are stateful. The fix (an SSM process stop, or a deny NACL) needs **extra IAM** that the module does not grant yet: `ssm:SendCommand` on the in-scope instance, or `ec2:ReplaceNetworkAclAssociation`. Add it to `modules/soar/playbooks.tf` (pb01) together with the code, and record which option you chose.
- `snapshot` runs **after** CONTAINED:
  - Snapshot each in-scope volume. Tags are written at creation.
  - Write a manifest to `EVIDENCE_BUCKET` with the snapshot IDs, actor (the execution ARN) and UTC times. Upload it with `ChecksumAlgorithm=SHA256`.
  - Store the returned SHA-256 **on the incident row** (`UpdateItem`). A file cannot contain its own hash.
  - The manifest plus the hash on the row form the chain-of-custody record.

## Non-negotiables

- Automation stops at **CONTAINED**. Eradication and recovery stay human-gated (§6.4).
- Every action updates the incident row. MTTC = `containedAt − eventTime` (ADR-0002 §3).
