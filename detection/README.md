# detection/ — S3 (SecOps)

The detection layer behind the SOAR engine: what sees the attack, and what the analyst hunts through afterwards. The Terraform is `infra/terraform/modules/detection`; this folder holds the catalogued Athena queries it registers.

| Path | What goes here |
|---|---|
| `athena-queries/` | The catalogued hunt queries (FR-8). One `.sql` per query; the header gives the ATT&CK technique, scenario, tables and parameters. Terraform turns each into an `aws_athena_named_query` in the `cs-forensics` workgroup, so the repo file and the saved query are the same text. |

## What the module creates (ADR-0002 module map)

| Service | Default | Purpose |
|---|---|---|
| GuardDuty detector | **on** | Findings drive `cs-ir-router` (modules/soar). Also exported to the log archive (`guardduty/`) for Athena. |
| GuardDuty S3 / Runtime / Malware protection | off | Paid after the trial; not needed for the three scenarios. Toggle per flag. |
| CloudTrail | **on** | Management events + S3 **data events for exactly the evidence and documents buckets** (and the lab bucket when enabled). This is the compensating control for the missing S3 server access logs (handoff gap 16). Delivered to the log archive (`cloudtrail/`), with log-file validation. |
| AWS Config | **on** | Recorder scoped to `AWS::S3::Bucket` (cost), plus `S3_BUCKET_PUBLIC_READ_PROHIBITED` and `S3_BUCKET_PUBLIC_WRITE_PROHIBITED`. NON_COMPLIANT results notify the analyst via the SOAR SNS topic. |
| Security Hub (+ CIS v3.0.0, PCI DSS v3.2.1) | off | Per-check cost; its controls need Config to record more than S3. Toggle per flag. |
| Athena `cs-forensics` workgroup | **on** | Settings **enforced**: a 1 GiB per-query scan cap and KMS-encrypted results. Glue catalog (`<name>_forensics`) with partition projection for `cloudtrail`, `vpc_flow_logs` and `guardduty_findings` — no crawlers, no `MSCK REPAIR`. |
| Glue table `waf_logs` (Phase D) | with `enable_edge` | Both web ACLs' logs in the `aws-waf-logs-<name>-<acct>` bucket (`modules/log-archive`, archive key; `authorization`, `cookie` and `x-origin-verify` redacted). Columns follow AWS's WAF DDL; partition projection on `waf_region` (`cloudfront`, `<region>`), `webacl` (the two ACL names) and `log_time` (`yyyy/MM/dd/HH/mm`, 1-minute interval). |

## Scenario C: containment vs. notification

GuardDuty and Config both see a public bucket, but they do different jobs:

- **Containment** is driven by GuardDuty `Policy:S3/BucketBlockPublicAccessDisabled` → `cs-ir-router` → PB-03. (The router consumes GuardDuty findings only.)
- **Config** `NON_COMPLIANT` is a second, independent signal that notifies the analyst. It does not drive a playbook.

## GuardDuty: one detector per region

A region holds a single detector. If one already exists (e.g. S1 ran `aws guardduty create-detector --enable`), either import it or set `manage_guardduty_detector = false`:

```bash
# import an existing detector instead of creating a second one
terraform import 'module.detection.aws_guardduty_detector.this[0]' <detector-id>
# the same applies to the Config recorder (also one per region):
terraform import 'module.detection.aws_config_configuration_recorder.this[0]' <name>-recorder
```

## Hunt queries

Parameterised with Athena `?` placeholders — run them with `PREPARE` / `EXECUTE ... USING`, in the `cs-forensics` workgroup and the `<name>_forensics` database. Each filters on a partition column, so a run stays far under the 1 GiB cap.

| File | ATT&CK | Scenario | Answers |
|---|---|---|---|
| `01_attacker_timeline_by_principal.sql` | T1078, T1552.001/005 | A, B | Every CloudTrail call by an access key / principal / source IP, oldest first. |
| `02_imds_and_recon_flow.sql` | T1046, T1552.005 | A | Per-minute scan shape (flow logs) next to the worker role's API calls from a foreign IP. |
| `03_s3_public_exposure_audit.sql` | T1530 | C | Exposure changes and object access on the bucket during the window, with external access flagged. |
| `04_waf_blocked_requests_by_client.sql` | T1190, T1595, T1499 | QA, E | Every request the WAFs did not simply allow, per client IP / ACL / terminating rule / action: counts, first and last seen, sample URIs, the IPs the rate rule was limiting (what the PB-05 harvester publishes) and `SoarBlockedIps` hits (a PB-05 block taking effect). Parameters: the first and last `log_time` minute. On the regional ACL the client IP is CloudFront's (use the `cloudfront` rows). |

`soar/tools/generate_ir_report.py` builds the per-incident chain-of-custody report (FR-8); see `soar/sims/README.md` for the simulation harness that produces the incidents these queries read.

## Cost (lab, after any free trial)

| Service | Rough cost | Note |
|---|---|---|
| CloudTrail | first management trail free; data events ~$0.10 / 100k events | Scoped to 2–3 buckets, so data-event volume is small. |
| AWS Config | ~$0.003 per configuration item | S3 buckets only. |
| GuardDuty | free 30 days, then per-event | Paid protections stay off. |
| Athena | $5 / TB scanned, **capped at 1 GiB/query** | ≈ $0.005 max per hunt query. |
| Security Hub | per check | Off by default. |

`terraform destroy` removes everything; `force_destroy` on the result bucket is on for the lab.
