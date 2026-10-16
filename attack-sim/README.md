# attack-sim/ — S3 (SecOps)

The attack simulations now live in **`soar/sims/`** (decision D1: they share the SOAR `core/` and the one `gate: soar` CI job), with full `pytest` coverage. This folder keeps the risk rules they enforce.

See [`soar/sims/README.md`](../soar/README.md) for the runner, modes and scenario table, and [`detection/athena-queries/`](../detection/athena-queries) for the hunt queries that read the incidents they produce.

**Rules (risk R4, AWS Abuse) — enforced in code by `soar/sims/safety.py`:**

1. Only target resources in our own account (`--allowed-account` allow-list; checked against `sts:GetCallerIdentity`). Never a third-party IP or host.
2. Use honeytoken keys only, created and deleted at run time. Real credentials are never used as "leaked" ones.
3. Every run checks the caller's account and region, and reads each target's live tags to confirm the scope tag (plus the name prefix for buckets and IAM users), before any pipeline call. It exits otherwise. This check (`verify_targets`) is independent of the pipeline's own guard.
4. Every live action has a matching, idempotent cleanup (for example, re-enabling Block Public Access after scenario C), run in a `finally:` block.
5. Live mode additionally requires the account id to be retyped (`--confirm-live`).

| Scenario | ATT&CK | Expected detection | Playbook |
|---|---|---|---|
| A — EC2 / IMDS abuse | T1552.005 / T1046 | GuardDuty UnauthorizedAccess / Recon | PB-01 |
| B — Leaked IAM key | T1078 / T1552.001 | GuardDuty IAMUser anomaly | PB-02 |
| C — Public S3 | T1530 | Config rule + GuardDuty S3 | PB-03 |
| D — ECS runtime compromise (replay-local, dry-run only) | T1610 / T1059 | GuardDuty Runtime Monitoring | PB-04 (built) |
| E / QA — Web attack, edge IP abuse (replay-local, dry-run only) | T1190 / T1595 | WAF rules + rate limit → harvester → edge bus | PB-05 (built) |

Scenarios D and E never act on a real account (ADR-0005 D20): they refuse `--target aws` and `live-aws`, and exit 3 unless the SSM dry-run switch reads `true`. Scenario E needs `--ip` (no default), and documentation-range addresses are refused by the guard by design. The ZAP baseline in CI is the live QA traffic; it never gets a WAF allow-list. Edge demos run only against our own distribution (`docs/runbooks/edge-waf-demo.md`, rule 1).
