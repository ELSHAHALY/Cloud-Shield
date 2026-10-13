# attack-sim/ — S3 (SecOps)

The attack simulations now live in **`soar/sims/`** (decision D1: they share the SOAR `core/` and the one `gate: soar` CI job), with full `pytest` coverage. This folder keeps the risk rules they enforce.

See [`soar/sims/README.md`](../soar/README.md) for the runner, modes and scenario table, and [`detection/athena-queries/`](../detection/athena-queries) for the hunt queries that read the incidents they produce.

**Rules (risk R4, AWS Abuse) — enforced in code by `soar/sims/safety.py`:**

1. Only target resources in our own account (`--allowed-account` allow-list; checked against `sts:GetCallerIdentity`). Never a third-party IP or host.
2. Use honeytoken keys only, created and deleted at run time. Real credentials are never used as "leaked" ones.
3. Every run checks the caller's account and region, and that each target carries the scope tag **and** the name prefix, before any AWS call. It exits otherwise.
4. Every live action has a matching, idempotent cleanup (for example, re-enabling Block Public Access after scenario C), run in a `finally:` block.
5. Live mode additionally requires the account id to be retyped (`--confirm-live`).

| Scenario | ATT&CK | Expected detection | Playbook |
|---|---|---|---|
| A — EC2 / IMDS abuse | T1552.005 / T1046 | GuardDuty UnauthorizedAccess / Recon | PB-01 |
| B — Leaked IAM key | T1078 / T1552.001 | GuardDuty IAMUser anomaly | PB-02 |
| C — Public S3 | T1530 | Config rule + GuardDuty S3 | PB-03 |
| QA — Web attack | T1190 | WAF rules + rate limit | PB-05 (not built) |
