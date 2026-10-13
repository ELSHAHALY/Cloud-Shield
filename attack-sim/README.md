# attack-sim/ — S3 (SecOps)

Scripts for scenarios A–C and the QA web attack (plan §7).

**Rules (risk R4, AWS Abuse):**

1. Only target resources in our own account. Never a third-party IP or host.
2. Use honeytoken keys only. Real credentials are never used as "leaked" ones.
3. Every script starts with a guard that checks the caller's account ID against an allow-list, and exits otherwise.
4. Every script has a matching `cleanup` step that restores the original state, for example by re-enabling Block Public Access after scenario C.

| Scenario | ATT&CK | Expected detection | Playbook |
|---|---|---|---|
| A — EC2 / IMDS abuse | T1552.005 / T1046 | GuardDuty UnauthorizedAccess / Recon | PB-01 |
| B — Leaked IAM key | T1078 / T1552.001 | GuardDuty IAMUser anomaly | PB-02 |
| C — Public S3 | T1530 | Config rule + GuardDuty S3 | PB-03 |
| QA — Web attack | T1190 | WAF rules + rate limit | PB-05 |
