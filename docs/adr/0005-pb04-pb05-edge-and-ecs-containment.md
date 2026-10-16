# ADR-0005: PB-04 (ECS task containment) and PB-05 (WAF IP block)

- **Status:** Accepted (16 Oct 2026)
- **Deciders:** @ahklsfg (S3, owner), @ELSHAHALY (S1: compute service and edge IP sets)
- **Relates to:** plan `docs/plans/s1-s2-edge-identity-waf.md` §4 (D12–D15, D19, D20) and §5 (D16, D17); ADR-0003 (the same "Terraform never lifts a containment" principle); ADR-0004 (where a block takes effect)

## Context

Phase C contained three resource types: EC2 instances (PB-01), IAM keys (PB-02) and S3 buckets (PB-03). Phase D adds the two Phase D attack surfaces:

- **Scenario D:** code execution inside the docs-api Fargate task, seen by GuardDuty Runtime Monitoring as `ECSCluster` + `*:Runtime/*` findings.
- **Scenario E / the QA row:** a client abusing the public edge, seen by the CloudFront WAF's rate rule (and, in Phase E, by a decoy route).

Both playbooks stop at CONTAINED, like every playbook (plan §6.4).

## Decision

### PB-04: ECS task (D12, D19)

- **Containment means** the compromised task's processes are dead **and** every sibling task is being replaced by a new PRIMARY deployment:
  - `StopTask`, then `UpdateService(forceNewDeployment)`;
  - `contained` requires desiredStatus STOPPED, every container STOPPED and task lastStatus DEPROVISIONING or STOPPED (the ENI may still be detaching; F21), plus the new deployment PRIMARY and the service still in scope. The Lambda polls every 2 s for about 45 s (timeout 55 s); the container `stopTimeout` is 2 s.
- **Ownership check before acting:** the guard reads the LIVE task (cluster, `group`, scope tag; finding-embedded tags are never trusted), and PB-04 requires the task's `startedBy` to be one of the owning service's `deployments[].id`. A forged `group` therefore cannot get a different service redeployed.
- **Evidence:** the task description and task definition are captured in memory **before** `StopTask` and written as SHA-256-checksummed evidence by the router step `PB04Evidence`, **after** CONTAINED (outside MTTC), the PB-03 pattern.
- **Routing (D19):** ECS Runtime findings reach the router only at `>= min_severity` (7). There is no `always_route` entry for `*:Runtime/*`: auto-stopping production tasks on Medium findings is too aggressive.
- **Reachable only with** `guardduty_runtime_monitoring = true` (paid, off by default), a container image, and `soar_scope_app_service = true` (the opt-in scope tag on the ECS service, propagated to its tasks).

### PB-05: WAF IP block (D13, D14, D15)

- **Trigger (D13).** The only path into the router is a **dedicated EventBridge bus**, `<name>-soar-edge`, whose rule matches only `source = cloudshield.edge` with `resourceType = IPAddress`. Its resource policy allows `events:PutEvents` to the named publishers and has an explicit **Deny** for every principal whose `aws:PrincipalArn` is not on that list (F24).
  - The **harvester** Lambda is the built-in publisher: a CloudWatch alarm on the rate rule's `BlockedRequests` changes state to ALARM, EventBridge runs the harvester, and it calls `GetRateBasedStatementManagedKeys` and puts **one event per IP** (at most 50, never setting `Time`) on the bus. It does no filtering: the guard vets each address.
  - Phase E's docs-api decoy route becomes a publisher by adding its task-role ARN to `pb05_publisher_arns`; nothing else changes (`app/README.md`).
- **IP guard (D14),** in order; the first failure refuses:
  1. `source == EDGE_EVENT_SOURCE`, and the event `time` is within [now − 15 min, now + 60 s].
  2. Exactly one address (no `/`, no zone id); IPv4-mapped IPv6 is normalised to IPv4.
  3. Global unicast only: `is_global` and not multicast, unspecified or reserved (so private, loopback, link-local, shared 100.64/10 and documentation ranges are refused; F25).
  4. Not inside any CIDR of the never-block SSM parameter, which is read on **every** evaluation.
- **Block:** select the IPv4 or IPv6 set; `GetIPSet` → if the `/32` or `/128` is present, succeed idempotently; refuse at the cap (`BLOCK_IP_SET_MAX`, default 1,000; WAF allows 10,000); `UpdateIPSet` with the `LockToken`, asserting in code that the new list is a superset of the old one (add-only); on `WAFOptimisticLockException` re-read and retry, **at most 3 attempts**; read back before `contained: true`.
- **Lifetime (D15):** PB-05 records `blockExpiresAt` (default now + 24 h) on the row. **Nothing removes a block automatically.** `soar/tools/list_expired_blocks.py` (read-only, `make expired-blocks`) lists overdue blocks with the manual removal command (`docs/runbooks/pb04-pb05-recovery.md`). The IP sets use `ignore_changes = [addresses]`, so `terraform apply` never lifts a block either.

### Sims D and E (D20)

Replay-local fixtures only: no `--target aws` and no `live-aws`. The runner also refuses (exit 3) unless the SSM dry-run switch reads `true`, so against a real account they can only ever produce `WOULD_CONTAIN_DRY_RUN`.

### Enhancement decisions recorded here (D16, D17)

- **Notifier secret (D16).** The ChatOps webhook URL is a credential. The operator creates it as an SSM SecureString under the SOAR key, out of band (`docs/runbooks/chatops-setup.md`); Terraform knows only the parameter **name**, so the URL is never in state, a plan or the repository. The notifier reads it with decryption, caches it for 5 minutes per container, posts only through `core/http.py` (https, exact-host allow-list, port 443, no userinfo, no redirects, no proxies, 3 s timeout, 8 KiB body cap) and logs the host only. It never raises into SNS.
- **LLM hook (D17).** Off by default; it runs only with `--ai-summary` **and** `CLOUDSHIELD_LLM_PROVIDER=anthropic` **and** `ANTHROPIC_API_KEY`. It sends a redacted projection (finding type, resource type, status, MTTC, step names) to `api.anthropic.com` only, through the same `core/http.py`, and degrades to "AI summary unavailable" on any error. It lives in `soar/tools/`, which the Lambda zip does not contain.

## Deviations from the plan, recorded at build time

- **PB-04 verifies the specific deployment.** The plan's `newDeploymentPrimary` check was "a PRIMARY deployment whose `createdAt` ≥ the action time". The build records the id of the deployment the redeploy produced (or the fresh PRIMARY found on a retry, which must not be the compromised task's own deployment) and requires **that id** to be PRIMARY. A concurrent unrelated deployment cannot satisfy the check.
- **Never-block list format and fail-closed rule.** The SSM parameter is a comma-separated list of CIDRs; every non-empty entry must contain an explicit prefix (`/32` for one host). The guard refuses **every** block when the parameter is unset, unreadable, empty, or contains **any** entry that is not a valid CIDR: one bad entry invalidates the whole list rather than being skipped. Terraform seeds it with the NAT EIP `/32` plus `pb05_never_block_cidrs`, and a precondition refuses to create PB-05 with an empty list.
- **The harvester strips only host prefixes.** WAF reports managed keys as CIDRs. The harvester strips `/32` from IPv4 keys and `/128` from IPv6 keys; any other prefix is passed through unchanged, so the guard (rule 2: no `/`) refuses it. The harvester itself still filters nothing.
- **Notifier gating.** The plan gates `notify.tf` on `chatops_webhook_param_name != ""`. The build also requires the playbook package, because the notifier ships in the same zip. With playbooks off, the raw-GuardDuty message branch is therefore defensive only (see `soar/README.md`).

## Abuse analysis: can PB-05 be made to block a legitimate IP?

| Path | Control |
|---|---|
| A same-account principal publishes a forged edge event to the edge bus | Explicit Deny unless `aws:PrincipalArn` is a named publisher (identity-policy Allows cannot override it). Residual: an account admin can rewrite the bus policy (ADR-0001). Verify on apply (plan §9 #11). |
| A forged `source = cloudshield.edge` / `resourceType = IPAddress` on the **default** bus | EventBridge rejects `aws.*` sources but not custom ones; however, no rule on the default bus targets the router with that pattern, and `Finding` resolves an IP target only for the edge source. The GuardDuty rule matches `source = aws.guardduty` only. |
| A replayed or pre-dated event | Freshness window [now − 15 min, now + 60 s] on the event `time`, which the harvester never sets (EventBridge stamps it). |
| A crafted address (CIDR, mapped, private, documentation, multicast, reserved) | Guard rules 2–3; the IPv4-mapped form is normalised first, so `::ffff:10.0.0.1` is refused as private. |
| Blocking our own egress or an operator | The never-block list, read on every call, fail-closed on empty or invalid. |
| A spoofed client IP at the edge | The rate key is the CloudFront viewer address, not `X-Forwarded-For` (ADR-0004 D4). An attacker can only get their own source address blocked. |
| Flooding the IP set | The cap (default 1,000) refuses further blocks; the hourly event id makes repeats router-level duplicates. |
| Losing or shrinking existing blocks | Add-only assertion before `UpdateIPSet`; `LockToken` with bounded retry; Terraform ignores the addresses. |

## Consequences

- **PB-04 does not eradicate.** `forceNewDeployment` re-runs the same task definition and image digest; if the image is compromised, so are the replacements. Eradication (a new, scanned image deployed by digest) and ECS Exec volatile capture are human steps (`docs/runbooks/pb04-pb05-recovery.md`), done **before** approving eradication.
- **PB-05 "contained" means the block list was updated and read back.** Propagation to every CloudFront edge is not observed [inferred: seconds to a minute]. No S3 evidence is written; the trigger and before/after counts are on the row's `actions`.
- **ECS IAM gaps (F22)** [inferred, verify on apply]: `DescribeTaskDefinition` has no resource-level permission (`*`); `UpdateService` cannot be narrowed to `forceNewDeployment` by IAM (the code only ever sends that, with no task-definition change, so no `iam:PassRole`). `StopTask` / `UpdateService` are conditioned on `ecs:cluster` and the scope tag; never granted: `RunTask`, `DeleteService`, `ExecuteCommand`, `PassRole`.
- **Known gap:** IPs that become rate-limited while the alarm is already in ALARM wait for the next transition, unless the optional `pb05_harvest_schedule` is set.

## Verify on the first apply (plan §9)

ECS condition-key support (StopTask / UpdateService succeed on an in-scope service, **fail** on an untagged one); Fargate stop timing under `stopTimeout = 2` against the 60 s MTTC; the GuardDuty agent ECR repository ARN; the bus Deny blocks an in-account admin role that is not listed; WAF alarm dimensions for CLOUDFRONT scope; IP-set propagation time; notifier delivery to the real webhook host.
