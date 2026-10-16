# ADR-0005: PB-04 (ECS task containment) and PB-05 (WAF IP block)

- **Status:** Accepted (16 Oct 2026); amended the same day after the Phase D audit (A1–A11, see "Audit amendments") and by Phase E (`DecoyRouteHit` is notify-only, see "Phase E amendment")
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
- **Ownership check before acting:** the guard reads the LIVE task (cluster, `group`, scope tag; finding-embedded tags are never trusted), and PB-04 asks ECS itself: `ListTasks(cluster, serviceName = <service>)` must contain the task ARN (desired status RUNNING, else STOPPED, which ECS keeps listing for about an hour). That **proves** membership (audit A4); `group` and `startedBy` are task fields a forged finding or a hand-run task can carry, so they are only hints. A forged `group` therefore cannot get a different service redeployed. IAM: `ecs:ListTasks` with `Resource "*"` narrowed by the `ecs:cluster` condition; the Service Authorization Reference lists `ListTasks` against the `container-instance` resource type with `ecs:cluster` [inferred, not verifiable offline; verify on apply], and Fargate tasks have no container instance.
- **Evidence:** the task description and task definition are captured in memory **before** `StopTask` and written as SHA-256-checksummed evidence by the router step `PB04Evidence`, **after** CONTAINED (outside MTTC), the PB-03 pattern.
- **Routing (D19):** ECS Runtime findings reach the router only at `>= min_severity` (7). There is no `always_route` entry for `*:Runtime/*`: auto-stopping production tasks on Medium findings is too aggressive.
- **Reachable only with** `guardduty_runtime_monitoring = true` (paid, off by default), a container image, and `soar_scope_app_service = true` (the opt-in scope tag on the ECS service, propagated to its tasks).

### PB-05: WAF IP block (D13, D14, D15)

- **Trigger (D13).** The **automatic** path into the router is a **dedicated EventBridge bus**, `<name>-soar-edge`, whose rule matches only `source = cloudshield.edge` with `detail.type` prefix `CloudShield:IPAddress/` and `resourceType = IPAddress` (audit A5). Its resource policy allows `events:PutEvents` to the named publishers and has an explicit **Deny** for every principal whose `aws:PrincipalArn` is not on that list (F24). It is **not** the only path: a principal allowed `states:StartExecution` on `cs-ir-router` (or `lambda:InvokeFunction` on PB-05, with a forged guard decision) can hand PB-05 any "fresh edge event". PB-05 therefore trusts nothing the caller wrote (below, audit A1).
  - **Two WAF rate rules (audit A2).** `RateLimitPerIp` stays site-wide and only answers 429; it is **never** harvested. `SoarApiRateLimit` (ADR-0004 D4) is scoped down to URI paths starting `/api/` with its own limit (`waf_api_rate_limit`, default 200 per 5 min); it is the only PB-05 feed: the harvester, the alarm and PB-05's corroboration all use it.
  - The **harvester** Lambda is the built-in publisher. It runs on the alarm (`SoarApiRateLimit` `BlockedRequests` ≥ 1 → ALARM) **and** on a schedule that is on by default with PB-05 (`pb05_harvest_schedule = "rate(5 minutes)"`). It calls `GetRateBasedStatementManagedKeys` and records each key in a small DynamoDB table (`<name>-soar-pb05-harvest-state`: on-demand, SOAR KMS key, TTL, harvester-only IAM). **An address is published only once it has been a managed key in ≥ 2 consecutive harvests** (sightings < 60 s apart are one harvest; > 660 s apart restart the count; conditional writes so concurrent harvests cannot both count). It then puts **one event per persistent address** (at most 50, never setting `Time`) on the bus. Address validity is still the guard's job.
  - Phase E's docs-api decoy route becomes a publisher by adding its task-role ARN to `pb05_publisher_arns` **and** adding its finding type to the edge allow-list together with a corroboration check PB-05 can make itself (`app/README.md`); an allow-listed type without corroboration is refused.
- **IP guard (D14),** in order; the first failure refuses:
  1. `source == EDGE_EVENT_SOURCE`; `detail.type` on the explicit edge allow-list (today only `CloudShield:IPAddress/WafRateLimitExceeded`, audit A1); the event `time` is within [now − 15 min, now + 60 s].
  2. Exactly one address (no `/`, no zone id); IPv4-mapped IPv6 is normalised to IPv4.
  3. Global unicast only: `is_global` and not multicast, unspecified or reserved (so private, loopback, link-local, shared 100.64/10 and documentation ranges are refused; F25).
  4. Not inside any CIDR of the never-block SSM parameter, which is read on **every** evaluation.
- **PB-05 re-checks, from sources the caller cannot write (audit A1),** before any IP-set call: the source and the type allow-list again; the **full** address rules (rule 3, not just `is_global`); the never-block list **re-read** from SSM (unreadable, empty or invalid → refuse); and **corroboration with WAF itself**: for `WafRateLimitExceeded`, `GetRateBasedStatementManagedKeys` on the CloudFront ACL and `SoarApiRateLimit` must list the address **right now**, otherwise PB-05 refuses. New IAM, nothing else: `wafv2:GetRateBasedStatementManagedKeys` on the CloudFront ACL ARN and `ssm:GetParameter` on the never-block parameter.
- **Block:** select the IPv4 or IPv6 set; `GetIPSet` → if the `/32` or `/128` is present, succeed idempotently; refuse at the cap (`BLOCK_IP_SET_MAX`, default 1,000; WAF allows 10,000); write `blockedCidr`, `ipSetArn`, `blockExpiresAt` and `blockState = pending` on the row **before** `UpdateIPSet` (audit A3), so a later failure can never leave an untracked block; `UpdateIPSet` with the `LockToken`, asserting in code that the new list is a superset of the old one (add-only); on `WAFOptimisticLockException` re-read and retry, **at most 3 attempts**; read back before `contained: true` and `blockState = active`.
- **Lifetime (D15, amended by audit A2): removal is automatic on expiry.** PB-05 records `blockExpiresAt` (default now + 24 h). The **sweeper** Lambda (`<name>-soar-pb05-sweeper`, `pb05_sweep_schedule`, default every 15 min) lifts a block only when it is **row-tracked, expired, and not covered by a newer unexpired row for the same address**; an unparseable expiry keeps the block. Per IP set: `GetIPSet` → remove exactly those entries → `UpdateIPSet` with the `LockToken` (bounded retry; the code asserts the new list is a **subset** of the old one and drops only expired tracked entries: remove-only) → read back → only then `blockLiftedAt`, `blockState = lifted` and an `unblock` action on the rows. It **never** removes an entry no row explains (an orphan): it reports it. Its IAM is exactly `Get/UpdateIPSet` on the two IP sets, `Scan/UpdateItem` on the incidents table, `kms:Decrypt` on the SOAR key and its own logs. It does not read the dry-run switch: it only undoes blocks PB-05 made while live, and dry-run never creates one. **Automation still stops at containment**: lifting an expired block ends a containment whose time is up; it is not recovery. Recovery of the workload, and any decision to block for longer, stay human (`docs/runbooks/pb04-pb05-recovery.md`). `make expired-blocks` remains as the read-only cross-check (below). The IP sets use `ignore_changes = [addresses]`, so `terraform apply` never adds or lifts a block.

### Sims D and E (D20)

Replay-local fixtures only: no `--target aws` and no `live-aws`. The runner also refuses (exit 3) unless the SSM dry-run switch reads `true`, so against a real account they can only ever produce `WOULD_CONTAIN_DRY_RUN`. After that gate the guard **and** the playbook base get a dry-run reader that always returns `true` (audit A10), so flipping the SSM switch mid-run cannot make them act.

### Enhancement decisions recorded here (D16, D17)

- **Notifier secret (D16).** The ChatOps webhook URL is a credential. The operator creates it as an SSM SecureString under the SOAR key, out of band (`docs/runbooks/chatops-setup.md`); Terraform knows only the parameter **name**, so the URL is never in state, a plan or the repository. The notifier reads it with decryption, caches it for 5 minutes per container, posts only through `core/http.py` (https, exact-host allow-list, port 443, no userinfo, no redirects, no proxies, 3 s timeout, 8 KiB body cap) and logs the host only. It never raises into SNS.
- **LLM hook (D17).** Off by default; it runs only with `--ai-summary` **and** `CLOUDSHIELD_LLM_PROVIDER=anthropic` **and** `ANTHROPIC_API_KEY`. It sends a redacted projection (finding type, resource type, status, MTTC, step names) to `api.anthropic.com` only, through the same `core/http.py`, and degrades to "AI summary unavailable" on any error. It lives in `soar/tools/`, which the Lambda zip does not contain.

## Deviations from the plan, recorded at build time

- **PB-04 verifies the specific deployment.** The plan's `newDeploymentPrimary` check was "a PRIMARY deployment whose `createdAt` ≥ the action time". The build records the id of the deployment the redeploy produced (or the fresh PRIMARY found on a retry, which must not be the compromised task's own deployment) and requires **that id** to be PRIMARY. A concurrent unrelated deployment cannot satisfy the check.
- **Never-block list format and fail-closed rule.** The SSM parameter is a comma-separated list of CIDRs; every non-empty entry must contain an explicit prefix (`/32` for one host). The guard refuses **every** block when the parameter is unset, unreadable, empty, or contains **any** entry that is not a valid CIDR: one bad entry invalidates the whole list rather than being skipped. Terraform seeds it with the NAT EIP `/32` plus `pb05_never_block_cidrs`, and a precondition refuses to create PB-05 with an empty list.
- **The harvester strips only host prefixes.** WAF reports managed keys as CIDRs. The harvester strips `/32` from IPv4 keys and `/128` from IPv6 keys; any other prefix is passed through unchanged, so the guard (rule 2: no `/`) refuses it. Its only filter is persistence (≥ 2 consecutive harvests); address validity is the guard's job.
- **Notifier gating.** The plan gates `notify.tf` on `chatops_webhook_param_name != ""`. The build also requires the playbook package, because the notifier ships in the same zip. With playbooks off, the raw-GuardDuty message branch is therefore defensive only (see `soar/README.md`).

## Abuse analysis: can PB-05 be made to block a legitimate IP?

The edge bus is the automatic path, **not** the only one (audit A1). The controls that matter are the ones PB-05 applies itself at block time.

| Path | Control |
|---|---|
| A same-account principal publishes a forged edge event to the edge bus | Explicit Deny unless `aws:PrincipalArn` is a named publisher (identity-policy Allows cannot override it). Even a named publisher only gets an event to the guard and PB-05, which corroborate it (below). Residual: an account admin can rewrite the bus policy (ADR-0001). Verify on apply (plan §9 #11). |
| A principal with `states:StartExecution` on `cs-ir-router` hands it a forged "fresh edge event", or one with `lambda:InvokeFunction` on PB-05 invokes it with a forged `allowed` guard decision | **PB-05 does not trust the event.** It re-checks source, type allow-list and the full address rules, re-reads the never-block list, and refuses unless `GetRateBasedStatementManagedKeys` on the CloudFront ACL lists the address under `SoarApiRateLimit` **at block time**. Such a principal cannot block an arbitrary public IP. **Residual risk, stated honestly:** an address that WAF really is rate-limiting on `/api/*` at that moment (and that is not on the never-block list) can be blocked by such a principal without waiting for the two-harvest persistence; it is an address the harvester would publish anyway once it persists, and the block still expires after `BLOCK_TTL_HOURS`. Keep `StartExecution` / `InvokeFunction` on these resources to the SOAR roles and admins. |
| A forged `source = cloudshield.edge` / `resourceType = IPAddress` on the **default** bus | EventBridge rejects `aws.*` sources but not custom ones; however, no rule on the default bus targets the router with that pattern, and `Finding` resolves an IP target only for the edge source. The GuardDuty rule matches `source = aws.guardduty` only. |
| An edge event of an unknown type | The bus rule forwards only `CloudShield:IPAddress/*`; the guard and PB-05 accept only the explicit allow-list, and PB-05 has a corroboration check per allowed type (none = refuse). |
| A replayed or pre-dated event | Freshness window [now − 15 min, now + 60 s] on the event `time`, which the harvester never sets (EventBridge stamps it). A replay of a real event still fails corroboration once WAF stops rate-limiting the address. |
| A crafted address (CIDR, mapped, private, documentation, multicast, reserved) | Guard rules 2–3, and again in PB-05; the IPv4-mapped form is normalised first, so `::ffff:10.0.0.1` is refused as private. |
| Blocking our own egress or an operator | The never-block list, read on every guard call **and again by PB-05**, fail-closed on unreadable, empty or invalid. |
| A spoofed client IP at the edge | The rate key is the CloudFront viewer address, not `X-Forwarded-For` (ADR-0004 D4). An attacker can only get their own source address blocked. |
| A short burst becomes a long block | Only `/api/*` traffic feeds PB-05 (`SoarApiRateLimit`), an address must persist over ≥ 2 consecutive harvests, and every block expires (24 h default, lifted by the sweeper). |
| Collateral damage behind a shared egress IP | See "Shared egress" below. |
| Flooding the IP set | The cap (default 1,000) refuses further blocks; the hourly event id makes repeats router-level duplicates. |
| Losing or shrinking existing blocks | Add-only assertion before `UpdateIPSet`; `LockToken` with bounded retry; Terraform ignores the addresses. The sweeper is remove-only, removes only expired row-tracked entries, and never touches orphans. |

## Audit amendments (Phase D audit, 16 Oct)

- **A1** PB-05 corroborates with WAF, re-reads the never-block list and re-checks the full address rules; the guard allow-lists edge finding types. The abuse table above no longer claims the bus is the only path.
- **A2** Scope-down rule `SoarApiRateLimit` (the only PB-05 feed), ≥ 2-consecutive-harvest persistence with the schedule on by default, and the auto-expiry sweeper. D15 changed from "nothing removes a block automatically" to "removal is automatic on expiry".
- **A3** Pending block fields are written before `UpdateIPSet`; `list_expired_blocks` groups by address (latest expiry wins) and reports `expired`, `lost` and `orphans`.
- **A4** PB-04 ownership is proven with `ecs:ListTasks(serviceName)`.
- **A5** Every type-based router choice also requires its `resourceType`; the edge-bus rule is pinned to the `CloudShield:IPAddress/` type prefix; `sims/local_router._route` mirrors it.
- **A10** Dry-run-only sims D/E use an always-dry-run reader after the runner's gate.
- **A11** IP-set recreation drops blocks (below).

## Phase E amendment (16 Oct): `DecoyRouteHit` is notify-only

docs-api now publishes `CloudShield:IPAddress/DecoyRouteHit` on the edge bus (ADR-0006, plan D13–D15). A1 is **not** weakened:

- `core/finding.py` gains `EDGE_NOTIFY_ONLY_TYPES = {CloudShield:IPAddress/DecoyRouteHit}`; it is **not** in `EDGE_FINDING_TYPES`.
- The guard (`_ip`, after the edge-source check) returns `allowed: false` with the reason `notify-only edge finding (decoy route hit): analyst review`. The router records `BLOCKED_BY_GUARD` and runs `Notify` (SNS + ChatOps). The hourly id makes repeats router-level duplicates.
- PB-05 still refuses any type outside its allow-list, even when invoked directly with a forged `allowed` decision (`test_pb05.py`).
- The publisher is derived in `modules/soar` (`app_publishes_decoy`): the task role joins the bus Allow list and the Deny's exemption, and its `PutEvents` grant is conditioned on `events:source` and `events:detail-type`.

Corroborated blocking (a WAF rule on `/api/admin` that PB-05 can read) is a recorded follow-up; until then, blocking a decoy caller is an analyst decision (`docs/runbooks/decoy-route.md`).

## Consequences

- **Shared egress (audit A2).** A block is per address. Behind a NAT, a carrier-grade gateway, a corporate proxy or a VPN exit, one abusive client blocks **everyone** behind that address, at the CloudFront edge, for the whole site. Mitigations: only `/api/*` traffic feeds PB-05; the address must stay over `waf_api_rate_limit` for ≥ 2 consecutive harvests; blocks expire (default 24 h, lowerable to 1 h with `pb05_block_ttl_hours`) and the sweeper lifts them; known-shared addresses belong on the never-block list. A wrongly blocked shared address is lifted by hand (`docs/runbooks/pb04-pb05-recovery.md`, B3) without waiting for expiry.
- **Recreating the IP sets drops every block (audit A11).** The IP sets are Terraform resources: destroying them (`enable_edge = false`, a rename, or a replacement) and creating them again loses every address in them. The rows still say `blockState = active` with a future `blockExpiresAt`; `make expired-blocks` reports those addresses as **lost**. This is accepted for the lab: `prevent_destroy` would block lab teardown. Re-block by hand if a lost block still matters.

- **PB-04 does not eradicate.** `forceNewDeployment` re-runs the same task definition and image digest; if the image is compromised, so are the replacements. Eradication (a new, scanned image deployed by digest) and ECS Exec volatile capture are human steps (`docs/runbooks/pb04-pb05-recovery.md`), done **before** approving eradication.
- **PB-05 "contained" means the block list was updated and read back.** Propagation to every CloudFront edge is not observed [inferred: seconds to a minute]. No S3 evidence is written; the trigger and before/after counts are on the row's `actions`.
- **ECS IAM gaps (F22)** [inferred, verify on apply]: `DescribeTaskDefinition` has no resource-level permission (`*`); `UpdateService` cannot be narrowed to `forceNewDeployment` by IAM (the code only ever sends that, with no task-definition change, so no `iam:PassRole`). `StopTask` / `UpdateService` are conditioned on `ecs:cluster` and the scope tag; never granted: `RunTask`, `DeleteService`, `ExecuteCommand`, `PassRole`.
- **Harvest timing:** with the default 5-minute schedule, an address that crosses the `/api/*` limit is published after its second consecutive sighting, typically 5–10 minutes after it starts, and blocked within the 60 s MTTC of that event. With `pb05_harvest_schedule = null` only alarm transitions harvest, and few addresses ever persist (documented trade-off).

## Verify on the first apply (plan §9)

ECS condition-key support (StopTask / UpdateService succeed on an in-scope service, **fail** on an untagged one; `ListTasks` with `Resource "*"` + `ecs:cluster` succeeds for our cluster and fails for another); Fargate stop timing under `stopTimeout = 2` against the 60 s MTTC; the GuardDuty agent ECR repository ARN; the bus Deny blocks an in-account admin role that is not listed; WAF alarm dimensions for CLOUDFRONT scope (Rule = `SoarApiRateLimit`); `GetRateBasedStatementManagedKeys` on a scoped-down rule returns the `/api/*` offenders; `kms:Decrypt` alone suffices for the harvester's and the sweeper's DynamoDB reads and writes on the SOAR-key tables; the sweeper lifts an expired block end to end (set `pb05_block_ttl_hours = 1` in a dry-run-off lab window); IP-set propagation time; notifier delivery to the real webhook host.
