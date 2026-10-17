# Runbook: edge and WAF demo (QA row, scenario E)

- **Owner:** S1 (@ELSHAHALY) with S3 (@ahklsfg) · **Relates to:** ADR-0004, ADR-0005, `attack-sim/README.md`, hunt query 04

## Rule 1 (risk R4, AWS abuse): our own distribution only

Every request in this runbook goes to **our own** CloudFront domain (`terraform output cloudfront_domain_name`) and nowhere else. Never point these commands at a third-party host, another team's distribution, or an `execute-api` endpoint you do not own. Keep the volume to what is written here: the rate test sends a few hundred requests, once.

## Before you start

1. `enable_edge = true` and `aws_region = "us-east-1"` are applied (≈ US$20/month for the WAFs; destroy afterwards). For the `/api` checks, `container_image` is set too.
2. **Keep `soar_dry_run = true`** for the demo. With dry-run off, PB-05 would really block the address you test from, for the whole site, until the sweeper lifts it after `pb05_block_ttl_hours` (default 24 h; D15) or someone removes it by hand.
3. Decide which address you test from, and check it against the never-block list: if it is on the list (for example the NAT EIP or an operator CIDR), the guard refuses it and the incident ends `BLOCKED_BY_GUARD`, which is also a valid demo of rule 4.

   ```bash
   aws ssm get-parameter --name /<name>/soar/pb05_never_block --query Parameter.Value
   ```

```bash
cd infra/terraform/environments/dev
EDGE=https://$(terraform output -raw cloudfront_domain_name)
```

## 1. Headers and the SPA (ZAP rules 10020, 10021, 10035, 10038)

```bash
curl -sI "$EDGE/" | grep -iE 'strict-transport|x-content-type|x-frame|content-security'
curl -s -o /dev/null -w '%{http_code}\n' "$EDGE/documents/123"     # 200: SPA deep link (D10)
```

## 2. The API needs a token, and errors are not rewritten (needs `container_image`)

```bash
curl -s -o /dev/null -w '%{http_code}\n' "$EDGE/api/healthz"        # 200
curl -s -o /dev/null -w '%{http_code}\n' "$EDGE/api/documents"      # 401, not a rewritten 200
```

## 3. Managed rules block a scanner-style payload

```bash
curl -s -o /dev/null -w '%{http_code}\n' "$EDGE/api/documents?id=1%27%20OR%20%271%27%3D%271"   # 403 (SQLi set, regional ACL)
```

## 4. Rate limit → harvester → PB-05 (dry-run)

Two rate rules (ADR-0004 D4). `RateLimitPerIp` answers **429** above `waf_rate_limit` requests per 5 minutes per IP on any path (default 300) and never feeds PB-05. Only `SoarApiRateLimit`, scoped to paths starting `/api/` (`waf_api_rate_limit`, default 200), feeds PB-05, and only for an address that is still over it at **two consecutive harvests** (the harvester runs every 5 minutes and on the alarm). WAF evaluates the rate every few tens of seconds, so the first 429s can lag. `/api/healthz` works for this even without the REST API: the CloudFront ACL counts the request either way.

```bash
burst() { for i in $(seq 1 250); do curl -s -o /dev/null -w '%{http_code}\n' "$EDGE/api/healthz"; done | sort | uniq -c; }
burst; sleep 240; burst      # stay over the limit for ~10 minutes
```

Then, within about ten minutes:

1. CloudWatch alarm `<name>-soar-pb05-rate-limited` goes to ALARM; EventBridge runs `<name>-soar-pb05-harvester`. Its first log shows `{"harvest": {"keys": 1, "observed": 1, "persistent": 0, "published": 0, ...}}`; a later scheduled run shows `"persistent": 1, "published": 1`.
2. The router runs on the edge bus event. In the incidents table the row (`edge-waf-rate-<ip>-<yyyyMMddHH>`) ends:
   - `WOULD_CONTAIN_DRY_RUN`, with the plan starting "re-read the never-block list …" and "corroborate: <ip>/32 must be a managed key of the WAF rate rule right now", or
   - `BLOCKED_BY_GUARD` with the guard's reason (never-block list, non-global address, stale event, edge type not allowed).
3. The IR report shows the scenario E triage:

   ```bash
   make ir-report INCIDENT=edge-waf-rate-<ip>-<yyyyMMddHH>
   ```

## 5. Hunt it (query 04)

In Athena, use the workgroup from `terraform output -raw athena_workgroup` (`<name>-cs-forensics`) and the database from `terraform output -raw glue_database`:

```sql
PREPARE h04 FROM <contents of detection/athena-queries/04_waf_blocked_requests_by_client.sql>;
EXECUTE h04 USING '2026/10/16/09/00', '2026/10/16/11/00';
```

Expect `SoarApiRateLimit` rows for your address (and `RateLimitPerIp` rows if you also went over the site-wide limit), the managed-rule row for step 3, and `soar_block_hits = 0` (dry-run: nothing was blocked).

## Afterwards

- If anything was really blocked, the sweeper lifts it at `blockExpiresAt`; to lift it now, remove it by hand (`docs/runbooks/pb04-pb05-recovery.md`, part B).
- The alarm returns to OK on its own. Destroy the edge if you are done: `enable_edge = false`, apply.
