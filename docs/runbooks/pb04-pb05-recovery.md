# Runbook: after PB-04 or PB-05 (eradication and recovery)

- **Owner:** S3 (@ahklsfg), with S1 (@ELSHAHALY) for images and the edge · **Relates to:** ADR-0005, plan §6.4
- **Rule:** automation stops at CONTAINED. Everything below is a human decision, made by an analyst, in this order.

Start from the incident report; it carries the ATT&CK mapping and these checklists:

```bash
make ir-report INCIDENT=<incident-id>            # FMT=json for machine-readable output
```

---

## Part A: PB-04 (compromised ECS task, scenario D)

What PB-04 did: proved the task belongs to the service (`ListTasks` by service name), stopped the compromised task (its processes are dead), forced a new deployment of the owning service, and (after CONTAINED) stored the pre-stop task description and task definition as SHA-256-checked evidence at `incidents/<id>/pb04-ecs-task-<ts>.json`.

What it did **not** do: change the image. `forceNewDeployment` re-runs the **same task definition and image digest** (D12). If the image is the source, the replacements carry the same implant.

### A1. Preserve evidence (before any eradication)

1. Check the chain of custody: the report's evidence table must say "intact" (exit code 0, not 2).
2. Read the prestate: image digests, task definition ARN, ENI and private IP, `startedAt`, `startedBy`.
3. Pull the container's logs for the task's lifetime from CloudWatch (log group `/<name>/compute/docs-api`) and the VPC flow logs for its private IP (hunt query 02 shows the pattern).
4. **Volatile capture with ECS Exec.** The compromised task's memory is gone (stopping it was the containment). Capture from a **replacement** task running the same digest, to find out whether the image itself is compromised. Use read-only commands; do not install tools in the container:

   ```bash
   CLUSTER=$(terraform -chdir=infra/terraform/environments/dev output -raw ecs_cluster_name)
   TASK=$(aws ecs list-tasks --cluster "$CLUSTER" --service-name <service> --query 'taskArns[0]' --output text)
   aws ecs execute-command --cluster "$CLUSTER" --task "$TASK" --container <container> \
     --interactive --command "/bin/sh -c 'ps -ef; ls -la /tmp /var/tmp; cat /proc/net/tcp'"
   ```

   ECS Exec sessions are themselves logged to `/<name>/compute/ecs-exec` (KMS-encrypted). Save the transcript next to the incident (the evidence bucket, `incidents/<id>/manual-exec-<ts>.txt`) and record its SHA-256 in the case notes.

### A2. Eradicate

1. Decide the source: a vulnerable dependency or code path (fix in the app), a compromised base image or build (rebuild from a clean base), or runtime-only abuse with a clean image (fix the entry point).
2. Build a new image through the CI pipeline: it is scanned (Trivy gate), pushed by `${GITHUB_SHA}` and deployed **by digest** (ADR-0004 D7). Never re-tag or overwrite (ECR is immutable).
3. Review the task definition's environment and the task role for anything the attacker could have read; rotate whatever was exposed.
4. Deploy the new digest (`container_image = "<repo>@sha256:<new>"`, local S1 apply).

### A3. Recover

1. Confirm the new deployment is PRIMARY, healthy, and running the new digest.
2. Watch GuardDuty Runtime Monitoring for the same finding type on the new tasks for at least a day.
3. Record the outcome on the incident (case notes) and close it.

---

## Part B: PB-05 (blocked client IP, scenario E)

What PB-05 did: confirmed with WAF that the address was being rate-limited on `/api/*` (`SoarApiRateLimit`) for at least two consecutive harvests and at block time, recorded `blockedCidr`, `ipSetArn`, `blockExpiresAt` and `blockState` on the row **before** changing anything, appended the address (`/32` or `/128`) to the CloudFront WAF block list (`<name>-soar-blocked-ips-v4` or `-v6`), and read it back (`blockState = active`).

What happens next without anyone: the **sweeper** (`<name>-soar-pb05-sweeper`, every 15 min) lifts the block once `blockExpiresAt` has passed (default 24 h) and no newer unexpired row covers the same address, then records `blockLiftedAt` and an `unblock` action on the row (D15, audit A2). `terraform apply` never touches the addresses.

### B1. Cross-check the blocks

```bash
make expired-blocks                  # FMT=json for JSON; read-only, never calls UpdateIPSet
# Also look for orphans in both sets:
#   cd soar && python -m tools.list_expired_blocks --table <name>-soar-incidents \
#     --ip-set-arn <v4 ARN> --ip-set-arn <v6 ARN>
```

It groups rows by address (the latest expiry wins) and reports:

- **expired**: past expiry. `STILL BLOCKED` here means the sweeper has not lifted it yet (it runs every 15 min) or failed: check the sweeper's log. The exact manual removal commands are printed.
- **lost**: not yet expired, but the address is missing from the live IP set: removed by hand, the pending block never applied, or the IP sets were destroyed and recreated (for example `enable_edge = false`; ADR-0005 A11). Re-block by hand if it still matters.
- **orphans**: entries in the IP set that no incident row explains (added outside PB-05). The sweeper never removes them; decide here.

### B2. Decide (before expiry)

Keep the block until expiry if the source is still hostile (WAF logs via hunt query 04 show continued attempts). Lift it early if the address is dynamic, **shared** (a NAT, a carrier-grade gateway, a corporate proxy: one client's abuse blocks everyone behind it), or a false positive; add known-shared addresses to the never-block list. To keep a hostile source blocked **longer** than the TTL, block it in a separate, human-owned rule: the sweeper lifts every PB-05 block on expiry.

### B3. Remove one block by hand (early lift, or an orphan)

`UpdateIPSet` **replaces the whole list**, so always start from a fresh read and remove exactly one entry:

```bash
ARN=<ipSetArn from the row>
NAME=$(echo "$ARN" | awk -F/ '{print $(NF-1)}'); ID=${ARN##*/}
aws wafv2 get-ip-set --scope CLOUDFRONT --region us-east-1 --name "$NAME" --id "$ID" > ipset.json
# Build the new list: every address in ipset.json EXCEPT <blockedCidr>.
aws wafv2 update-ip-set --scope CLOUDFRONT --region us-east-1 --name "$NAME" --id "$ID" \
  --lock-token "$(jq -r .LockToken ipset.json)" \
  --addresses $(jq -r --arg c "<blockedCidr>" '.IPSet.Addresses - [$c] | join(" ")' ipset.json)
aws wafv2 get-ip-set --scope CLOUDFRONT --region us-east-1 --name "$NAME" --id "$ID" \
  --query "IPSet.Addresses" | grep -c "<blockedCidr>"        # expect 0
```

On `WAFOptimisticLockException`, someone (PB-05, the sweeper or another analyst) changed the set in between: start again from `get-ip-set`. If the entry is the only one, use `--addresses '[]'` [inferred: the CLI's JSON form for an empty list; check the read-back].

Record the removal (who, when, why) on the incident. The sweeper later finds the address already gone and changes nothing.

### B3a. Wrong block on a protected address

If a never-block address was blocked anyway, treat it as a SOAR defect: remove the block (B3), set `soar_dry_run = true`, and investigate the guard decision on the row before turning automation back on.
