# Runbook: after PB-04 or PB-05 (eradication and recovery)

- **Owner:** S3 (@ahklsfg), with S1 (@ELSHAHALY) for images and the edge · **Relates to:** ADR-0005, plan §6.4
- **Rule:** automation stops at CONTAINED. Everything below is a human decision, made by an analyst, in this order.

Start from the incident report; it carries the ATT&CK mapping and these checklists:

```bash
make ir-report INCIDENT=<incident-id>            # FMT=json for machine-readable output
```

---

## Part A: PB-04 (compromised ECS task, scenario D)

What PB-04 did: stopped the compromised task (its processes are dead), forced a new deployment of the owning service, and (after CONTAINED) stored the pre-stop task description and task definition as SHA-256-checked evidence at `incidents/<id>/pb04-ecs-task-<ts>.json`.

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

What PB-05 did: appended the address (`/32` or `/128`) to the CloudFront WAF block list (`<name>-soar-blocked-ips-v4` or `-v6`), read it back, and recorded `blockedCidr`, `ipSetArn` and `blockExpiresAt` on the row. Nothing removes a block automatically (D15), and `terraform apply` never touches the addresses.

### B1. Review blocks that are past their expiry

```bash
make expired-blocks                  # FMT=json for JSON; read-only, never calls UpdateIPSet
```

It lists incident id, CIDR, age, and the exact removal commands for each overdue block that is still in the live IP set.

### B2. Decide

Keep the block if the source is still hostile (WAF logs via hunt query 04 show continued attempts, or threat intel says so). Remove it if the address was dynamic, shared (a NAT or carrier-grade gateway), or a false positive.

### B3. Remove one block (add-only automation, manual removal)

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

On `WAFOptimisticLockException`, someone (or PB-05) changed the set in between: start again from `get-ip-set`. If the entry is the only one, use `--addresses '[]'` [inferred: the CLI's JSON form for an empty list; check the read-back].

Record the removal (who, when, why) on the incident.

### B3a. Wrong block on a protected address

If a never-block address was blocked anyway, treat it as a SOAR defect: remove the block (B3), set `soar_dry_run = true`, and investigate the guard decision on the row before turning automation back on.
