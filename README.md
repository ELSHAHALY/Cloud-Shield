# CloudShield

**Automated DevSecOps & Cloud Incident Response (SOAR) platform** — DEPI AWS Cloud Security capstone, Fall 2026.

A multi-tenant document API on AWS has two defensive loops around it:

- **Shift-left:** a GitHub Actions pipeline with six security gates.
- **Shift-right:** GuardDuty → EventBridge → Step Functions `cs-ir-router` → Lambda playbooks. These contain an incident automatically, typically in under 60 s, and capture forensic evidence afterwards. Eradication stays human-gated.

> **New here? Start with [docs/HANDOFF.md](docs/HANDOFF.md).**
>
> Region `us-east-1` · `PROJECT_NAME=cloudshield` · Single-account build ([ADR-0001](docs/adr/0001-single-account-first.md)) · Module map and feature flags ([ADR-0002](docs/adr/0002-module-map-and-scaffold-strategy.md))

---

## Team

| Role | Owner | Owns |
|---|---|---|
| **S1** Platform / Infra / CI-CD | [@ELSHAHALY](https://github.com/ELSHAHALY) | `infra/` (bootstrap, network, compute, edge), `.github/` |
| **S2** App / Identity / Data | [@YasseenAbdelghany](https://github.com/YasseenAbdelghany) | `app/`, `modules/data`, `modules/identity` |
| **S3** SecOps / SOAR / Forensics | [@ahklsfg](https://github.com/ahklsfg) | `soar/`, `detection/`, `attack-sim/`, `modules/soar`, `modules/log-archive` |

[CODEOWNERS](.github/CODEOWNERS) enforces this. Cross-domain, security-critical paths need two owners: the pipeline, the environment composition, the quarantine security group and the forensic worker.

---

## Repository layout

```
.github/
  workflows/ci.yml               6 security gates + terraform validate/test + plan via OIDC
  CODEOWNERS · dependabot.yml · pull_request_template.md
infra/terraform/
  bootstrap/                     run once: state bucket, GitHub OIDC + plan role, budget, guardrails
  modules/                       (each one = one trust boundary, Fig. 7.1)
    network/       TB2           VPC 10.20.0.0/16, 4 subnet tiers, 1 NAT, gateway endpoints,
                                 flow logs, NLB/app/worker/QUARANTINE security groups
    compute/       TB4 + TB2     ECR (immutable, scan-on-push), ECS cluster, roles
                                 [flag] internal NLB + Fargate service · [flag] EC2 report-worker
    data/          TB3           DynamoDB documents + append-only audit (PITR), documents bucket, KMS
    log-archive/   TB5           KMS-encrypted log archive (flow-log delivery wired)
    soar/          TB5           SNS, incidents table, evidence bucket, dry-run switch, GuardDuty rule
                                 [flag] guard + PB-01..05 Lambdas + Step Functions cs-ir-router,
                                 PB-05 edge bus + harvester, ChatOps notifier
    identity/      TB1           Cognito user pool (TOTP MFA, immutable tenant claim), SPA client, 4 groups
    edge/          TB1           [flag] CloudFront + SPA bucket, CloudFront and regional WAF,
                                 PB-05 IP sets, REST API + VPC Link + Cognito authorizer
    detection/     TB5           GuardDuty, CloudTrail, Config, Athena/Glue (+ waf_logs)
    */tests/                     offline `terraform test` suites (mocked AWS provider)
  environments/dev/              composes the modules — one banner per owner
app/            S2 — Express API + React SPA
soar/           S3 — safety guard + playbook code (handler contract in soar/README.md)
detection/      S3 — Athena hunt queries
attack-sim/     S3 — scenario A–C scripts
scripts/gate-selftest.sh         proves each CI gate trips on a seeded bad input
docs/adr/       architecture decision records
```

### Trust boundaries (from plan Figure 7.1)

| Boundary | Zone | Lives in |
|---|---|---|
| TB0 | Internet (untrusted): users, adversary | — |
| TB1 | AWS edge (semi-trusted): WAF + CloudFront / API Gateway, Cognito | `edge` (built, behind `enable_edge`), `identity` (built) · [ADR-0004](docs/adr/0004-edge-identity-waf.md) |
| TB2 | VPC private subnets (trusted compute): docs-api task, report-worker EC2 | `network`, `compute` |
| TB3 | AWS data plane (data at rest): DynamoDB, S3 docs | `data` |
| TB4 | Supply chain: npm registry, GitHub repo + Actions, ECR | `.github/`, `compute` (ECR) |
| TB5 | Security account (highest trust): SOAR + evidence | `soar`, `log-archive`, `detection` |

### Feature flags: what exists by default

Code-dependent resources are written in full but **off** until their artifact exists (ADR-0002 §2).

| Variable (`environments/dev`) | Default | Turning it on creates |
|---|---|---|
| `container_image` | `null` | Internal NLB, task definition, Fargate service (image **must** be `…@sha256:` digest-pinned) |
| `enable_report_worker` | `false` | EC2 forensic target carrying the SOAR scope tag |
| `soar_playbook_package` | `null` | Safety guard + PB-01/02/03 Lambdas and the `cs-ir-router` state machine. Until then GuardDuty findings go **straight to SNS email**. PB-04, PB-05 and the notifier also need it. |
| `soar_dry_run` | `true` | `false` = playbooks really act |
| `enable_edge` | `false` | CloudFront, the CloudFront and regional WAFs (≈ US$20/month), the SPA bucket and WAF logging; the REST API too when `container_image` is set; and **PB-05** (edge bus, harvester + sighting table, never-block list, auto-expiry sweeper) when the package is set. **Requires `aws_region = us-east-1`** ([ADR-0004](docs/adr/0004-edge-identity-waf.md)). |
| `soar_scope_app_service` | `false` | The SOAR scope tag on the docs-api ECS service and its tasks. **PB-04** exists only with this, a container image and `guardduty_runtime_monitoring = true` (paid) ([ADR-0005](docs/adr/0005-pb04-pb05-edge-and-ecs-containment.md)). |
| `chatops_webhook_param_name` | `""` | The ChatOps notifier, subscribed to the incidents topic. Name an SSM SecureString you created with the SOAR key ([runbook](docs/runbooks/chatops-setup.md)); the URL never enters Terraform. |
| `allow_worker_lab_scan` | `false` | LAB ONLY: worker egress to all VPC ports, for scenario A |

---

## Getting started

### 0. Tools

Install Terraform ≥ 1.10 (CI uses 1.16.5), AWS CLI v2, Docker, gitleaks, semgrep, trivy and checkov. Then:

```bash
pip install pre-commit && pre-commit install   # gitleaks + terraform fmt on every commit
```

### 1. Bootstrap the account (S1, once)

```bash
aws sts get-caller-identity          # confirm you are in the RIGHT account first

cd infra/terraform/bootstrap
cp terraform.tfvars.example terraform.tfvars   # set the team's emails
terraform init
terraform apply
terraform output                     # note: state_bucket, state_kms_key_arn, gha_plan_role_arn
```

`bootstrap/` keeps **local** state on purpose, because it creates the remote-state bucket itself. Back up its `terraform.tfstate` somewhere private. Never commit it; `.gitignore` already blocks it.

Confirm the AWS Budgets subscription emails, or the alerts never arrive.

### 2. Deploy the dev baseline

```bash
cd ../environments/dev
cp backend.hcl.example backend.hcl            # paste bucket + KMS ARN from step 1
cp terraform.tfvars.example terraform.tfvars  # add analyst emails
terraform init -backend-config=backend.hcl
terraform plan -out=tfplan
terraform apply tfplan
```

With every flag at its default, this creates the network, log archive, ECR repository, empty ECS cluster, data tables and bucket, and the SOAR baseline. **No** service, EC2 instance, Lambda or state machine is created.

Steady-state cost is about **US$33/month for the NAT gateway plus about US$4/month for 4 KMS keys**, with small log and S3 charges on top. Destroy the environment when you're not working:

```bash
terraform destroy
```

Leave `bootstrap/` up: it costs cents.

**Phase D costs** (lab, us-east-1, plan §8):

| Item | Approximate cost | Default |
|---|---|---|
| WAF: 2 web ACLs ($5 each) + 10 rules ($1 each, incl. the `/api/*` PB-05 rate rule) + $0.60 per million requests; IP sets have no listed charge [inferred] | **≈ $20/month** with no traffic | off (`enable_edge`) |
| CloudFront / REST API / WAF logs / edge KMS key | free tier / $3.50 per million calls / cents / $1 per month | with `enable_edge` |
| CloudWatch alarm (PB-05 harvester) | $0.10/month | with PB-05 |
| Dedicated edge bus; PB-04, PB-05, harvester, sweeper and notifier Lambdas; the on-demand sighting table | free tier at lab volume | flags |
| GuardDuty Runtime Monitoring (PB-04 prerequisite) | per vCPU-hour after the trial | **off** |
| Cognito Essentials (TOTP) | free tier for lab MAU | **on** |
| LLM summary in the IR report | provider-billed, per run, opt-in only | off |

**GuardDuty must be enabled** for the SOAR rule to receive anything. Until the `detection` module exists, run:

```bash
aws guardduty create-detector --enable
```

### 3. Wire up GitHub (repo admin)

1. **Collaborators:** invite `@YasseenAbdelghany` and `@ahklsfg` with **Write** access. Without it, CODEOWNERS ignores their lines.
2. **Settings → Secrets and variables → Actions → Variables.** None of these are secrets, because OIDC removes the need for any.

| Variable | Value |
|---|---|
| `AWS_PLAN_ROLE_ARN` | `gha_plan_role_arn` output |
| `TF_STATE_BUCKET` | `state_bucket` output |
| `TF_STATE_KMS_KEY_ARN` | `state_kms_key_arn` output |
| `AWS_REGION` | `us-east-1` |
| `ENFORCE_GATES` | leave **unset** at first, then set `true` |
| `STAGING_URL` | set once the app is deployed; this enables the DAST gate |

3. **Settings → Branches → add a rule for `main`:**
   - Require a PR with **2 approvals** and **Code Owner review**. CODEOWNERS lines with several owners need only *one* of them; the second approval is what makes review two-person.
   - Require these status checks: `gate: secrets (gitleaks)`, `gate: sast (semgrep)`, `gate: sca (trivy fs)`, `gate: iac (terraform + checkov)`, `gate: image (trivy image + sbom)`.
   - Block force pushes and deletions. Include administrators.

### Fail-open → enforced

Gates start **fail-open**: findings show as warnings and in the job summary but don't block a merge. Set `ENFORCE_GATES=true` **no later than the end of Sprint 1**; from then on, any finding fails the job (FR-5).

These always hard-fail regardless: `terraform fmt`, `terraform validate` (every root **and** module) and `terraform test`.

---

## Testing

| What | Command | Where |
|---|---|---|
| Format | `make fmt` / `terraform fmt -check -recursive infra/terraform` | CI `iac` job |
| Validate every root + module | `make validate` | CI `iac` job |
| Module unit tests (mocked AWS, no creds) | `make test` | CI `iac` job |
| IaC policy | `checkov -d infra/terraform --framework terraform` | CI `iac` job |
| **Gates actually trip** | `scripts/gate-selftest.sh all` | local, before enforcing |

The module tests check the safety defaults:

- No Lambda, state machine or service exists by default.
- Dry-run is on.
- GuardDuty findings go to SNS only until the router exists.
- The router records the MTTC start (`$.time`) first and puts every playbook behind the safety guard.
- Images must be digest-pinned, and containers cannot run as root.
- The worker requires IMDSv2 and carries the scope tag.

`gate-selftest.sh` seeds:

| Gate | Seed |
|---|---|
| secrets | A runtime-generated fake GitHub PAT |
| sast | Express SQL built by string concatenation |
| sca | lodash 4.17.4 (CVE-2019-10744) |
| iac | SSH open to 0.0.0.0/0 |
| image | `node:14` |
| dast | A server with no security headers |

**Note:** ZAP baseline is passive and does not find SQLi. Semgrep is the gate for seeded SQLi (KPI §2.4).

---

## MTTC (how the < 60 s KPI is measured)

MTTC = `containedAt − eventTime` on the incident row (`soar` incidents table):

- `eventTime` is the EventBridge event `time`, so it measures SOAR latency and excludes GuardDuty's detection and delivery delay. GuardDuty's own `findingCreatedAt` is stored alongside it for audit.
- `containedAt` is the moment the state machine enters `MarkContained`. The EBS snapshot and evidence manifest run **after** that, so they never count against MTTC.
- Dry-run executions end as `WOULD_CONTAIN_DRY_RUN` and are excluded.

Details are in ADR-0002 §3.

---

## Design notes and gaps found while implementing

| # | Finding | Status |
|---|---|---|
| 1 | Terraform state location was not specified in the plan. | Handled: S3 + KMS with S3-native locking. |
| 2 | A literal "deny-all" NACL on the forensics subnet would also lock out the analyst. | Handled: the NACL allows intra-subnet traffic only. **Decide:** SSM endpoints inside that subnet, or offline analysis. |
| 3 | Hive-partitioned flow logs break the bucket-policy pattern from the AWS docs, so every log would be silently dropped. | Handled in `log-archive`. |
| 4 | Open-source Checkov has no severity data, so "fail on HIGH" isn't possible. | Fails on any failed check. Every skip has an inline reason. |
| 5 | Interface endpoints would cost about US$100/month. | Off by default. |
| 6 | Account-level S3 Block Public Access would stop scenario C from ever firing. | Deliberately not set. Every bucket blocks public access itself. |
| 7 | One account has weaker isolation than the designed Security account. | Accepted (ADR-0001). |
| 8 | The plan role uses `ReadOnlyAccess`. | Accepted for now. Replace it in Sprint 3. |
| 9 | There is no apply role yet. | Deliberate. Add one behind a GitHub Environment with reviewers. |
| 10 | **The PB-01 security-group swap does not cut connections that are already open** (security groups are stateful). | Open: an S3 code item (see `soar/README.md`). |
| 11 | **Tenant isolation is enforced in the API, not by IAM.** | Accepted. Stretch goal: STS session tags with `dynamodb:LeadingKeys` (ADR-0002 §5). |
| 12 | **PB-03 is bounded by bucket-name prefix, not tag**, because S3 bucket actions don't reliably support tag conditions. | Accepted. The scenario C bucket must be named `cloudshield-dev-*`. |
| 13 | **Synthetic GuardDuty sample findings conflict with the safety guard.** | Resolved: they pass only in dry-run. Real MTTC comes from scenarios A–C. |
| 14 | **The ZAP gate could never fail** (it ran with `-I` and had no FAIL rules). | Fixed: security-header rules are now FAIL. |
| 15 | **The audit table is insert-only by convention only**, because IAM can't force `attribute_not_exists` on PutItem. | Mitigated: no Update or Delete permission, the app's conditional write, the table stream as tamper evidence, and PITR. |
| 16 | **No compensating control yet for the missing S3 access logs** on the documents and evidence buckets. CloudTrail S3 data events arrive with `detection`. | Open: an S3 item, Sprint 2. |
| 17 | **Account Lambda quota.** New accounts (limit 10) reject reserved concurrency. | Default is unreserved; set 5 once `get-account-settings` shows ≥ 120. |

### Independent audit (8 Oct 2026)

An independent review agent audited commit `ea39d48` and returned **PASS WITH FIXES**: 10 major and 10 minor findings. Fixed in the next commit:

- **The router now fails closed:**
  - The safety guard proceeds only on a boolean `allowed == true`.
  - Real action happens only on a boolean `dry_run == false`.
  - CONTAINED is recorded only when the playbook returns `contained: true`.
- **PB-01 is reachable in scenario A.** `InstanceCredentialExfiltration*` routes to PB-01, and the scenario A and C finding types bypass `min_severity`.
- **SOAR can't escalate IAM.** `iam:Put*Policy` is allowed only on principals carrying `soar-target-boundary`.
- **Re-runs work.** A finding that FAILED or ran in dry-run can run again when GuardDuty re-delivers it.
- **Lambda trust policy:** removed an `aws:SourceAccount` condition that Lambda does not populate.
- **KMS:** added the Step Functions log-delivery grant to the key policy.
- **Documents bucket** now denies the SSE-S3 header.
- **Gate self-test** now requires the seeded finding to appear in the tool's output.
- **Corrected claims:** the CODEOWNERS any-one-owner semantics, and the audit table being insert-only by convention.

---

## Next steps

- [ ] **G1:** written ministry waiver for the 3-person team (risk R1, rated H×H).
- [ ] **S1:** apply `bootstrap/` and `environments/dev`, invite collaborators, set variables and branch protection, run `scripts/gate-selftest.sh`, then set `ENFORCE_GATES=true`.
- [x] **S1:** `edge` module: REST API Gateway + VPC Link → `module.compute.nlb_arn`, WAF ×2, CloudFront. ECR push role (OIDC, `main` only, push by digest). Phase D; verify-on-apply items in ADR-0004.
- [ ] **S2:** `app/openapi.yaml`, then `app/docs-api/` with `Dockerfile` and `/healthz` (token contract in `app/README.md`). The `identity` module (Cognito) is built (Phase D).
- [ ] **S3:** `soar/safety_guard` with pytest **first**, then PB-01, then build the zip and set `soar_playbook_package` with `soar_dry_run=true`. Run scenario A, then flip dry-run off.
- [ ] **S3:** `detection` module: GuardDuty detector, CloudTrail with S3 data events, Glue tables, an Athena workgroup with a scan cap, and Config rules.
