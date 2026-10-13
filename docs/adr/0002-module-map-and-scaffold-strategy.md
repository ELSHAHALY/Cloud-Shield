# ADR-0002 — Module map, feature-flagged scaffold, MTTC clock, NLB ingress

- **Status:** Accepted (8 Oct 2026)
- **Deciders:** @ELSHAHALY (S1), @YasseenAbdelghany (S2), @ahklsfg (S3)
- **Amends:** the module table in [ADR-0001](0001-single-account-first.md)

## 1. Module map

Each module sits inside exactly one trust boundary from plan Figure 7.1, so a future multi-account split moves whole modules and never splits one.

| Module | Trust boundary (Fig. 7.1) | Owner | Future account | Status |
|---|---|---|---|---|
| `network` | TB2: VPC private subnets | S1 | Workload | built |
| `compute`: ECR | TB4: supply chain | S1 | Workload | built |
| `compute`: ECS, NLB, report-worker | TB2 | S1 (worker: C S3) | Workload | built, flag-gated |
| `data` | TB3: data plane | S2 | Workload | built |
| `log-archive` | TB5: security | S3 | Security | built |
| `soar` | TB5: security | S3 | Security | built, playbooks flag-gated |
| `edge` (API Gateway REST + VPC Link, WAF ×2, CloudFront) | TB1: AWS edge | S1 | Workload | planned |
| `identity` (Cognito) | TB1 | S2 | Workload | planned |
| `detection` (GuardDuty, Security Hub, Config, CloudTrail, Glue/Athena) | TB5 | S3 | Security | planned |

ADR-0001's separate `ecr`, `ecs`, `logging` and `cognito` modules are folded into `compute`, `detection` and `identity`.

Incident and evidence data live in `soar`, not `data`. The security domain stays separate from tenant data (plan §8.4).

## 2. What "scaffold" means here

Only real resources get built: anything that works with no application or Lambda code. Code-dependent resources are written in full but stay switched off behind input flags until their artifact exists.

| Flag (dev variable) | When null or false | When set |
|---|---|---|
| `container_image` (digest-pinned) | ECR + cluster + IAM only | + internal NLB, task definition, Fargate service |
| `enable_report_worker` | — | + EC2 forensic target carrying the SOAR scope tag |
| `soar_playbook_package` | GuardDuty findings go **straight to SNS** | + 4 Lambdas, Step Functions `cs-ir-router`; EventBridge retargets to it |

`terraform test` (mocked provider) checks every default.

## 3. MTTC clock

Decision: MTTC is measured from the **EventBridge event `time`** to the moment the state machine enters `MarkContained`. GuardDuty's own `createdAt` is stored next to it on the incident row. This separates SOAR latency, which we control and target at under 60 s, from GuardDuty's detection and delivery delay, which we don't control.

Consequences:

- The EBS snapshot and SHA-256 manifest run **after** CONTAINED. Evidence capture never counts against MTTC.
- Dry-run executions end in `WOULD_CONTAIN_DRY_RUN` and are **excluded** from MTTC reporting.
- **Synthetic GuardDuty sample findings** (`create-sample-findings`) exercise the pipeline only in dry-run. The safety guard blocks them when `dry_run=false`. Real MTTC numbers come from scenarios A–C.

## 4. Ingress: internal NLB + REST API Gateway VPC Link

Following plan §4.3–4.4. REST API Gateway supports a regional WAF web ACL and usage-plan throttling. Its VPC Link (v1) targets an NLB over PrivateLink.

The NLB sets `enforce_security_group_inbound_rules_on_private_link_traffic = off`. PrivateLink traffic carries no source IP the NLB's security group could match. The endpoint is consumed only by our own VPC Link and is not shared.

**Trade-off accepted:** with an NLB there is no L7 routing or ALB-style auth at the load balancer. All of that lives at API Gateway (TB1).

## 5. Known limits (say these in the viva)

- **Tenant isolation is enforced in the API**, from the Cognito JWT tenant claim, not by IAM. The task role can reach every tenant's items. *Stretch goal:* per-request STS session tags with `dynamodb:LeadingKeys` and S3 prefix conditions.
- **PB-01 security-group swap does not drop tracked connections.** Security groups are stateful. The playbook must also stop the offending process or apply a deny NACL to the instance's subnet. That is an S3 code item.
- **PB-03 is bounded by bucket-name prefix (`cloudshield-dev-*`), not by tag.** S3 tag-based ABAC (`aws:ResourceTag` on bucket actions) exists, but only after `PutBucketAbac` is enabled on each bucket, which we do not do. The scenario C bucket must use the prefix. The guard checks the tag in code.
- **The audit table is insert-only by convention, not enforced by IAM.** No IAM condition key forces `attribute_not_exists` on `PutItem`. Mitigations: the app always sends that condition; there is no Update or Delete permission; the table stream (NEW_AND_OLD_IMAGES) gives tamper evidence; and PITR allows recovery.
- **SOAR may write inline policies onto principals** (PB-01 on the worker role, PB-02 on the honeytoken user). `iam:Put*Policy` accepts any document, so both actions are allowed only on principals carrying `soar-target-boundary`. A compromised playbook therefore cannot escalate them beyond SSM plus a few reads.
- **Scenario routing.** IMDS credential theft arrives as `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration*` with `resourceType = AccessKey`. The router sends it to **PB-01**, not PB-02. The Medium and Low findings that scenarios A and C produce (`Recon:EC2/Portscan`, `Policy:S3/*`) bypass `min_severity` through `always_route_finding_types`.
- **The router fails closed.** Only boolean `allowed == true` proceeds; only boolean `dry_run == false` acts; only `contained == true` from the playbook records CONTAINED.
- **Lambda reserved concurrency defaults to unreserved (-1).** New accounts have a limit of 10, and AWS rejects any reservation that leaves fewer than 100 unreserved. Set it to 5 once the quota allows.
- **IMDSv2 is enforced on the report-worker.** Scenario A must use the token flow (PUT, then GET). The design's "SSRF-style IMDS query" is still valid; it just needs the token flow.
