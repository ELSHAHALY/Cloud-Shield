# Phase D: edge, identity, two WAFs, PB-04 (ECS) and PB-05 (WAF IP block), and SOAR enhancements

**Branch:** `feat/s1-s2-edge-identity-waf` (stacked on `feat/s3-detection-athena-sims` = PR #2, which is stacked on PR #1) · **Status:** **APPROVED scope**, 16 Oct; building.

**Owners:**
- S1 @ELSHAHALY: edge, ECR push, CI, compute.
- S2 @YasseenAbdelghany: identity, app contract.
- S3 @ahklsfg: PB-04, PB-05, router, notifier, IR report, WAF logs, Glue, query 04, sims.

**Sources:** HANDOFF §3 (gaps 9, 11), §6, §8, §10, §11; ADR-0001, ADR-0002 §1–§5, ADR-0003; plan §1.1, §4.3, §6.2, §6.4, §8.6, §8.8; `README.md`; `soar/README.md` (handler contract, guard rules); `.zap/rules.tsv`; `attack-sim/README.md` (QA row → PB-05); the Phase C plan (format, F5 scope-tag precedent); module code under `infra/terraform/modules/*`; `soar/core/*`; `.github/workflows/ci.yml`; `bootstrap/main.tf`.

**How facts are marked:**
- **[doc]**: checked against AWS or Python documentation while planning.
- **[repo]**: read from this repository.
- **[inferred]**: my best understanding, not verified. Every [inferred] item is on the verify-on-apply list (§9) or covered by a test.

---

## 1. Facts that shape the design, and the decisions

### 1.1 Facts

| # | Fact or conflict | Plan |
|---|---|---|
| F1 | WAF can log to S3 only into a bucket whose name starts with `aws-waf-logs-` [doc]. The log archive can't receive WAF logs. | **D8:** a dedicated `aws-waf-logs-<name>-<acct>` bucket in `modules/log-archive`, encrypted with the archive key. That key already trusts `delivery.logs.amazonaws.com`, scoped by `aws:SourceArn arn:aws:logs:<region>:<acct>:*` [repo]. |
| F2 | A `CLOUDFRONT`-scope web ACL **and its IP sets** must be created in us-east-1 [doc]. | **D9:** `modules/edge` declares `configuration_aliases = [aws.us_east_1]`; dev adds the aliased provider. PB-05 calls WAFv2 with `WAF_REGION=us-east-1`. |
| F3 | Behind CloudFront, the regional ACL on API Gateway sees **CloudFront's IP**. `X-Forwarded-For` is client-controlled, because CloudFront appends to it [doc]. | **D4:** per-IP controls (reputation, rate limit, **PB-05 block list**) live on the **CloudFront ACL**. The regional ACL locks the origin to CloudFront and inspects payloads. |
| F4 | `module.compute.nlb_arn` is **unknown, not null**, while the NLB is being created [repo]. `count` on it fails. | **D6:** plan-time bools (`enable_api`, `enable_pb04`, `enable_pb05`), following the existing `revocable_role_arns` pattern [repo]. |
| F5 | CloudFront drops `Authorization` by default, and `Host` must not reach `execute-api`. An origin request policy that forwards all viewer headers forwards `Authorization`. Caching must be off when it isn't in the cache key [doc]. | `/api/*` uses Managed-CachingDisabled + Managed-AllViewerExceptHostHeader. |
| F6 | REST API logging needs the account-level `aws_api_gateway_account` CloudWatch role, a regional singleton [doc]. | `manage_apigw_account_role` (default `true`), plus an import note. |
| F7 | API Gateway auto-creates `API-Gateway-Execution-Logs_<id>/<stage>` unencrypted, with no expiry [doc]. | Pre-create it with the edge KMS key and 30 d retention. |
| F8 | The REST Cognito authorizer checks signature, issuer and expiry, but not `aud`, for ID tokens [inferred]. Custom attributes appear only in the ID token [doc]. | **D5:** the authorizer takes the ID token. The app re-verifies `iss`, `aud` and `token_use=id`. The tenant comes **only** from the verified claim. |
| F9 | Users can change their own custom attributes unless they're left out of `write_attributes`. Schema changes replace the pool [doc]. | `custom:tenant_id` is `mutable = false` **and** not writable. The schema is frozen in tests. |
| F10 | The ZAP gate FAILs on rules 10020, 10021, 10035 and **10038 (CSP)** [repo]. Managed-SecurityHeadersPolicy has no CSP [inferred]. | A custom response-headers policy with all four headers, on both behaviours. |
| F11 | A CloudFront `custom_error_response` for 403/404 also rewrites WAF and API errors to `200 index.html` [doc]. | **D10:** SPA rewrite with a CloudFront Function. A test asserts there is no `custom_error_response`. |
| F12 | With no domain, the default certificate fixes minimum viewer TLS at TLSv1 [doc]. | **D11:** Checkov skips CKV_AWS_174 / CKV2_AWS_42 with a reason. Follow-up: custom domain + ACM. |
| F13 | ECR is `IMMUTABLE`, and untagged images expire after 7 d [repo]. | Push tag `${GITHUB_SHA}`, deploy **by digest**. |
| F14 | Gap 9: there is no CI apply role [repo]. | CI pushes only. Deploying stays a local S1 apply. |
| F15 | Cognito threat protection needs the Plus tier [doc]. | `ESSENTIALS` by default; validation ties the threat-protection mode to `PLUS`. |
| F16 | The OIDC provider lives in `bootstrap/` (local state); the ECR repo lives in dev [repo]. | **D7:** push role in `modules/compute/ci-push.tf`; new `bootstrap` output `github_oidc_provider_arn`. |
| F17 | CI runs `validate` and `test` on **every module directory standalone** [repo]. A module with `configuration_aliases` must pass that on TF 1.16.5 [inferred]. | Builder step 0 smoke-tests it. **Fallback:** no alias, plus a `precondition` that `region == "us-east-1"` (plan §1.2: single region). |
| F18 | The user's brief names the scope tag `cloudshield:soar-enabled=true`. The repo's tag is `cloudshield:soar-scope=in-scope`, used in every IAM condition, the guard, the sims and SSM [repo]. This is the same conflict as Phase C F5. | **D18:** keep the repo tag. New code reads it from `SCOPE_TAG_KEY/VALUE`; nothing hard-codes it. |
| F19 | GuardDuty ECS findings carry `resource.resourceType = "ECSCluster"`. `resource.ecsClusterDetails` holds `arn`, `name`, `tags` and `taskDetails`. `taskDetails` holds `arn`, `definitionArn`, `group`, `startedBy`, `launchType`, `containers`, `tags` [doc: GuardDuty API `EcsClusterDetails` / `EcsTaskDetails`]. Service-launched tasks have `group = "service:<serviceName>"`, and `startedBy` is the deployment id [inferred]. | `EcsTaskTarget` is parsed from these fields. The owning service comes from `group`, then is **cross-checked** against live `DescribeTasks` + `DescribeServices` (§4.1). |
| F20 | Runtime Monitoring is **off** by default (Phase C D3: paid) [repo]. On Fargate it injects a GuardDuty agent sidecar. The task **execution role** must be able to pull the agent image from a GuardDuty-owned ECR repository [inferred from GuardDuty prerequisites]. Our execution role allows pulls from **this repo only** [repo]. | PB-04 is reachable **only** with `guardduty_runtime_monitoring = true` **and** the service enabled. `modules/compute` adds an optional `guardduty_agent_ecr_repository_arns` to the pull statement; the exact per-region ARN comes from the GuardDuty docs at build time. |
| F21 | When a Fargate task is stopped, ECS sends SIGTERM, then SIGKILL after `stopTimeout` (default 30 s) [doc]. The task passes through STOPPING → DEPROVISIONING (ENI detach) → STOPPED [doc]. Total time to `STOPPED` is not bounded and can threaten the 60 s MTTC [inferred]. | Set the container `stopTimeout = 2` in compute. PB-04's `contained` requires `desiredStatus = STOPPED` **and every container `lastStatus = STOPPED`** **and** task `lastStatus ∈ {DEPROVISIONING, STOPPED}` (the processes are dead, only the ENI is still detaching). Lambda timeout 55 s; polls every 2 s. |
| F22 | ECS IAM support [inferred, to verify against the Service Authorization Reference]:<ul><li>`StopTask` and `DescribeTasks` take `task` ARNs with the `ecs:cluster` condition.</li><li>`UpdateService` and `DescribeServices` take `service` ARNs with `ecs:cluster`.</li><li>`StopTask` and `UpdateService` support `aws:ResourceTag/*`.</li><li>`DescribeTaskDefinition` has **no** resource-level permission.</li><li>`UpdateService` without a task-definition change needs no `iam:PassRole`.</li></ul> | PB-04 IAM (§4.1). The real-provider test pins the documents. Apply-time AccessDenied is in §9. |
| F23 | `UpdateIPSet` **replaces the whole address list** and needs the `LockToken` from `GetIPSet`. A stale token raises `WAFOptimisticLockException`. IP sets hold at most 10,000 addresses [doc]. Terraform would revert any address PB-05 adds [repo pattern]. | Add-only read-modify-write with bounded retry; a cap of 1,000. The IP sets use `lifecycle { ignore_changes = [addresses] }`, so an apply never lifts a block (the same principle as ADR-0003). |
| F24 | In the same account, an identity policy allowing `events:PutEvents` is enough to publish to a bus unless the bus's resource policy **explicitly denies** it (IAM policy-evaluation logic [doc]; EventBridge applying it the same way is [inferred]). `PutEvents` lets the publisher set `Time` [doc]. EventBridge rejects `aws.*` sources from `PutEvents` [repo: Phase C F1]. | **D13:** a dedicated bus whose policy has a **Deny** for any `aws:PrincipalArn` outside a named publisher list. The guard rejects edge events whose `time` is in the future or older than 15 min. The custom-bus rule matches only `source = cloudshield.edge` with `resourceType = IPAddress`, so PB-01 to PB-04 can't be triggered through it. |
| F25 | Python `ipaddress`: `is_global` is False for private, loopback, link-local, reserved, shared (100.64/10) and **documentation** ranges (192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32) [doc]. Multicast must be checked separately [doc]. | Guard rules in §4.2. Test fixtures can't use documentation IPs as "blockable" addresses (§7). |
| F26 | The SNS incidents topic gets two message shapes [repo]:<ul><li>the router `Notify` string `Incident <id> \| <type> \| resource <rt> \| …`</li><li>while playbooks are off, the **raw GuardDuty event** JSON (plus Config notifications)</li></ul> | The notifier parses both strictly and ignores anything else (logged, never raised). |
| F27 | `urllib.request` follows redirects by default and honours `*_proxy` environment variables [doc]. Ruff `S310` flags `urlopen` [doc]. Semgrep `p/python` has a dynamic-urllib audit rule; its severity is believed to be below ERROR, which is what the gate fails on [inferred]. | One shared `core/http.py` call site: https-only, exact-host allow-list, no redirects, no proxies, 3 s timeout. `# noqa: S310` and `# nosemgrep` on that single line, each with its reason. |

### 1.2 Decisions

| # | Decision |
|---|---|
| **D1 Scope** | All in, in this order: edge + identity + ECR push + WAF logging/hunting → **PB-04, PB-05, router** → zero-cost enhancements (notifier, triage report, optional LLM hook, IaC snippet). |
| D2 | One CloudFront distribution: `/*` → private SPA bucket (OAC); `/api/*` → REGIONAL REST API. Same origin, so no CORS. |
| D3 | CloudFront adds a random `x-origin-verify` header; regional ACL rule 0 blocks anything without it. API Gateway blanks it before the backend. This is a bypass deterrent, **not** authentication; anyone with WAF or CloudFront read access can see it. |
| D4 | **CloudFront ACL:** p0 `SoarBlockedIps` (PB-05), IP reputation, rate limit (429), Common rule set, KnownBadInputs. **Regional ACL:** OriginVerify, KnownBadInputs, SQLi. |
| D5 | Cognito authorizer on the ID token, plus app re-verification. SRP from the SPA; no hosted UI or OAuth in Phase D. |
| D6 | `identity` always on. `enable_edge` defaults to **false** (≈ $19/month for the WAFs). `enable_api`, `enable_pb04` and `enable_pb05` are plan-time bools. |
| D7 | ECR push trust: `sub` StringEquals `repo:<owner>/<repo>:ref:refs/heads/main`. |
| D8 | WAF logs go to the `aws-waf-logs-*` bucket, with `authorization`, `cookie` and `x-origin-verify` redacted. |
| D9 | us-east-1 provider alias (fallback in F17). |
| D10 | SPA rewrite via a CloudFront Function; never `custom_error_response`. |
| D11 | Default certificate; the TLS minimum-version skips carry a reason. |
| **D12 PB-04 semantics** | Containment = **the compromised task's processes are dead (F21) and every sibling task is being replaced** (a new PRIMARY deployment). Task metadata is captured **before** StopTask and written as hashed evidence **after** CONTAINED (router step `PB04Evidence`), outside MTTC. This is the PB-03 pattern [repo]. **Limit:** `forceNewDeployment` re-runs the **same task definition and image digest**. If the image itself is compromised, the replacements are too. Eradication (a new image or digest) stays human (§6.4). |
| **D13 PB-05 trigger** | **(b) is the only path into the router:** custom events on a **dedicated bus**, `${name}-soar-edge`. Its policy denies `events:PutEvents` to every principal not in `pb05_publisher_arns`. **(a) feeds (b):** a CloudWatch alarm on the rate rule's `BlockedRequests` → EventBridge (default bus) → the **harvester Lambda**. It calls `GetRateBasedStatementManagedKeys` and publishes **one event per IP** onto the dedicated bus, so every IP passes the guard individually. Rejected: an input transformer straight into the router. The alarm carries no IP, so the guard couldn't vet targets. **Phase E boundary:** docs-api (the decoy route) becomes a publisher simply by adding its task-role ARN to `pb05_publisher_arns`. |
| **D14 IP guard** | See §4.2: global unicast only, never-block list in SSM, /32 and /128 only, edge-sourced only, fresh events only. |
| **D15 Block lifetime** | PB-05 records `blockExpiresAt` (default TTL 24 h) on the row. **Nothing removes blocks automatically** (§6.4). `tools/list_expired_blocks.py` (read-only) lists overdue blocks for an analyst. |
| **D16 Notifier secret** | The webhook URL is a credential. The operator creates it as an SSM **SecureString** under the SOAR CMK, out of band, so it never enters Terraform state or the repo. Terraform knows only the parameter **name**. |
| **D17 LLM hook** | Off by default, opt-in per run (`--ai-summary` **and** `CLOUDSHIELD_LLM_PROVIDER` set). Fixed endpoint allow-list; redacted input. Never in a Lambda. Tests never touch the network. |
| D18 | Scope tag stays `cloudshield:soar-scope=in-scope` (F18). |
| **D19 Runtime routing** | ECS Runtime findings reach the router **only at ≥ `min_severity`** (7). No `always_route` entry for `*:Runtime/*`, because auto-stopping production tasks on Medium findings is too aggressive. |
| **D20 Sims D/E** | Replay-local fixtures only: no `--target aws`, no `live-aws`. Additionally, the runner refuses (exit 3) unless the SSM dry-run switch reads `true`. Against a real account they can only ever produce `WOULD_CONTAIN_DRY_RUN`. |

## 2. Terraform: identity and edge

### 2.1 New module `modules/identity` (TB1, S2)

| File | Contents |
|---|---|
| `main.tf` | **`aws_cognito_user_pool.this`** `${name}-users`:<ul><li>`user_pool_tier = var.user_pool_tier`; `deletion_protection = var.deletion_protection`</li><li>`username_attributes = ["email"]`; `auto_verified_attributes = ["email"]`; case-insensitive usernames</li><li>**MFA:** `mfa_configuration = var.mfa_configuration` (`ON` default, `OPTIONAL` allowed); `software_token_mfa_configuration { enabled = true }`; **no SMS configuration** (TOTP only)</li><li>`allow_admin_create_user_only = true`</li><li>Passwords: minimum 14, all four character classes, temporary password valid 1 day</li><li>Recovery by verified email only</li><li>Schema: `custom:tenant_id` String, **`mutable = false`**, length 1–64</li><li>`user_pool_add_ons.advanced_security_mode = var.threat_protection_mode`</li></ul>**`aws_cognito_user_pool_client.spa`**:<ul><li>No secret</li><li>`explicit_auth_flows = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]`</li><li>`prevent_user_existence_errors = "ENABLED"`; token revocation on</li><li>Access and ID tokens 60 min, refresh 1 d, `auth_session_validity = 3`</li><li>`read_attributes = ["email", "email_verified", "custom:tenant_id"]`; **`write_attributes = ["email"]`**</li><li>No OAuth flows</li></ul>**`aws_cognito_user_group` × 4, exactly:** `admin` (precedence 10), `member` (20), `auditor` (30, read-only, including the audit trail), `secops-analyst` (5, SOC dashboard, plan §8.8). No IAM roles on groups. RBAC is enforced in the API from `cognito:groups`. |
| `variables.tf` | `name`; `mfa_configuration` (validated ∈ `ON`, `OPTIONAL`; `OFF` rejected); `user_pool_tier` (LITE / ESSENTIALS / PLUS, default ESSENTIALS); `threat_protection_mode` (OFF / AUDIT / ENFORCED; non-OFF needs PLUS); `deletion_protection`; `access_token_minutes` (5–60); `refresh_token_days` (1–30); `tags` |
| `outputs.tf` | `user_pool_id`, `user_pool_arn`, `user_pool_client_id`, `issuer_url`, `group_names`, `app_environment` = `{COGNITO_USER_POOL_ID, COGNITO_CLIENT_ID, COGNITO_ISSUER}` |

### 2.2 New module `modules/edge` (TB1, S1). Gated in dev by `count = var.enable_edge ? 1 : 0`.

| File | Contents |
|---|---|
| `versions.tf` | `aws ~> 6.0` with `configuration_aliases = [aws.us_east_1]`; `random ~> 3.6` |
| `main.tf` | Identity data sources. **Edge KMS key** `alias/${name}-edge`, with its policy as a **separate `aws_kms_key_policy`** (no cycle). Statements:<ul><li>AccountAdmin</li><li>`cloudfront.amazonaws.com` `kms:Decrypt` with `AWS:SourceArn` = this distribution</li><li>`logs.<region>.amazonaws.com` with encryption-context `ArnLike` on `log-group:/${name}/edge/*` and `log-group:API-Gateway-Execution-Logs_*`</li></ul> |
| `spa.tf` | Bucket `${name}-spa-${acct}`: KMS, versioning, BPA ×4, BucketOwnerEnforced, lifecycle. Policy: TLS deny + `s3:GetObject` for `cloudfront.amazonaws.com` with `AWS:SourceArn` = the distribution. OAC (sigv4, always sign). `aws_cloudfront_function.spa_rewrite` (cloudfront-js-2.0, viewer-request): a URI with no extension is rewritten to `/index.html`. |
| `waf.tf` | `random_password.origin_verify` (48 characters, no specials).<br>**PB-05 block lists** (`provider = aws.us_east_1`, `scope = CLOUDFRONT`): `aws_wafv2_ip_set.soar_blocked_v4` `${name}-soar-blocked-ips-v4` (IPV4) and `…_v6` `${name}-soar-blocked-ips-v6` (IPV6). Both start with `addresses = []` and have **`lifecycle { ignore_changes = [addresses] }`** (F23).<br>**`aws_wafv2_web_acl.cloudfront`** (us_east_1, CLOUDFRONT, default allow):<ul><li>**p0 `SoarBlockedIps`**: `or_statement` of the two `ip_set_reference_statement`s → block 403</li><li>p1 `AWSManagedRulesAmazonIpReputationList`</li><li>p2 `RateLimitPerIp`: limit `var.waf_rate_limit` (default 300) per 300 s, aggregate `IP`, block with **429**</li><li>p3 `AWSManagedRulesCommonRuleSet`</li><li>p4 `AWSManagedRulesKnownBadInputsRuleSet`</li></ul>**`aws_wafv2_web_acl.api`** (REGIONAL; only with `enable_api`): p0 `OriginVerify` (`not` byte-match EXACTLY on `x-origin-verify` → 403), p1 KnownBadInputs, p2 `AWSManagedRulesSQLiRuleSet`.<br>Metrics and sampled requests on every rule. Association of the regional ACL with the stage. Logging configurations ×2 → `var.waf_log_bucket_arn`, with redaction (D8). The CloudFront one is created only when the region is us-east-1. |
| `api.tf` (`enable_api`) | REGIONAL REST API.<br>VPC Link → `[var.nlb_arn]`.<br>`COGNITO_USER_POOLS` authorizer on `var.cognito_user_pool_arn`.<br>Methods:<ul><li>`GET /api/healthz`: `NONE` → `/healthz`</li><li>`ANY /api/{proxy+}`: **Cognito** → `/{proxy}`</li></ul>`HTTP_PROXY` + `VPC_LINK` integrations; `integration.request.header.x-origin-verify = "''"`.<br>Deployment with `triggers` + `create_before_destroy`.<br>Stage `v1`: X-Ray; JSON access log (requestId, status, `claims.sub`, `claims['custom:tenant_id']`, `wafResponseCode`).<br>Method settings: `ERROR` logging, **`data_trace_enabled = false`**, metrics on, caching off, throttle 50 burst / 20 rate.<br>Log groups (F7).<br>`aws_api_gateway_account` + role (`count = var.manage_apigw_account_role`); trust `apigateway.amazonaws.com` with **no** SourceAccount condition until verified (lesson of HANDOFF M3). |
| `cdn.tf` | Response headers policy:<ul><li>HSTS 1 y + includeSubdomains, nosniff, `frame-options DENY`, `strict-origin-when-cross-origin`</li><li>**CSP:** `default-src 'self'; connect-src 'self' https://cognito-idp.<region>.amazonaws.com; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'`</li></ul>Distribution:<ul><li>`web_acl_id` = the CloudFront ACL; PriceClass_100; http2and3; IPv6</li><li>`default_root_object = index.html`; default certificate; **no `custom_error_response`**</li><li>Default behaviour → SPA (CachingOptimized, redirect-to-https, headers, rewrite function)</li><li>`/api/*` (`enable_api`) → `<api-id>.execute-api.<region>.amazonaws.com`, `origin_path = /v1`, https-only, TLSv1.2, header `x-origin-verify`, 7 methods, CachingDisabled + AllViewerExceptHostHeader, headers policy</li></ul>Managed policy IDs come from `data` sources looked up by name. |
| `variables.tf` | `name`, `enable_api`, `nlb_arn`, `nlb_dns_name`, `nlb_listener_port`, `cognito_user_pool_arn`, `waf_log_bucket_arn` (validated `aws-waf-logs-` prefix), `waf_rate_limit` (10–2,000,000), `api_throttle_burst` / `rate`, `manage_apigw_account_role`, `log_retention_days`, `tags` |
| `outputs.tf` | `cloudfront_domain_name` (→ `STAGING_URL`), `distribution_id` / `arn`, `spa_bucket_name`, `cloudfront_web_acl` = `{name, id, arn}`, `api_web_acl_arn`, `rate_rule_name`, **`block_ip_set_arns` = `{v4, v6}`**, `rest_api_id`. The `execute-api` URL is deliberately not output. |

## 3. Terraform: shared changes

| File | Change | Owner |
|---|---|---|
| `bootstrap/outputs.tf` | `+ github_oidc_provider_arn` | S1 |
| `modules/compute/ci-push.tf` (new) | Created when `github_oidc_provider_arn != null`. Role `${name}-gha-ecr-push`.<br>**Trust:** `aud` = `sts.amazonaws.com`; **`sub` StringEquals** `repo:${github_repository}:ref:refs/heads/${ecr_push_branch}`.<br>**Policy:** `ecr:GetAuthorizationToken` on `*`; on the **string-built repo ARN only**: BatchCheckLayerAvailability, InitiateLayerUpload, UploadLayerPart, CompleteLayerUpload, PutImage, BatchGetImage, DescribeImages, DescribeImageScanFindings. No KMS statement; whether one is needed is in §9. | S1 (+ S3 approval) |
| `modules/compute/service.tf`, `main.tf`, `variables.tf` | **For PB-04:**<ul><li>Container `stopTimeout = 2` (F21).</li><li>ECS service `tags = merge(var.tags, var.soar_scope_app_service ? var.soar_scope_tag : {})` (default **false**). `propagate_tags = "SERVICE"` already copies the tags to tasks [repo]. Add `enable_ecs_managed_tags = true`.</li><li>Optional `guardduty_agent_ecr_repository_arns` (default `[]`), appended to the execution role's pull statement (F20).</li></ul>Variables: `github_oidc_provider_arn`, `github_repository` (validated), `ecr_push_branch`, `soar_scope_app_service`, `guardduty_agent_ecr_repository_arns`.<br>Outputs: `ecr_push_role_arn`, `ecs_cluster_arn` (exists), `ecs_service_name` (exists). | S1, S3 consulted |
| `modules/log-archive/waf-logs.tf` (new) | `enable_waf_logs` (default false). Bucket `aws-waf-logs-${name}-${acct}`: archive key, versioning, BPA, BucketOwnerEnforced, lifecycle. Policy: TLS deny, `AWSLogDeliveryAclCheck`, `AWSLogDeliveryWrite` on `AWSLogs/${acct}/*` with ACL + SourceAccount + SourceArn conditions. Rename the KMS sid `AllowVpcFlowLogDelivery` to `AllowLogDelivery`. Outputs with `depends_on` on the policy. The name is outside PB-03's `${name}-*` prefix. | S3 |
| `modules/detection/athena.tf` | Behind `waf_log_bucket_name != ""`: `aws_glue_catalog_table.waf_logs`.<ul><li>OpenX JSON SerDe; columns exactly as in AWS's WAF partition-projection DDL [doc]</li><li>Partitions `waf_region` (enum `cloudfront,<region>`), `webacl` (enum = `var.waf_web_acl_names`), `log_time` (date `yyyy/MM/dd/HH/mm`, interval 1 minute, range `<start>,NOW`) [doc]</li><li>Template `s3://<bucket>/AWSLogs/<acct>/WAFLogs/${waf_region}/${webacl}/${log_time}`</li></ul> | S3 |
| `detection/athena-queries/04_waf_blocked_requests_by_client.sql` | ATT&CK T1190 / T1595 / T1499; Scenario: QA, E. `Parameters: 2` (`log_time` from/to). Per client IP / terminating rule / action: count, first and last seen, sample URIs, rate-limited keys, and hits on `SoarBlockedIps` (PB-05 effect). | S3 |

## 4. SOAR: PB-04, PB-05 and router (S3)

### 4.1 PB-04 `playbooks/pb04_ecs_task_contain.py`, actions `contain` | `evidence`

**`Finding` changes** (`core/finding.py`):
- New `EcsTaskTarget(cluster_arn, task_arn, service_name | None)`, parsed when `resourceType == "ECSCluster"` and `ecsClusterDetails.taskDetails.arn` exists.
- Task ARN regex: `^arn:aws[\w-]*:ecs:[a-z0-9-]+:\d{12}:task/[\w-]{1,255}/[0-9a-f]{32}$`.
- `service_name` comes from `group` when it matches `^service:[\w-]{1,255}$`; otherwise None, and PB-04 refuses.

**Guard** (rule 3, ECS branch):
- `DescribeTasks(cluster, tasks=[arn], include=["TAGS"])` → the **live** task tags must carry the scope tag.
- The task's `clusterArn` must equal `ECS_CLUSTER_ARN`.
- The service must be in `ECS_SERVICE_NAMES`.
- Tags embedded in the finding are **never trusted**.

**`contain`** (before CONTAINED; Lambda timeout 55 s):
1. Re-check the scope (defence in depth). `DescribeServices` on the owning service: the service must carry the scope tag, and **the task's `startedBy` must equal one of the service's `deployments[].id`**. That proves the task belongs to that service, so a forged `group` can't redeploy the wrong service [inferred field semantics; tested with moto or a Stubber].
2. **Capture first** (in memory, returned as `prestate`): `DescribeTasks` output (task definition ARN, every `containers[].image` + `imageDigest`, ENI id and private IP from `attachments`, `startedAt`, `startedBy`) and `DescribeTaskDefinition` (container definitions; environment values are non-secret config by design [repo: `data.app_environment`]).
3. `StopTask(reason="cloudshield-soar <incident-id>")`. Already `STOPPED` → idempotent.
4. `UpdateService(forceNewDeployment=True)`. Skipped if a PRIMARY deployment created after `eventTime` already exists (idempotent on retry).
5. **Verify** with retries every 2 s, up to about 45 s (F21):
   - `taskStopped`: desiredStatus STOPPED, every container STOPPED, task `lastStatus ∈ {DEPROVISIONING, STOPPED}`
   - `newDeploymentPrimary`: a PRIMARY deployment whose `createdAt` ≥ the action time
   - `serviceInScope`

   Only then `contained: true`.

**`evidence`** (router `PB04Evidence`, after CONTAINED): the prestate is written to `incidents/<id>/pb04-ecs-task-<ts>.json` with SHA-256, using `EvidenceCollector` + `add_evidence` [repo pattern].

**Not automated:** ECS Exec volatile capture [repo: compute comment]. It needs an interactive session; it goes in the runbook as a human step, done **before** approving eradication.

**IAM** (`data.aws_iam_policy_document.pb04`). Cluster, service and allowed names come from variables, so ARNs are plan-time strings:

| Sid | Actions | Resource | Conditions |
|---|---|---|---|
| ReadTask | `ecs:DescribeTasks` | `arn:…:task/${cluster_name}/*` | `ArnEquals ecs:cluster = cluster ARN` |
| StopInScopeTask | `ecs:StopTask` | `arn:…:task/${cluster_name}/*` | `ecs:cluster` + `aws:ResourceTag/<scope> = in-scope` |
| ReadService | `ecs:DescribeServices` | `arn:…:service/${cluster_name}/<each allowed service>` | `ecs:cluster` |
| RedeployInScopeService | `ecs:UpdateService` | same service ARNs | `ecs:cluster` + scope tag |
| ReadTaskDefinition | `ecs:DescribeTaskDefinition` | `*` (**no resource-level support**, F22) | — |
| WriteEvidence | `s3:PutObject` | `${evidence}/incidents/*` | — |

- **Not granted:** `ecs:RunTask`, `ecs:DeleteService`, `ecs:UpdateService` on other services, `iam:PassRole`, `ecs:ExecuteCommand`.
- The guard role gains `ecs:DescribeTasks` scoped the same way.

### 4.2 PB-05 `playbooks/pb05_waf_ip_block.py`, actions `block`; plus `harvest_handler` (publisher)

**Event contract** (dedicated bus `${name}-soar-edge`; `source = "cloudshield.edge"`; `detail-type = "CloudShield Edge Finding"`). The shape is GuardDuty-like, so the unchanged router `RecordDetected` and `Finding` parse it:

```json
{"detail": {"schemaVersion": "2.0", "id": "edge-waf-rate-<ip-normalised>-<yyyyMMddHH>",
  "type": "CloudShield:IPAddress/WafRateLimitExceeded", "severity": 5.0,
  "createdAt": "<iso>", "accountId": "<acct>", "region": "<region>",
  "resource": {"resourceType": "IPAddress",
               "ipAddressDetails": {"ipAddressV4": "x.x.x.x"}},
  "service": {"serviceName": "cloudshield", "additionalInfo": {"sample": false,
               "publisher": "waf-rate-harvester", "webAcl": "<name>"}}}}
```

- Phase E adds the type `CloudShield:IPAddress/DecoyRouteHit` (docs-api decoy route).
- The hourly id makes repeats within the hour router-level duplicates [repo: the `RecordDetected` condition].

**`Finding` changes:**
- `Finding` now carries `source`.
- New `IpAddressTarget(address, version)`, resolved only when `source == "cloudshield.edge"` and `resourceType == "IPAddress"`. Any other combination → `UnknownTarget`.

**Guard: IP branch** (replaces the tag check, since an IP has no tags). The first failure refuses:
1. `source == EDGE_EVENT_SOURCE`, and `time` is within [now − 15 min, now + 60 s] (F24).
2. The value parses with `ipaddress.ip_address`; no `/` allowed; IPv4-mapped IPv6 is normalised to IPv4.
3. `is_global` and not `is_multicast`, `is_unspecified` or `is_reserved` (F25).
4. Not inside any CIDR in the **never-block** SSM parameter `/${name}/soar/pb05_never_block`. It is read on **every** call; if it is unreadable, refuse (fail closed). Terraform seeds it with the NAT EIP `/32` plus `var.pb05_never_block_cidrs` (operator IPs).
5. Rules 1, 2 and 5 are unchanged.

**`block`:**
1. Select the IP set by family from `BLOCK_IP_SET_ARNS` (the ARN gives name and id). WAFv2 client in `WAF_REGION`.
2. `GetIPSet` → addresses + LockToken. If the `/32` or `/128` is already present → idempotent success.
3. `len ≥ BLOCK_IP_SET_MAX` (default 1,000; F23) → `PlaybookError` → FAILED → analyst.
4. `UpdateIPSet(addresses = old + [cidr], LockToken)`. In code, assert `set(new) ⊇ set(old)` before the call (add-only). On `WAFOptimisticLockException`, re-Get and retry, **at most 3 attempts**.
5. **Verify:** `GetIPSet` contains the CIDR (3 attempts, 1 s apart).
6. `set_fields`: `blockedCidr`, `ipSetArn`, `blockExpiresAt = now + BLOCK_TTL_HOURS` (default 24). Return `contained: true`.
7. **Limit (say it in the viva):** "contained" means the block list is updated and read back. Propagation to every CloudFront edge isn't observed [inferred: it takes seconds to a minute]. No S3 evidence: the triggering event and the before/after counts are on the row's `actions`.

**`harvest_handler`** (gated with PB-05):
- Trigger: `aws_cloudwatch_metric_alarm` on `AWS/WAFV2 BlockedRequests` for the CloudFront ACL and rule `RateLimitPerIp` (dimensions `WebACL`, `Rule` [inferred for CLOUDFRONT scope]; period 60 s, ≥ 1) → default-bus rule on `CloudWatch Alarm State Change` to `ALARM` → harvester.
- It calls `GetRateBasedStatementManagedKeys(Scope=CLOUDFRONT, …)` and, for each IPv4/IPv6 key, `PutEvents` onto the dedicated bus, **without** setting `Time`. At most 50 events per invocation.
- It does **no** filtering of its own: the guard does that.
- **Known gap:** IPs that become rate-limited while the alarm is already in ALARM wait for the next transition. An optional `pb05_harvest_schedule` (`rate(5 minutes)`) is off by default.

**Expired blocks:** `soar/tools/list_expired_blocks.py` (read-only):
- Scans the incidents table for `blockExpiresAt < now` and cross-checks the live IP sets.
- Prints incident id, CIDR, age, and the documented manual removal command.
- `make expired-blocks`.
- It never calls `UpdateIPSet`.

**IAM:**

| Role | Grants |
|---|---|
| pb05 | `wafv2:GetIPSet`, `wafv2:UpdateIPSet` on **exactly the two IP-set ARNs** |
| harvester | `wafv2:GetRateBasedStatementManagedKeys` on the CloudFront ACL ARN; `events:PutEvents` on the dedicated bus ARN |
| guard | `ssm:GetParameter` on the never-block parameter |

Not granted anywhere: `wafv2:UpdateWebACL`, `wafv2:Delete*`, `wafv2:CreateIPSet`.

**Bus policy:**
- Allow `events:PutEvents` for each ARN in `pb05_publisher_arns`. The harvester role is always included; the Phase E docs-api task role and an operator replay role are optional.
- **Deny** `events:PutEvents` for `Principal "*"` with `ArnNotEquals aws:PrincipalArn` = that list.
- Residual risk (ADR-0001): an account admin can rewrite the bus policy.

### 4.3 `modules/soar` wiring

| File | Change |
|---|---|
| `variables.tf` | `enable_pb04` (bool), `ecs_cluster_name`, `ecs_cluster_arn`, `ecs_service_names` (list); `enable_pb05` (bool), `block_ip_set_arns` (list), `waf_web_acl` (object name/id/arn), `waf_rate_rule_name`, `pb05_publisher_arns` (list), `pb05_never_block_cidrs` (validated by `cidrhost`), `nat_public_ip`, `pb05_block_ttl_hours` (1–168), `pb05_ip_set_max` (1–9,000), `pb05_harvest_schedule`; `chatops_webhook_param_name` (default `""`), `chatops_allowed_hosts` (default `["hooks.slack.com", "discord.com"]`). All features off by default. |
| `playbooks.tf` | `local.playbooks` += `soar-pb04-ecs-task-contain` (timeout 55) and `soar-pb05-waf-ip-block` (timeout 20), each when its bool and `enable_playbooks` are true. New per-playbook documents `pb04` and `pb05` (§4.1, §4.2). `lambda_env` += `ECS_CLUSTER_ARN`, `ECS_SERVICE_NAMES`, `BLOCK_IP_SET_ARNS`, `BLOCK_IP_SET_MAX`, `BLOCK_TTL_HOURS`, `WAF_REGION`, `NEVER_BLOCK_PARAM`, `EDGE_EVENT_SOURCE`. All optional in `Settings` (empty means the feature is off, so PB-04/PB-05 refuse). |
| `edge-bus.tf` (new, `enable_pb05`) | `aws_cloudwatch_event_bus` `${name}-soar-edge` + policy (§4.2); never-block SSM parameter (String; non-secret); rule on the bus `{source:["cloudshield.edge"], detail.resource.resourceType:["IPAddress"]}` → `cs-ir-router` via the existing events role; harvester Lambda + role + KMS log group; alarm + default-bus alarm rule + Lambda permission (`SourceArn` = rule). Requires region us-east-1 (precondition, F2). |
| `notify.tf` (new, when `chatops_webhook_param_name != ""`) | Notifier Lambda (§5.1) + role + log group; `aws_sns_topic_subscription` (protocol `lambda`); `aws_lambda_permission` with `SourceArn` = the topic. |
| `state-machine.tf` | **RouteByResource** (before Default):<ul><li>`{And: [resourceType == "ECSCluster", type StringMatches "*:Runtime/*"]}` → `PB04Contain` (only when `enable_pb04`)</li><li>`{And: [source == "cloudshield.edge", resourceType == "IPAddress"]}` → `PB05Block` (only when `enable_pb05`)</li></ul>Choices are built with `concat()` of conditional lists, so the graph is still valid with both off.<br>`PB04Contain` / `PB05Block` tasks: same Retry and Catch as PB01–03, then `IsDryRun`.<br>**NeedsEvidence** += `ECSCluster` → `PB04Evidence` (Catch → Notify, as PB03Evidence does).<br>The guard is still the only way into `RouteByResource` [repo]. |
| `main.tf` | No change to the GuardDuty rule (D19). |
| `outputs.tf` | `edge_event_bus_arn`, `pb05_never_block_parameter`, `notifier_function_name` |

**Dev wiring:**
- `enable_pb04 = var.container_image != null && var.guardduty_runtime_monitoring && var.soar_scope_app_service`
- `enable_pb05 = var.enable_edge`
- Names and ARNs come from compute, edge and network (`nat_public_ip`). Edge never consumes soar outputs: no cycle.

## 5. Zero-cost enhancements (stdlib only; no new runtime dependencies)

### 5.1 ChatOps notifier: `soar/notifier/handler.py` + `soar/core/notifier.py` + `soar/core/http.py`

- **Input:** an SNS record. Parse the router string with a strict regex (`^Incident ([\w.:-]{1,128}) \|`) or the raw GuardDuty JSON (`detail.id`). Anything else is logged and ignored (F26).
- **Reads:** the incident row (`dynamodb:GetItem` on the incidents table; `kms:Decrypt` on the SOAR key). Builds a card: incident id, finding type, ATT&CK id (shared `core/attack.py`, §5.2), status, MTTC (`containedAt − eventTime`, or "—"), resource type.
- **Secret:**
  - `ssm:GetParameter(WithDecryption=True)` on exactly `chatops_webhook_param_name`, encrypted with the SOAR CMK (D16). The operator runbook command uses `--type SecureString --key-id alias/<name>-soar`.
  - Cached for 5 min per container. Never logged; the log shows the host only.
- **`core/http.py` `post_json(url, body, allowed_hosts, timeout=3)`:**
  - The scheme must be `https`; the host must be **exactly** in the allow-list; no userinfo; port absent or 443.
  - Built with `urllib.request.build_opener(ProxyHandler({}), _NoRedirect())`, where `_NoRedirect.redirect_request` returns None (F27).
  - Body ≤ 8 KiB; the response is read ≤ 4 KiB and discarded.
  - The single call line carries `# noqa: S310 - scheme and host validated above` and `# nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected - allow-listed https host`.
- **Never raises into the pipeline:** the handler catches `Exception` (`# noqa: BLE001`, with reason), logs it, and returns `{"posted": false, "reason": …}`. SNS → Lambda is async; returning normally avoids retry storms.
- **IAM:** `ssm:GetParameter` on that one parameter, `dynamodb:GetItem` on the table, `kms:Decrypt` on the SOAR key, own logs. Nothing else.
- **Packaging:** `scripts/package_soar.py` `PACKAGES` += `notifier`; the contract test's package set is updated.

### 5.2 Executive triage and remediation in `soar/tools/generate_ir_report.py`

- **New `soar/core/attack.py`:** a deterministic table keyed by finding-type prefix. Each entry has ATT&CK id(s), tactic, impact statement, eradication checklist and recovery checklist.

  | Scenario | Finding type | Technique(s) |
  |---|---|---|
  | A | Exfiltration | T1552.005 |
  | A recon | Recon | T1046 |
  | B | IAM user | T1078 / T1552.001 |
  | C | S3 policy | T1530 |
  | D | `*:Runtime/*` | T1610 / T1059, plus T1496 for CryptoCurrency |
  | E | `CloudShield:IPAddress/*` | T1190 / T1595 / T1499 |
  | — | anything else | an "analyst review" default |

- **Report:** a new "Executive summary" section (Markdown and JSON): status, MTTC verdict, the impact line, and checklists that link ADR-0003 (PB-01) and §4.1–4.2 (PB-04/05) recovery steps.
- **IaC remediation snippet (PB-03 incidents, posture loop §1.1):**
  - When `findingType` starts `Policy:S3/Bucket` and the bucket name is known, emit a ready-to-apply `resource "aws_s3_bucket_public_access_block" "<sanitised>" { bucket = "<name>" … four flags true }` plus `terraform import …`.
  - The bucket name is validated against the S3 bucket regex before it is interpolated. The resource label is `[a-z0-9_]`-sanitised. Anything invalid means no snippet (no HCL injection).
- **Optional LLM hook (D17):**
  - Active only with `--ai-summary` **and** `CLOUDSHIELD_LLM_PROVIDER=anthropic`, plus the key in `ANTHROPIC_API_KEY`. Otherwise the code path is skipped entirely.
  - Input = a **redacted** projection: finding type, resource type, status, MTTC, action step names. Regex scrubbing replaces ARNs, 12-digit account ids, IPv4/IPv6, emails, `AKIA` / `ASIA` key ids and bucket names with placeholders. Raw evidence and rows are never sent.
  - Goes through `core/http.py` with the allow-list `{"api.anthropic.com"}`.
  - Output is labelled "AI-generated, advisory". Any error degrades to "AI summary unavailable"; exit codes are unchanged.
  - **The Builder must load the `claude-api` skill before writing this**, for the model id and request shape.
- **Tests:** an autouse fixture patches `socket.socket` / `urllib.request.urlopen` to raise. The hook is tested with an injected fake opener: redaction, opt-in gating, failure degradation.

## 6. Sims, CI, docs and ownership

**Sims** (`soar/sims/`):
- `scenarios.py` += `d` ("ECS runtime compromise", T1610/T1059, `Execution:Runtime/NewBinaryExecuted`, severity 8, `ECSCluster`, pb04) and `e` ("Edge IP abuse", T1190/T1595, `CloudShield:IPAddress/WafRateLimitExceeded`, `IPAddress`, pb05; needs `--ip`, **no default**).
- `build_event` builds them with `source` set correctly.
- `local_router._route` mirrors the two new choices, including the `source` check.
- `runner.py`: d/e reject `--target aws` and `live-aws`, and refuse unless the dry-run switch reads `true` (D20).
- `verify_targets`: d → task tags + cluster; e → the IP-guard rules.

**CI** (`ci.yml`, job `image`):
- `permissions: {contents: read, id-token: write}`.
- Step "Push scanned image (main only)" with condition `push && refs/heads/main && vars.AWS_ECR_PUSH_ROLE_ARN != '' && steps.detect.outputs.present == 'true' && steps.scan.outcome == 'success'`. That is what blocks unscanned or failed images even in fail-open mode.
- Login via `get-login-password`, skip if the tag exists, push the **same local image**, `wait image-scan-complete`, digest to the job summary. Remove the `TODO(S1)`.
- New variables `AWS_ECR_PUSH_ROLE_ARN` and `ECR_REPOSITORY`.
- ZAP: `-m 1`; no WAF allow-list for CI.

**Makefile:**
- `sim` accepts `SCENARIO=d|e` (with `SIM_ARGS="--ip …"`).
- `+ expired-blocks`.
- `TF_DIRS` / `TF_TEST_DIRS` pick up the new modules automatically.

**Docs:**

| File | Change |
|---|---|
| `docs/adr/0004-edge-identity-waf.md` | D2–D11, D18 |
| `docs/adr/0005-pb04-pb05-edge-and-ecs-containment.md` | D12–D15, D19, D20; the PB-05 abuse analysis; the ECS IAM gaps |
| ADR-0002 §1 / §5 | Module rows → built; PB-04/05 limits |
| `soar/README.md` | Handler table + env vars + guard rules for ECS and IP + PB-04 / PB-05 notes + notifier |
| `attack-sim/README.md` | QA row → PB-05 (built) |
| `detection/README.md` | `waf_logs` + query 04 |
| `README.md` | Flags: `enable_edge`, `soar_scope_app_service`, `chatops_webhook_param_name`; cost (§8); TB1 built |
| HANDOFF §12 | Same shape as §11 |
| `app/README.md` | The S2 token contract (F8); audit `sourceIp` from `CloudFront-Viewer-Address` [inferred: forwarded by AllViewerExceptHostHeader, §9]; the Phase E PB-05 publisher contract (event shape §4.2; the publisher ARN must be added to `pb05_publisher_arns`) |
| `docs/runbooks/tenant-provisioning.md` | New |
| `docs/runbooks/edge-waf-demo.md` | New. R4: own distribution only |
| `docs/runbooks/pb04-pb05-recovery.md` | New: ECS Exec capture, image eradication, IP-block removal |
| `docs/runbooks/chatops-setup.md` | New: put-parameter SecureString, allowed hosts |
| `docs/runbooks/repo-admin-setup.md` | New variables; add the soar gate to the required checks |

**CODEOWNERS:**

```
/infra/terraform/modules/edge/            @ELSHAHALY
/infra/terraform/modules/edge/api.tf      @ELSHAHALY @YasseenAbdelghany
/infra/terraform/modules/edge/waf.tf      @ELSHAHALY @ahklsfg   # PB-05 IP sets
/infra/terraform/modules/identity/        @YasseenAbdelghany
/infra/terraform/modules/compute/ci-push.tf  @ELSHAHALY @ahklsfg
/infra/terraform/modules/compute/service.tf  @ELSHAHALY @ahklsfg  # PB-04 target
```

## 7. Test matrix (written before the code; guard tests first)

| Suite | Kind | Cases |
|---|---|---|
| `identity/tests/identity.tftest.hcl` | mock | MFA `ON` by default, `OPTIONAL` accepted, `OFF` rejected; TOTP on, no SMS; admin-only create; password ≥ 14; `tenant_id` `mutable = false`; no client secret; flows exactly SRP + refresh; `write_attributes` excludes tenant; user-existence errors prevented; revocation on; **groups == {admin, member, auditor, secops-analyst}**; threat protection rejected without PLUS |
| `edge/tests/edge.tftest.hcl` | mock (two providers) | **Defaults:** no API, VPC link or regional ACL; CloudFront ACL (scope CLOUDFRONT) with **p0 `SoarBlockedIps` referencing both IP sets, action block**; both IP sets CLOUDFRONT scope, correct IP versions, `addresses == []`; rate rule with 429; KnownBadInputs in both ACLs; no `custom_error_response`; never `allow-all`; four ZAP headers incl. CSP.<br>**`enable_api`:** VPC link → nlb; Cognito on every method but healthz; origin header blanked; OriginVerify p0; `data_trace_enabled = false`; throttling; caching off; `/api/*` policies, origin path, TLSv1.2; redaction.<br>**Validations:** WAF log bucket prefix; rate limit < 10. |
| `edge/tests/policies.tftest.hcl` | real provider + `override_resource` | SPA bucket policy scoped to the distribution ARN; KMS CloudFront decrypt scoped; logs statement limited to two patterns; API Gateway role trust |
| `compute/tests/ci_push.tftest.hcl` | real provider, plan + `override_data` | Absent by default; `sub` StringEquals the exact main ref (**mutation-check:** change it to StringLike `*` and confirm the test fails); push actions only on the repo ARN; only `GetAuthorizationToken` on `*`; no `Delete*`, `SetRepositoryPolicy` or `iam:*` |
| `compute/tests/compute.tftest.hcl` | mock | Push role null by default; service untagged by default, scope tag when `soar_scope_app_service`; `stopTimeout == 2`; GuardDuty agent ARNs appended only when given |
| `log-archive/tests/delivery.tftest.hcl` | real provider | WAF bucket off by default; prefix; write only under `AWSLogs/<acct>/*`; SourceAccount + SourceArn + ACL conditions |
| `detection/tests/detection.tftest.hcl` | mock | `waf_logs` gated; template and `log_time` format; named-query count == fileset (4) |
| `soar/tests/soar.tftest.hcl` | mock | PB-04/PB-05, bus, harvester and notifier absent by default; with flags, they exist; router graph has `PB04Contain`/`PB05Block` reachable **only** after `GuardDecision`; the IPAddress choice includes `source == cloudshield.edge`; NeedsEvidence → PB04Evidence; GuardDuty rule pattern unchanged (D19) |
| `soar/tests/iam.tftest.hcl` (extend; override all new resources) | real provider | **pb04:** Stop/Update only on `task\|service/<cluster>/…` with `ecs:cluster`, scope-tag conditions on both; `*` only on `DescribeTaskDefinition`; no RunTask, PassRole or ExecuteCommand.<br>**pb05:** wafv2 only Get/UpdateIPSet on exactly 2 ARNs.<br>**Harvester:** exactly GetRateBasedStatementManagedKeys on the ACL + PutEvents on the bus.<br>**Bus policy:** Deny with `ArnNotEquals aws:PrincipalArn` == the publisher list.<br>**Notifier:** only the one SSM parameter, GetItem, KMS decrypt. |
| `test_finding.py` / `test_guard.py` | pytest | ECS: valid; bad task ARN; no task; `group` not `service:`; live tags missing; cluster mismatch; service not allowed; finding-embedded tags ignored. IP: v4 / v6 / IPv4-mapped; private, loopback, link-local, shared, documentation, multicast, unspecified, reserved → refuse; CIDR string → refuse; never-block hit → refuse; never-block unreadable → refuse; wrong `source` → Unknown; stale and future `time` → refuse; sample × dry-run as before; return types are exact `bool` |
| `test_pb04.py` | moto ECS (Stubber where moto lacks deployments / `stopTimeout` semantics) | Happy path (all three verifications); dry-run makes **zero** mutating calls; `startedBy` not among the service's deployments → raises **before** StopTask; untagged service → raises; already STOPPED → idempotent; existing fresh PRIMARY → no second UpdateService; verify timeout → `contained: false`; evidence hash on the row; prestate captured **before** StopTask (call-order assertion) |
| `test_pb05.py` | moto WAFv2 (or Stubber) | Append v4/v6; already present → idempotent; LockException ×2 then success; ×3 → raises; cap reached → raises; add-only assertion (a stubbed shrinking list → raises); read-back required; `blockExpiresAt` = now + TTL; harvester publishes one event per key, never sets `Time`, caps at 50 |
| `test_notifier.py` | pytest, no network | Router-string and raw-event parsing; unknown message ignored; http rejects http://, non-allow-listed host, userinfo, a port other than 443, and a redirect (fake 302 → not followed); `ProxyHandler({})` is used; SSM failure → `posted: false`, no raise; webhook value never appears in logs (caplog) |
| `test_ir_report.py` (extend) | pytest | Triage section per scenario A–E + default; PB-03 snippet exact text; invalid bucket → no snippet; AI hook off by default (socket patched to raise); opt-in uses the fake opener; redaction removes ARN, account, IP, email, key id and bucket |
| `test_list_expired_blocks.py` | moto | Lists only overdue rows; read-only (no Update calls) |
| `test_sims.py` (extend) | pytest | Router parity: `_route` vs `state-machine.tf` incl. ECS and IP choices; d/e refuse `--target aws` / `live-aws`; d/e refuse when dry-run reads `false`; `e` requires `--ip` |
| `test_contract.py` (update) | pytest | Handler list now covers safety guard, pb01–pb05, pb05 harvester and notifier; env-var set equality incl. new vars; package contents == {core, safety_guard, playbooks, notifier} |
| `test_queries.py` | pytest | `CATALOGUED_TABLES += waf_logs`; query 04 passes all checks |

**Test fixtures:** blockable IPs must be global (F25), so they use well-known public anycast addresses **only inside moto**. Documentation ranges are used only to assert refusals. If moto lacks an ECS/WAFv2 call, use a `botocore.stub.Stubber` (the Phase A precedent). New moto extras are allowed only if they add no packages (`pip install --dry-run` diff empty); otherwise use the Stubber.

## 8. Cost (lab, us-east-1)

| Item | Approximate cost | Default |
|---|---|---|
| WAF: 2 ACLs ($5 each) + 9 rules ($1 each) + $0.60 per million requests; IP sets have no listed charge [inferred]. *Audit A2 added a 10th rule (`SoarApiRateLimit`): ≈ $20/month.* | **≈ $19/month** with no traffic | off (`enable_edge`) |
| CloudFront / REST API / WAF logs / edge KMS | free tier / $3.50 per M / cents / $1 | with edge |
| CloudWatch alarm (harvester) | $0.10/month | with PB-05 |
| Dedicated bus, PB-04/05, harvester and notifier Lambdas | free tier at lab volume | flags |
| GuardDuty Runtime Monitoring (PB-04 prerequisite) | per vCPU-hour after the trial | **off** (Phase C D3) |
| Cognito Essentials (TOTP) | free tier for lab MAU | **on** |
| LLM hook | provider-billed, per run, opt-in only | off |

## 9. Quality gates and the verify-on-apply list

**Gates:**

- `terraform fmt` clean; `validate` in **all 9 dirs**; `terraform test` all green.
- Checkov **0 failed**. Expected skips, each with a reason:
  - CKV_AWS_174 / CKV2_AWS_42: default certificate.
  - CKV_AWS_86: WAF logs every request.
  - CKV_AWS_310: single region.
  - CKV_AWS_374: geo restriction.
  - CKV_AWS_120 / 225: per-tenant responses are never cached.
  - CKV2_AWS_51: VPC Link only.
  - CKV2_AWS_53: openapi validation in the app.
  - CKV_AWS_59: healthz only.
  - Bucket logging / replication / notifications: as for the evidence bucket.
  - On the new Lambdas, the same CKV_AWS_116 / 117 / 272 / 115 reasons as PB01–03.
- **pytest coverage ≥ 95%** (`fail_under = 95`; coverage `source += notifier`). ruff clean. Gitleaks: no leaks (the origin secret and the webhook live only in state and SSM). actionlint clean. Lambda zip is deterministic.

**Verify on the first apply** ([inferred] items):

1. `validate` / `test` with `configuration_aliases` on TF 1.16.5 (step 0).
2. Whether ECR push needs KMS.
3. Whether AllViewerExceptHostHeader forwards `CloudFront-Viewer-Address`.
4. WAF S3 delivery under the archive key's SourceArn.
5. A `waf_logs` smoke query.
6. API Gateway role trust without conditions.
7. A SPA deep link returns 200, while an unauthenticated `/api/x` returns **401**.
8. ECS condition-key support (F22): StopTask and UpdateService with tag conditions succeed on an in-scope service and **fail** on an untagged one.
9. Fargate stop timing under `stopTimeout = 2` against the 60 s MTTC (F21).
10. The GuardDuty agent ECR repository ARN and that tasks still start with Runtime Monitoring on (F20).
11. The bus Deny blocks an in-account admin role that isn't on the list (F24).
12. WAF alarm dimensions for CLOUDFRONT scope.
13. IP-set propagation time to the edge.
14. Notifier delivery to the real webhook host.

## 10. Builder order and pipeline

1. **Step 0:** F17 smoke (a stub module with `configuration_aliases`, `validate` + `test` on 1.16.5). Decide the alias or the fallback.
2. `bootstrap` output → `compute/ci-push.tf` + compute PB-04 prerequisites (tags, `stopTimeout`, agent pull) + tests.
3. `identity` + tests.
4. `log-archive` WAF bucket + tests.
5. `edge` (KMS, SPA, IP sets, WAF, API, CDN) + both suites.
6. `detection` `waf_logs` + query 04 + `test_queries`.
7. Dev wiring + `validate`.
8. CI push step + actionlint.
9. **SOAR core:** `Finding` (`source`, ECS, IP) → guard (tests first) → `Settings` / contract.
10. **PB-04** + tests → **PB-05** (block + harvester) + tests → `list_expired_blocks`.
11. `modules/soar` (playbooks.tf, edge-bus.tf, state-machine.tf) + mock and IAM suites → `local_router`, sims d/e, parity test.
12. **Enhancements:** `core/http.py` → notifier (+ notify.tf, packager) → `core/attack.py` + report triage + IaC snippet → LLM hook (**load the `claude-api` skill first**).
13. Checkov to 0 failed; coverage ≥ 95%.
14. Docs: ADR-0004, ADR-0005, ADR-0002, READMEs, HANDOFF §12, runbooks, CODEOWNERS, `app/README`.

**Independent Auditor** (a fresh agent). Focus:

- `execute-api` reachable without the CloudFront WAF?
- Tenant change or forgery; another client's token accepted?
- Secrets (JWTs, origin header, webhook URL) in logs or state outputs?
- Push-role trust breadth; an unscanned image pushed in fail-open mode?
- `custom_error_response` regression; plan-time-unknown `count`s; Checkov skip honesty.
- **PB-05 abuse:** can any principal or input cause a block of a legitimate IP? Check:
  - the bus Deny and the publisher list
  - a forged `source` or `resourceType` on the default bus
  - stale or future `time`
  - the never-block list read and fail-closed behaviour
  - IPv4-mapped / reserved / documentation edge cases
  - harvester input trust
  - IP-set cap and add-only behaviour
  - Terraform reverting blocks
- **PB-04 wrong-service actions:** a forged `group`, a task from another cluster or service, the `startedBy` ↔ deployment check, tag conditions, and whether UpdateService could change anything but the deployment.
- **Notifier:** secret handling (SecureString, no logging, cache), **SSRF** (scheme, host allow-list, redirects, proxies, userinfo, ports), and no exceptions leaking into SNS retries.
- **LLM hook data egress:** truly off by default; redaction completeness; endpoint allow-list; no use in Lambdas.
- The router still fails closed; CONTAINED is reachable only via `CheckContained`.

**Validator:** fmt / validate / test, Checkov, ruff + pytest ≥ 95%, Gitleaks, actionlint, zip determinism. Then push and open **PR #3 stacked on #2** (merge order #1 → #2 → #3).

**Phase E (next)** builds on these boundaries:
- Node docs-api with a **decoy route**: it publishes `CloudShield:IPAddress/DecoyRouteHit` to the PB-05 bus as a named publisher; no other wiring changes.
- React SOC dashboard: reads the incidents GSI; `secops-analyst` group.
- docker-compose for local development.
