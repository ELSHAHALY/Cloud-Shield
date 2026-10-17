# Phase E: docs-api, SPA (customer portal and SOC dashboard), GRC hub, local compose

**Branch:** `feat/s2-app-soc-ui-grc`, stacked on `feat/s1-s2-edge-identity-waf` (PR #3 → #2 → #1). It becomes **PR #4**, based on PR #3's branch.
**Status:** APPROVED 16 Oct 2026 (user confirmed D1 paths `app/docs-api` + `app/spa`, D13 decoy notify-only, D20 Vitest for the SPA / Jest for docs-api, D21 moto server instead of LocalStack). Building.

**Owners**
- **S2 @YasseenAbdelghany** (lead): `app/` (API, SPA, GRC content, local tooling), `modules/data`.
- **S1 @ELSHAHALY:** the decoy resource in `modules/edge/api.tf`, the posture read in `modules/compute`, CI, compose review.
- **S3 @ahklsfg:** `modules/soar/app-integration.tf` (SOC read and decoy publisher IAM), the notify-only edge type in the guard, the ATT&CK table export, sign-off on the SOC data contract.

**Sources**
- `docs/HANDOFF.md` §2–§12; the Phase D plan (`docs/plans/s1-s2-edge-identity-waf.md`); ADR-0002, ADR-0004, ADR-0005.
- `app/README.md`: the token contract and the PB-05 publisher contract.
- `README.md`, `.github/workflows/ci.yml`, `.github/CODEOWNERS`, `.github/dependabot.yml`, `Makefile`, `.gitignore`, `.zap/rules.tsv`, `scripts/gate-selftest.sh`.
- `infra/terraform/modules/{data,compute,identity,edge,soar,network}/`, `environments/dev/main.tf`.
- `soar/core/{finding,guard,evidence,incidents,attack}.py`, `soar/playbooks/pb05_waf_ip_block.py`, `soar/tools/generate_ir_report.py`, `soar/requirements-dev.txt`.

**How facts are marked**
- **[doc]:** checked against vendor or official documentation while planning.
- **[repo]:** read from this repository.
- **[inferred]:** my best understanding, not verified. Each one is either on the verify-on-apply list (§16), covered by Builder step 0 (§17), or covered by a test.
- **[verify]:** a legal, licensing or version claim that must be checked against an official source before it ships. GRC content may show it only with a "verify" badge, never as an established fact.

---

## 1. Facts that shape the design, and the decisions

### 1.1 Facts

| # | Fact or conflict | Plan |
|---|---|---|
| F1 | **Paths.** The brief asks for `apps/docs-api` and `apps/soc-ui`. The repo already uses `app/` everywhere [repo]:<ul><li>CI `APP_DIR` defaults to `app/docs-api`, and the image gate builds `$APP_DIR/Dockerfile`</li><li>CODEOWNERS has `/app/`</li><li>`app/README.md` lists `docs-api/`, `spa/` ("customer portal + SecOps SOC dashboard") and `openapi.yaml`</li><li>`README.md` layout, HANDOFF §6, the Dependabot TODO (`/app/docs-api`) and the `repo-admin-setup.md` `APP_DIR` row</li></ul>There is one CloudFront distribution with one SPA bucket (`modules/edge/spa.tf`) [repo]. | **D1** |
| F2 | The image gate's build **context** is `$APP_DIR` [repo]. The contract `app/openapi.yaml` and the GRC data sit outside that context. | **D2** |
| F3 | **Data model.** The brief says "single-table" with an `AUDIT_EVENT` table. The data module already has [repo]:<ul><li>`documents`: PK `tenantId`, SK `docId`</li><li>`audit`: PK `tenantId`, SK `eventKey` = `<ISO-8601 UTC>#<requestId>`, stream NEW_AND_OLD_IMAGES</li></ul>Both have PITR and the data CMK. The task role has `PutItem`, `Query` and `GetItem` on audit, with no Update or Delete. No data exists yet, because nothing has been applied. | **D3** |
| F4 | The audit table is insert-only **by convention**: the app sends `attribute_not_exists(eventKey)`, IAM grants no Update/Delete, and the stream and PITR exist (HANDOFF M6, gap 15) [repo]. `data/main.tf` says the stream is alarmed by "the detection module", but **no such resource exists** (grep of `modules/detection`) [repo]. | Phase E never calls it "immutable". The comment is corrected. A stream consumer is a follow-up (§17). |
| F5 | Documents bucket policy [repo]:<ul><li>denies a foreign KMS key id</li><li>denies the SSE-S3 header</li><li>denies `s3:signatureAge` above `presigned_url_max_seconds` (default 300, range 60–3600)</li></ul>It has **no CORS configuration** [repo]. The CloudFront CSP is `connect-src 'self' https://cognito-idp.<region>.amazonaws.com` [repo `cdn.tf`]. A browser `fetch` PUT to S3 would be blocked by both. | **D9:** upload goes **through the API**. Download is a pre-signed GET **navigation**, which `connect-src` doesn't govern and which needs no CORS. |
| F6 | `GetObject` with a `VersionId` needs `s3:GetObjectVersion` [doc]. The task role has Get/Put/DeleteObject on `documents/*` only [repo]. | Add `GetObjectVersion`; narrow to `tenants/*` (§9). |
| F7 | With S3 Bucket Keys the SSE-KMS encryption context is the **bucket** ARN [doc]. The documents bucket has `bucket_key_enabled = true` [repo]. | There is no per-tenant KMS context. Tenant isolation is not cryptographic (ADR-0002 §5); say so. |
| F8 | API Gateway [repo `api.tf`]:<ul><li>`GET /api/healthz` (NONE) → `/healthz`</li><li>`ANY /api/{proxy+}` (Cognito) → `/{proxy}`</li><li>`x-origin-verify` is blanked</li></ul>An **unauthenticated** request to any other path is rejected at API Gateway (401) and never reaches the app. | Decoy: **D14**. |
| F9 | **Token contract** (Phase D F8/D5, `app/README.md`) [repo]:<ul><li>The ID token is re-verified by the app: signature, `exp`, `iss`, `aud == COGNITO_CLIENT_ID`, `token_use == id`.</li><li>The tenant comes only from `custom:tenant_id`; roles only from `cognito:groups`.</li><li>A cross-tenant request is a 404.</li></ul>Cognito ID tokens carry `cognito:groups` and `custom:*` [doc]. `aws-jwt-verify`'s `CognitoJwtVerifier` derives `iss` and the JWKS URL from the pool id, checks `token_use` and `clientId` (`aud` for ID tokens), and never follows token-supplied `jku`/`x5u` [doc]. | **D5, D6** |
| F10 | `custom:tenant_id` is any 1–64-character string (identity schema) [repo]. The runbook example is `t-acme-01` [repo]. No tenant registry exists anywhere; a tenant is just the Cognito attribute [repo]. | **D7:** the app enforces a strict tenant format; `_platform` is a reserved partition. |
| F11 | Container contract [repo `compute`]:<ul><li>port 3000</li><li>`user` 1000:1000 (root is rejected by validation)</li><li>`readonlyRootFilesystem`, writable `/tmp` volume</li><li>`capabilities.drop = ALL`, `initProcessEnabled`</li><li>**`stopTimeout = 2`**</li><li>`X86_64`</li><li>NLB HTTP health check `/healthz` → 200 every 15 s; no task-definition `healthCheck`</li><li>environment comes from `container_environment` (non-secret)</li></ul>App security group egress is 443/tcp to `0.0.0.0/0` (JWKS, AWS APIs via NAT) [repo]. | §11 Dockerfile |
| F12 | **What happens to an unknown edge type today** [repo `edge-bus.tf`, `guard.py`, `state-machine.tf`]:<ul><li>The bus rule forwards every `CloudShield:IPAddress/*` + `IPAddress` event to `cs-ir-router`.</li><li>The guard refuses types outside `EDGE_FINDING_TYPES = {WafRateLimitExceeded}`.</li><li>The router records `BLOCKED_BY_GUARD` with `guardReason` and runs `Notify` (SNS → email and the ChatOps notifier).</li><li>PB-05 independently refuses non-allow-listed types (audit A1).</li></ul>So `DecoyRouteHit` already yields **record + notify, never block**. | **D13** |
| F13 | The edge bus exists only with `enable_pb05 = enable_edge && playbook package` [repo]. | docs-api must degrade to audit-only when `EDGE_BUS_NAME` is empty. |
| F14 | **Bus policy** = Allow for the named publishers (the harvester role + `pb05_publisher_arns`) plus an explicit Deny for everyone else (`ArnNotEquals aws:PrincipalArn`) [repo]. EventBridge supports the `events:source` and `events:detail-type` condition keys on `PutEvents` [doc]. | The task role may publish only `source = cloudshield.edge` with detail-type `CloudShield Edge Finding` (§9). |
| F15 | **Source IP.** `CloudFront-Viewer-Address` (`<ip>:<port>`) is believed to be forwarded by Managed-AllViewerExceptHostHeader (Phase D verify #3) [inferred]. Its IPv6 rendering [inferred], and whether CloudFront overwrites a viewer-supplied header of that name [inferred], are also unconfirmed. HTTP_PROXY is believed to pass it through API Gateway [inferred]. `execute-api` is reachable directly by anyone holding the origin secret (ADR-0004 consequences) [repo], and **that caller can forge the header**. | **D13–D14**. Every audit row carries `sourceIpTrusted`. |
| F16 | **Incidents table** [repo]:<ul><li>PK `incidentId`; GSI `status-eventTime` (projection ALL); SOAR CMK.</li><li>Statuses written by the router: `DETECTED`, `CONTAINED`, `WOULD_CONTAIN_DRY_RUN`, `BLOCKED_BY_GUARD`, `NO_PLAYBOOK_ANALYST_REVIEW`, `FAILED`.</li><li>Fields: `findingType`, `severity`, `resourceType`, `eventTime`, `firstEventTime`, `findingCreatedAt`, `containedAt`, `wouldContainAt`, `sfnStartedAt`, `executionArn`, `attempts`, `actions[]`, `evidenceRecords[]`, `evidenceSha256`, `guardReason`, `failure`, PB-05 `blockedCidr`/`blockState`/`blockExpiresAt`.</li></ul>A decoy row holds the IP **only inside its id** (`edge-decoy-<ip>-<hour>`). | SOC reads use one Query per status, never a Scan (§7). |
| F17 | **Evidence bucket** [repo]:<ul><li>SOAR CMK + Bucket Key, versioned.</li><li>**Object Lock only when `evidence_object_lock_days > 0`** (GOVERNANCE; default 0 = off).</li><li>Records are `{bucket, key, versionId, sha256, sha256Base64}`.</li><li>The IR tool recomputes SHA-256 from S3 and exits 2 on a mismatch.</li></ul>CloudTrail S3 data events cover the evidence and documents buckets [repo dev wiring]. | The UI must say "Object Lock not enabled" honestly when it is off. |
| F18 | The IR logic is Python: `generate_ir_report.py` (387 lines). Triage is `core/attack.py`, whose matchers are **lambdas** [repo]. TypeScript can't import either. | **D17** |
| F19 | **Posture.** The app can't safely query GitHub at runtime.<ul><li>The image job runs after secrets/SAST/SCA (`needs`), so those outcomes are known **before** `docker build` [repo].</li><li>An image cannot contain its own Trivy result: writing it in would change the digest that was scanned [inferred, by construction].</li><li>CI pushes to ECR only when every scan really passed (audit A9) [repo].</li><li>ECR scan-on-push (basic) is on [repo].</li></ul> | **D18** |
| F20 | **Emulator.**<ul><li>LocalStack's Cognito is a paid feature [inferred].</li><li>LocalStack moved to an account/auth-token model for its images in 2025–2026 [verify].</li><li>The repo already pins **moto 5.2.4** (`soar/requirements-dev.txt`) [repo].</li><li>moto is **Apache-2.0** licensed, not MIT as the brief's notes say [verify; believed Apache-2.0].</li><li>The moto server covers S3 (including Object Lock retention [inferred]), DynamoDB (GSI), KMS, EventBridge custom buses, SSM and STS [inferred → step 0].</li></ul> | **D21** |
| F21 | Port clash: docs-api listens on **3000** [repo `app_port`], and the brief wants the UI on host `localhost:3000`. | Compose maps SPA host 3000 → nginx 8080. docs-api is not published to the host. |
| F22 | Node 24 is the Active LTS line; Node 26 is due to enter LTS in late October 2026 [verify]. | Node **24.x**, pinned in `app/.nvmrc` and `engines`. Base images by digest. |
| F23 | Express 5 forwards rejected async handlers to the error handler, and defaults `query parser` to `"simple"` [doc], so `?a[$ne]=1` is not parsed into an object. | Express 5. |
| F24 | REST API payload limit is 10 MB; integration timeout defaults to 29 s [doc]. | Upload cap is 5 MiB by default. Polling, not streaming (D19). |
| F25 | `TransactWriteItems` allows up to 100 actions across tables in one account/Region, authorised per underlying action (`PutItem`, `UpdateItem`, `ConditionCheckItem`) [doc]. | A document change and its audit event are written atomically (§5.4). |
| F26 | GitHub Actions `services:` containers run beside a job on Ubuntu runners [doc]. | moto in CI for Jest integration tests. |
| F27 | Existing gates [repo]:<ul><li>Trivy fs: fixable CRITICAL, skips `infra/`, scans lockfiles.</li><li>Trivy image: fixable CRITICAL/HIGH.</li><li>Semgrep: `p/owasp-top-ten` + `p/nodejs` + `p/python`, ERROR only, excludes `infra/` and `docs/`.</li><li>Checkov: `--framework terraform` on `infra/terraform` only.</li></ul>Trivy skips npm dev dependencies by default [inferred]. The Trivy image default scanners include `secret` [inferred]. | §11 CI deltas |
| F28 | `.gitignore` already ignores `dist/`, `build/`, `coverage/`, `.env.*` (except `.env.example`), `*.pem` and `*.key` [repo]. The Dependabot npm block is a TODO [repo]. | Lockfiles must be committed; the local IdP keeps its key in memory only. |
| F29 | **Legal sources.** None are in the repo.<ul><li>GDPR article numbers [doc].</li><li>Egypt Law No. 151 of 2020 [doc] for the law's identity; its article-level content [verify].</li><li>CBE cloud/outsourcing instruments [verify].</li><li>KSA PDPL (Royal Decree M/19, 1443H) [doc for the decree]; its amendments, dates, transfer and breach rules [verify].</li><li>NCA ECC-2:2024 and CCC [verify].</li></ul> | **D23–D24** |
| F30 | GDPR Art. 28(9) lets the controller–processor contract be "in writing, including in electronic form" [doc]. A click-through is **not** a qualified electronic signature (eIDAS QES; Egypt E-Signature Law No. 15 of 2004 [verify]). | **D25** |
| F31 | Everything is deployed in `us-east-1` (plan §1.2) [repo]. AWS has no Region in Egypt [inferred]; the KSA Region's status [verify]. | GRC residency and transfer rules report **GAP** for EG, SA and EU tenants by construction. That is the honest output. |
| F32 | The edge CSP is `default-src 'self'` with no `unsafe-inline`, plus `img-src 'self' data:` [repo]. | **D20:** no inline `<style>`/`<script>`, no CSS-in-JS, no chart library. |
| F33 | Amplify v6 stores tokens in `localStorage` by default and accepts a custom key-value store such as `sessionStorage` [verify]. `amazon-cognito-identity-js` is in maintenance [verify]. | **D20** |
| F34 | **Phase D promised** (app/README, ADR-0005, HANDOFF §12): the decoy publishes `CloudShield:IPAddress/DecoyRouteHit` as a named publisher; until a corroboration check exists, "the guard and PB-05 refuse the type". HANDOFF §12 "Next" says "a **corroborated** edge type". [repo] | **D13**: notify-only in Phase E; corroborated blocking is a follow-up. |
| F35 | Module wiring: soar already consumes compute outputs and compute consumes `soar.target_permissions_boundary_arn` [repo]. Terraform orders by resource, not module, so the new edges (task role → soar policy; soar env → compute task definition) form no resource cycle, provided `soar.app_environment` is built only from soar-owned names [inferred]. | Builder step 7 runs `validate` and `plan -refresh=false` (mock). |

### 1.2 Decisions

| # | Decision |
|---|---|
| **D1 Paths** | Keep `app/`. The brief's `apps/docs-api` is `app/docs-api`; its `apps/soc-ui` is **`app/spa`**, one SPA containing the customer portal, the SOC dashboard and the GRC hub, behind role-gated routes. One distribution means one SPA bucket. **No existing path changes.**<br>Files touched only to *add* the new directories: `.github/workflows/ci.yml` (D2 context, new `app` job), `.github/dependabot.yml`, `.github/CODEOWNERS`, `app/README.md`, `README.md` (layout), `docs/HANDOFF.md` §13, `docs/runbooks/repo-admin-setup.md` (`APP_DIR` / `IMAGE_CONTEXT` rows, new required check).<br>New: `app/openapi.yaml`, `app/.nvmrc`, `app/docs-api/`, `app/spa/`, `app/grc/`, `app/local-dev/`, root `docker-compose.local.yml`. |
| **D2 Build context** | The image gate builds with `docker build -f "$APP_DIR/Dockerfile" "$IMAGE_CONTEXT"`. `IMAGE_CONTEXT` is a new env, `vars.IMAGE_CONTEXT \|\| 'app'`. `app/docs-api/Dockerfile.dockerignore` (BuildKit per-Dockerfile ignore [doc]) allow-lists only `docs-api/`, `openapi.yaml` and `grc/{schema,rules,matrix,agreements,platform-facts.json}`. The contract stays at `app/openapi.yaml`, its documented home. |
| **D3 Data model** | **Reuse the existing tables. No new table, no schema change.**<ul><li>`documents` becomes single-table *style* with typed sort keys: `doc#<uuidv7>` for documents, `meta#grc-profile` for a tenant's GRC profile.</li><li>The brief's `AUDIT_EVENT` **is** the `audit` table.</li></ul>Why not a new single-table design: PITR, KMS, the stream, the IAM and the tests already exist; a new table would need new IAM, tests and PITR; and nothing in the brief needs another access pattern. |
| D4 | Every audit write uses `ConditionExpression: attribute_not_exists(eventKey)`. Wording everywhere: "insert-only audit table (conditional writes, no Update/Delete IAM, stream, PITR)", never "immutable". |
| **D5 Auth** | Production mode: `CognitoJwtVerifier.create({userPoolId, clientId, tokenUse: "id"})`, plus an explicit re-check of `iss == COGNITO_ISSUER`. Failure → 401 with `WWW-Authenticate: Bearer error="invalid_token"`. There is never an unverified decode. Local mode: D22. |
| **D6 RBAC + ABAC** | RBAC is a fixed permission table keyed by `cognito:groups`; unknown groups are ignored and several groups give the union. ABAC: the tenant key comes from the token only, and member writes are limited to documents they own (§4). `secops-analyst` gets **no** tenant-document access (separation of duties). |
| D7 | Tenant format `^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`. Otherwise → 403 `TENANT_INVALID` (fail closed; the runbook is updated). `_platform` (leading underscore, so never a tenant) holds platform-scoped audit: decoy hits and SOC evidence/report access. |
| D8 | IDs are server-generated **UUIDv7** (time-ordered; about 20 lines on `crypto.randomFillSync`, no dependency). The S3 key is `tenants/<tenantId>/docs/<docId>`. No client value, file name included, ever enters a key. |
| D9 | Upload: `POST /documents` (metadata, `PENDING_UPLOAD`) → `PUT /documents/{docId}/content` (raw body ≤ `MAX_UPLOAD_BYTES`, default 5 MiB).<ul><li>The server recomputes SHA-256 and compares it with the declared value.</li><li>It sniffs magic bytes for the type.</li><li>`PutObject` with `ServerSideEncryption=aws:kms`, `SSEKMSKeyId=DATA_KMS_KEY_ARN` (the exact ARN the bucket policy expects) and `ChecksumSHA256`.</li></ul>Download: a pre-signed GET with `VersionId`, `ResponseContentDisposition=attachment` (RFC 6266/5987-encoded) and `ResponseContentType`; `expiresIn = min(requested, PRESIGNED_URL_MAX_SECONDS)`. |
| D10 | Delete → a tombstone. One transaction sets `status=DELETED`, clears title/description/tags and writes the audit event; then S3 `DeleteObject` (a delete marker). Non-current versions expire after 30 days [repo lifecycle], so erasure completes within 30 days. That is the GRC Art. 17 note. |
| D11 | The error model is RFC 9457 `application/problem+json` with a stable `code` and the `requestId`. It never includes stack traces, AWS error messages or ARNs (§3.2). |
| D12 | The OpenAPI spec is the request validator (`express-openapi-validator`, `additionalProperties: false` everywhere). Responses are validated against it **in tests**. Types are generated with `openapi-typescript` into both packages and committed; CI fails on drift. |
| **D13 Decoy semantics** | **Notify-only in Phase E; A1 is not weakened.** docs-api publishes `CloudShield:IPAddress/DecoyRouteHit` (the existing contract). SOAR keeps refusing it. The guard returns an explicit reason, `notify-only edge finding (decoy route hit): analyst review`, through a new `EDGE_NOTIFY_ONLY_TYPES`. It is still `allowed: false` and is **not** added to `EDGE_FINDING_TYPES`. The router records `BLOCKED_BY_GUARD` and notifies (F12). The SOC UI labels such rows "Decoy hit: notify only".<br>Rejected: corroborating with docs-api's own writes (not independent); making docs-api a blocking publisher.<br>**Follow-up (not built):** a CloudFront WAF rule `SoarDecoyRateLimit` (rate-based, scoped to `/api/admin`, limit 10 per 60 s [doc: minimum 10]). PB-05 could then corroborate a decoy hit against WAF's own managed keys exactly as it does for `WafRateLimitExceeded`. That needs S1 + S3 review and about $1/month; ADR-0006 records it. |
| **D14 Decoy reachability** | In the app the decoy handler runs **before** authentication, so it fires with or without a token. A token, if present, is verified silently, only to name the actor. To catch *unauthenticated* scanners, `modules/edge` gains `enable_decoy_route` (default **false**): `ANY /api/admin` and `ANY /api/admin/{proxy+}`, authorisation NONE → `/admin`, `/admin/{proxy}`. With the flag off, the decoy sees only authenticated callers (insider or stolen-token probing), which is still useful. |
| D15 | `DECOY_PUBLISH_ENABLED` (Terraform-set) and `EDGE_BUS_NAME` must both be set to publish; otherwise the hit is audit-only. Limits: one publish per IP per hour per task (it matches the hourly id), a global cap of 30 per minute per task, and audit writes capped at 5 per minute per IP (the rest are counted in a log line). |
| **D16 SOC data path** | docs-api reads TB5 directly with a **read-only, prefix-scoped policy owned and attached by `modules/soar`** (`app-integration.tf`). The same principle applies to the data module: the owner of the data decides who touches it. Rejected for now: a separate SOC read Lambda/API, which is better isolation and the multi-account target (ADR-0001) but more infrastructure. The residual risk (a compromised task can read incident rows and evidence) is recorded in ADR-0006, mitigated by read-only access, the `incidents/*` scope and CloudTrail data events on the evidence bucket. SOC routes are **`secops-analyst` only**. |
| **D17 IR report in the UI** | **Port only the verification primitive, not the report logic.** docs-api recomputes SHA-256 over each evidence object (version-pinned; base64 cross-check exactly as `_check_evidence`), computes MTTC exactly as `build_report`, reads Object Lock status, and renders JSON + Markdown with the same field names as `IrReport.to_dict()`, minus `ai_summary` and `iac_remediation` (shown as "run `make ir-report`").<br>Triage comes from `app/docs-api/src/soc/attack-table.generated.json`. A new `soar/tools/export_attack_table.py` emits it, with a declarative mirror proven equal to `core.attack.triage` over a corpus; CI fails on drift.<br>Parity is pinned by shared golden fixtures (`soar/tests/fixtures/coc_golden.json`) asserted by **both** pytest and Jest. The Python tool stays authoritative; the UI report is labelled "live verification view".<br>Hardening:<ul><li>The evidence bucket must equal `EVIDENCE_BUCKET`; the key must start with `incidents/`.</li><li>At most 20 objects, each at most 5 MiB.</li><li>Markdown is a download only and is never rendered as HTML.</li></ul> |
| **D18 Posture** | Three sources, each worded precisely:<ol><li>**Build info** baked at image build: commit SHA, build time, and the *real outcomes* of the secrets/SAST/SCA/app gates (`needs.*`), plus whether gates were enforced.</li><li>**Image policy** (static text): "CI pushes to ECR only when Trivy reports no fixable CRITICAL/HIGH vulnerabilities at scan time."</li><li>**Live ECR basic scan** of the running digest (`APP_IMAGE` env → `DescribeImageScanFindings`): counts plus completion time, or "unavailable". It never says "no vulnerabilities".</li></ol>Containment health: the SSM dry-run switch, `SOAR_PLAYBOOKS_ENABLED`, FAILED count in 24 h, last MTTC. |
| D19 | "Live" means **polling**: SOC overview every 15 s, paused when the tab is hidden, backing off to 120 s on errors and honouring `Retry-After`. docs-api keeps a shared in-memory cache of SOC data (never tenant data) for 10 s. No SSE or WebSocket: REST API + VPC Link and a 29 s timeout gain nothing. |
| D20 | SPA:<ul><li>React + TypeScript + Vite + Tailwind (compiled CSS only), React Router.</li><li>`aws-amplify/auth` v6 for SRP + TOTP, with tokens in `sessionStorage` [verify API].</li><li>Charts are hand-written SVG components.</li><li>`build.modulePreload.polyfill = false` (no inline script).</li><li>ESLint `react/no-danger: error`.</li><li>**Vitest** + React Testing Library for components. A deliberate deviation from "Jest" for the SPA: the same `expect` API, Vite-native, and no second transform pipeline. docs-api uses **Jest** (ts-jest, CommonJS).</li></ul> |
| **D21 Emulator** | **moto server** (`motoserver/moto:5.2.4@sha256:…`), the same version as the Python tests, Apache-2.0 [verify]. LocalStack is not used: Cognito is paid and the licensing is in flux [verify]. All AWS access goes through `AWS_ENDPOINT_URL`, so swapping to LocalStack is a one-service change, documented but not supported. |
| **D22 Local auth with no production bypass** | A dev-only `local-idp` (in `app/local-dev`, never in the production image) mints RS256 ID tokens with **`iss = http://local-idp:9000`**: http, not a Cognito URL format.<br>docs-api's config validator:<ol><li>`CLOUDSHIELD_ENV` defaults to `aws` (strict).</li><li>In `aws` mode, `COGNITO_ISSUER` must match `^https://cognito-idp\.[a-z0-9-]+\.amazonaws\.com/[a-z0-9-]+_[A-Za-z0-9]+$` and must equal the issuer derived from `COGNITO_USER_POOL_ID`. Any of `AUTH_LOCAL_ISSUER`, `AUTH_LOCAL_JWKS_URI`, `AWS_ENDPOINT_URL` or `S3_PUBLIC_ENDPOINT` being present makes the process exit at startup.</li><li>`CLOUDSHIELD_ENV=local` is accepted **only** together with `AWS_ENDPOINT_URL` whose host is in {`moto`, `localhost`, `127.0.0.1`, `::1`}. Local auth is thereby coupled to a fake data plane: even a mis-set production task couldn't reach real data with a local token.</li></ol>The verifier factory returns `CognitoJwtVerifier` in `aws` mode and a generic RSA verifier only in `local` mode.<br>Belt and braces: API Gateway's Cognito authorizer already rejects non-Cognito tokens; a Terraform test asserts the task definition never contains `CLOUDSHIELD_ENV=local`, `AUTH_LOCAL_*`, `AWS_ENDPOINT_URL` or `S3_PUBLIC_ENDPOINT`; Jest proves every rejection (§13). |
| **D23 GRC engine** | Rules are **data**: versioned JSON (`app/grc/rules/<semver>.json`) validated by JSON Schema (ajv) at startup.<ul><li>An invalid ruleset makes the GRC endpoints answer 503 (fail closed); the rest of the API is unaffected.</li><li>The condition DSL has a fixed set of operators, an allow-listed fact path set and depth ≤ 8. No `eval`, no regexes from data, no prototype paths.</li><li>Every assessment returns the ruleset version + SHA-256 and the disclaimer.</li></ul> |
| D24 | Every legal claim carries a `citation` with `status: "doc" \| "verify"`. The UI shows a "Verify against the official text" badge on `verify` items. Disclaimer: informational mapping for an academic capstone, **not legal advice**, last reviewed `<date>`. |
| **D25 Agreements** | Click-through **acceptance logging** for a DPA and an SLA template. Only tenant `admin` can accept; until the tenant has accepted every `required` agreement, document **writes** answer 403 `AGREEMENT_REQUIRED`. What is recorded is in §8.4. It is click-wrap evidence bound to an MFA-authenticated Cognito identity, **not** a qualified or advanced electronic signature. Agreement texts are templates, not reviewed by counsel. |
| D26 | Onboarding: the operator creates the tenant's first `admin` in Cognito (runbook; no self sign-up [repo]). At first sign-in the SPA routes the admin to `/onboarding`: accept DPA + SLA, then set the GRC profile. |
| D27 | CI: a new hard-failing job **`gate: app (lint + typecheck + test + build)`**, which always fails like `soar` (correctness):<ul><li>moto service, Jest coverage gate, Vitest, `vite build`</li><li>OpenAPI/types drift check, hadolint (pinned), `docker compose config`</li></ul>The image job also `needs: app`, and its push condition also requires `needs.app.result == 'success'`. Checkov adds `--framework dockerfile` on `app/` (fail-open per `ENFORCE_GATES`). Semgrep adds `p/typescript` and `p/react` [verify names]. Only `docs-api` gets an image. **The SPA is a static build for the SPA bucket**; its local nginx image is compose-only and never pushed. |
| D28 | Supply chain:<ul><li>Exact versions (`save-exact=true`), committed `package-lock.json` per package, `npm ci --ignore-scripts` (`.npmrc ignore-scripts=true`).</li><li>Node 24 and base images pinned by digest.</li><li>Dependabot for `npm` (3 directories) and `docker`.</li><li>setup-node pinned to a commit SHA.</li></ul> |

---

## 2. Component boundaries

```
TB0 browser ──► CloudFront (+WAF, CSP) ──/*────► SPA bucket (app/spa static build)
                     │ /api/*  (CloudFront-Viewer-Address added)
                     ▼
          REST API GW (regional WAF, Cognito authorizer; [flag] NONE /api/admin*)
                     │ VPC Link ► NLB ► Fargate task "docs-api" (TB2)
                     ▼
┌─────────────── docs-api (Express 5 / TS) ───────────────────────────────┐
│ decoy ─► audit(_platform) + PutEvents(edge bus)       [pre-auth]        │
│ auth ─► rbac/abac ─► documents | audit | agreements | grc | soc         │
└──┬──────────────┬───────────────┬────────────────┬───────────────┬─────┘
   ▼ TB3 (data CMK)               ▼ TB5 read-only (SOAR CMK)        ▼ TB4
 documents tbl, audit tbl,     incidents tbl + GSI, evidence/    ECR scan of own digest
 documents bucket tenants/*    incidents/*, dry_run SSM;
                               PutEvents edge bus (source/detail-type pinned)
                                    │
                                    ▼ cs-ir-router ► guard: notify-only ► BLOCKED_BY_GUARD ► SNS/ChatOps
```

| Component | Boundary | Owns | Must never |
|---|---|---|---|
| `app/docs-api` | TB2 | REST API, authZ, tenant isolation, audit, decoy, SOC read model, GRC engine, agreements | write to TB5; Scan any table; take a tenant from anything but the token; log tokens or bodies |
| `app/spa` | TB0 code served from TB1 | UI (portal, SOC, GRC) | enforce security (UX gating only); render HTML from data; store tokens in `localStorage` |
| `app/grc` | data | rules, matrix, agreements, platform facts, schemas | contain unmarked legal claims |
| `app/local-dev` | dev only | local IdP, seed, fixtures | ship in any pushed image; run against real AWS (the seed refuses a non-local endpoint) |
| `modules/soar/app-integration.tf` | TB5 | the read/publish grant to the app role | grant writes, Scan, or `kms:GenerateDataKey` |

---

## 3. API contract (`app/openapi.yaml`, OpenAPI 3.1, contract-first)

### 3.1 Conventions

- **Paths** are those the container sees. API Gateway strips `/api`, and local nginx does the same.
- `securitySchemes.cognitoIdToken` = HTTP bearer, JWT. It is global; `/healthz` and the decoy have `security: []`.
- **Every** request body is `additionalProperties: false`, with `maxLength` on every string and patterns on every id:
  - `docId`: UUIDv7 regex
  - `incidentId`: `^[\w.:-]{1,128}$`, as in `finding.py`
  - `agreementId`: `^[a-z][a-z0-9-]{1,31}$`
  - `version`: `^\d{4}-\d{2}(?:\.\d+)?$`
- **Response headers on every response:** `X-Request-Id`; `Cache-Control: no-store`; `Content-Type: application/json` or `application/problem+json`. `Retry-After` on 429.
- **Pagination:** an opaque `cursor` (base64url JSON holding **only** the sort-key value, re-validated by regex). The partition key is always rebuilt from the token (§5.1).
- The decoy paths are in the spec under tag `decoy` with `x-cloudshield-decoy: true`, for auditor visibility. The spec is never served by the API.

### 3.2 Error model (RFC 9457)

```json
{"type": "urn:cloudshield:problem:not-found", "title": "Not Found", "status": 404,
 "code": "NOT_FOUND", "requestId": "0192b3c4-…",
 "errors": [{"path": "/body/title", "message": "must NOT have more than 200 characters"}]}
```

| Code | Status | When |
|---|---|---|
| `UNAUTHENTICATED` | 401 | missing or invalid token (any verifier failure) |
| `TENANT_INVALID` | 403 | `custom:tenant_id` absent or not matching D7 |
| `FORBIDDEN` | 403 | permission missing (RBAC) or not the owner (ABAC) |
| `AGREEMENT_REQUIRED` | 403 | document write before the tenant accepted the required agreements |
| `NOT_FOUND` | 404 | unknown route, **another tenant's resource**, a tombstoned document |
| `VALIDATION_FAILED` | 400 | spec violation; `errors[]` carries only `path` + the schema message, never the input value |
| `CONFLICT` | 409 | duplicate create; acceptance already recorded (returns the existing record) |
| `PRECONDITION_FAILED` | 412 | `If-Match` version mismatch |
| `PAYLOAD_TOO_LARGE` / `UNSUPPORTED_MEDIA_TYPE` | 413 / 415 | upload limits; type or magic-byte mismatch |
| `INTEGRITY_MISMATCH` | 422 | uploaded bytes ≠ declared SHA-256 |
| `RATE_LIMITED` | 429 | app-level limiter |
| `SERVICE_UNAVAILABLE` | 503 | GRC ruleset invalid; agreements catalogue unloadable |
| `INTERNAL` | 500 | anything else. Logged server-side with the stack; the body carries only `requestId`. |

### 3.3 Routes (shapes are named `components.schemas` in the spec)

| Method + path | Request | Response |
|---|---|---|
| `GET /healthz` | — | `{status:"ok"}`: no version, no dependency checks |
| `GET /me` | — | `Me {sub, email?, tenantId, groups[], permissions[]}` |
| `GET /documents?limit(1–100)&cursor` | — | `DocumentPage {items: DocumentMeta[], nextCursor?}` |
| `POST /documents` | `DocumentCreate {title(1–200), description?(≤2000), contentType∈{application/pdf, text/plain, image/png, image/jpeg, application/vnd.openxmlformats-officedocument.wordprocessingml.document}, sizeBytes(1–MAX), sha256(hex64), classification∈{public,internal,confidential,restricted}, tags?[≤10 × ≤32]}` | 201 `DocumentMeta` (`status: PENDING_UPLOAD`) |
| `PUT /documents/{docId}/content` | raw body; `Content-Type` must equal the declared type | 200 `DocumentMeta` (`AVAILABLE`, `s3VersionId` internal-only, not returned) |
| `GET /documents/{docId}` | — | `DocumentMeta {docId, title, description?, contentType, sizeBytes, sha256, classification, tags, ownerSub, status, createdAt, updatedAt, version}` |
| `PATCH /documents/{docId}` | `DocumentPatch {title?, description?, classification?, tags?}` (at least 1 property); optional `If-Match: "<version>"` | `DocumentMeta` |
| `GET /documents/{docId}/download` | — | `DownloadUrl {url, expiresAt}` |
| `DELETE /documents/{docId}` | — | 204 |
| `GET /audit?from&to&limit&cursor` | ISO bounds, default 30 days | `AuditPage {items: AuditEvent[], nextCursor?}` |
| `GET /agreements` | — | `Agreement[] {agreementId, version, title, sha256, effectiveDate, required}` |
| `GET /agreements/{agreementId}/{version}/text` | — | `text/plain; charset=utf-8` |
| `GET /agreements/status` | — | `AgreementStatus {complete, accepted[], pending[]}` |
| `POST /agreements/{agreementId}/accept` | `AcceptanceRequest {version, sha256, authorityConfirmed: true}` | 201 `Acceptance`; 200 if already accepted (idempotent) |
| `GET /grc/ruleset` | — | `RulesetSummary {version, sha256, lastReviewed, disclaimer, jurisdictions[], frameworks[]}` |
| `GET /grc/responsibility-matrix` | — | `ResponsibilityMatrix` (§8.3) |
| `GET /grc/profile` / `PUT /grc/profile` | `GrcProfile` (§8.2) | `GrcProfile + {version, updatedAt, updatedBy}` |
| `GET /grc/assessment` | — | `GrcAssessment {rulesetVersion, rulesetSha256, profileVersion, generatedAt, platformFacts, disclaimer, findings: GrcFinding[]}` |
| `GET /soc/overview` | — | `{incidents: IncidentSummary[≤50], metrics: SocMetrics, generatedAt}`: one call per poll |
| `GET /soc/incidents?status&limit&cursor` | — | `IncidentPage` |
| `GET /soc/incidents/{incidentId}` | — | `IncidentDetail` (§7.2) |
| `GET /soc/incidents/{incidentId}/evidence` | — | `EvidenceCheck[]` (§7.3) |
| `GET /soc/incidents/{incidentId}/report?format=json\|md` | — | `IrReport` JSON, or `text/markdown` attachment |
| `GET /soc/metrics?window=24h\|7d\|30d` | — | `SocMetrics {mttc{targetSeconds:60, samples, last, p50, p90, max}, byStatus{}, byTactic[{tactic, count, techniques[]}], window}` |
| `GET /soc/posture` | — | `Posture` (§7.5) |
| `GET /soc/audit?from&to&limit&cursor` | — | `AuditPage` for `_platform` |
| `ANY /admin`, `ANY /admin/{rest}` (decoy) | ignored (no body parser) | 403 `FORBIDDEN` problem, byte-identical in shape to a real 403 |

---

## 4. Middleware chain, RBAC and ABAC

### 4.1 Order (`app/docs-api/src/app.ts`, `buildApp(deps)` factory for tests)

1. `app.disable('x-powered-by')`; `app.set('trust proxy', false)`; Express 5 `query parser: simple`.
2. **requestId:** a server-generated UUIDv4 (any inbound `X-Request-Id` is ignored), set on `res`.
3. **securityHeaders:** `helmet` with:
   - CSP `default-src 'none'; frame-ancestors 'none'`
   - `Referrer-Policy: no-referrer`, HSTS 1 y + subdomains, `nosniff`, `X-Frame-Options: DENY`
   - CORP `same-origin`, COOP `same-origin`
   - plus `Cache-Control: no-store`

   There is **no CORS middleware**: everything is same-origin.
4. **sourceIp:**
   - In `aws` mode, parse `CloudFront-Viewer-Address` strictly. Split on the last `:`, strip `[]`, check with `net.isIP`, normalise IPv4-mapped addresses to IPv4. The result is `{ip, trusted: true}`.
   - Anything else gives `{ip: null, trusted: false}`. `X-Forwarded-For` is never read.
   - In `local` mode nginx overwrites the same header (§10).
5. **Logger:** `pino-http`. Redacted: `authorization`, `cookie`, `x-origin-verify`, `cloudfront-viewer-address`. Logged per request: `requestId`, method, **route template**, status, latency, `sub`, `tenantId`. Bodies, query values and tokens are never logged.
6. **preAuthLimiter:** 60/min per trusted IP, otherwise per "unknown" bucket.
7. **decoyRouter** (§6), mounted at `/admin`.
8. **`GET /healthz`.**
9. **Body parsers**, per route: `express.json({limit: '64kb', strict: true, type: 'application/json'})`; `express.raw({limit: MAX_UPLOAD_BYTES, type: <declared>})` on the upload route only.
10. **openapiValidator** (requests; responses too when `NODE_ENV=test`).
11. **authenticate** (D5/D22) → `req.principal`. A 401 also counts toward `preAuthLimiter`.
12. **principal:** tenant regex (D7), `groups = claim ∩ {admin, member, auditor, secops-analyst}`, `permissions = ⋃ ROLE_PERMISSIONS[g]`. The result is frozen as `Principal {sub, tenantId: TenantId (branded type), groups, permissions, jti?}`.
13. **userLimiter:** 600/min per `sub`. Uploads 30/min, download URLs 120/min, SOC 240/min.

    The limiters are in-memory per task, so with 2 tasks the effective limit is 2×. WAF and API Gateway throttling (50 burst / 20 rps) remain the real limits.
14. **Routers**, each route with `requirePermission(p)`; document writes also with `agreementGate`.
15. **notFound** → 404 problem. **errorHandler** maps known errors (validator, body parser `SyntaxError`/`type`/`entity.too.large`, `AppError`, `ConditionalCheckFailedException` → 404/409/412 by context). Anything else → 500 `INTERNAL`.
16. **server.ts:** SIGTERM → `server.close()` + a forced exit at 1.5 s, inside `stopTimeout = 2` (F11).

### 4.2 Permissions and route matrix

| Permission | admin | member | auditor | secops-analyst |
|---|:-:|:-:|:-:|:-:|
| `doc:read` (list, get, download URL) | ✓ | ✓ | ✓ | — |
| `doc:write` (create, upload, patch) | ✓ | ✓ own | — | — |
| `doc:delete` | ✓ | ✓ own | — | — |
| `audit:read` (tenant) | ✓ | — | ✓ | — |
| `agreement:read` | ✓ | ✓ | ✓ | ✓ |
| `agreement:accept` | ✓ | — | — | — |
| `grc:read` (ruleset, matrix) | ✓ | ✓ | ✓ | ✓ |
| `grc:assess` (profile read, assessment) | ✓ | — | ✓ | — |
| `grc:profile:write` | ✓ | — | — | — |
| `soc:read` (overview, incidents, metrics, `_platform` audit) | — | — | — | ✓ |
| `soc:evidence` (evidence verify, report export) | — | — | — | ✓ |
| `posture:read` | — | — | — | ✓ |

`GET /me` needs only authentication. The decoy needs nothing.

**ABAC** (inside the services, in addition to RBAC):

- Every repository function takes a `Principal`, never a bare tenant string. The branded `TenantId` type can only be built in `principal.ts`, so a handler *cannot* pass a request-derived tenant.
- **Member** writes need `item.ownerSub === principal.sub`. A mismatch → 403 `FORBIDDEN`. The tenant matches, so a 403 does not reveal existence.
- **Cross-tenant:** GetItem on `{tenantId: principal.tenantId, docId}` simply misses → 404.
- **Agreement gate:** a per-tenant in-memory cache, 60 s TTL, invalidated on acceptance. A catalogue load failure → 503 (fail closed).

---

## 5. Data access

### 5.1 Keys

| Store | Attribute | Format | Source |
|---|---|---|---|
| documents table | `tenantId` | D7 regex | token only |
| | `docId` | `doc#<uuidv7>` | server |
| | | `meta#grc-profile` | constant |
| audit table | `tenantId` | tenant, or `_platform` | token, or constant |
| | `eventKey` | `<YYYY-MM-DDTHH:mm:ss.sssZ>#<requestId>` (one time-ordered event per request) | server |
| | | `AGREEMENT#<agreementId>#<version>` (acceptance marker) | catalogue |
| documents bucket | key | `tenants/<tenantId>/docs/<uuidv7>` | server |
| incidents table (read) | `incidentId` | `^[\w.:-]{1,128}$` | path, validated |
| evidence bucket (read) | key | from the row only; must start `incidents/`, ≤ 1024; the record's `bucket` must equal `EVIDENCE_BUCKET` | row |

### 5.2 Access patterns: all static expressions, never interpolated

| Operation | Call |
|---|---|
| List documents | `Query tenantId = :t AND begins_with(docId, "doc#")`, `ScanIndexForward=false` (UUIDv7 gives newest first), filter `status <> DELETED`, `ExclusiveStartKey = {tenantId: principal, docId: cursor}` |
| Get document | `GetItem {tenantId: principal, docId: "doc#"+id}`; DELETED → 404 |
| Create | `TransactWriteItems [Put doc attribute_not_exists(docId); Put audit attribute_not_exists(eventKey)]` |
| Upload | S3 PutObject first → `Transact [Update doc SET status=AVAILABLE, s3VersionId, updatedAt, version=version+1 IF status=PENDING_UPLOAD AND ownerSub=:sub (member) ; Put audit]`. If the transaction fails, best-effort `DeleteObject`, then 500. |
| Patch | `Update` with a fixed allow-list `#title #description #classification #tags` (ExpressionAttributeNames) `IF status=AVAILABLE [AND version=:ifMatch]` + audit, in one transaction |
| Delete | `Transact [Update SET status=DELETED, deletedAt REMOVE title, description, tags ; Put audit]` → S3 `DeleteObject` |
| Tenant audit | `Query tenantId=:t AND eventKey BETWEEN :fromIso AND :toIso+"~"`. The upper bound starts with a digit, so `AGREEMENT#…` markers are excluded. |
| Acceptance | `Transact [Put marker attribute_not_exists ; Put time-ordered event attribute_not_exists]`; status via `GetItem` on the marker |
| GRC profile | `GetItem` / `Put {tenantId, docId:"meta#grc-profile"}` + audit, in one transaction |

### 5.3 S3, KMS and pre-signing

- `PutObject` sets `{ServerSideEncryption:"aws:kms", SSEKMSKeyId: DATA_KMS_KEY_ARN, ChecksumAlgorithm:"SHA256", ChecksumSHA256, ContentType}`. **No `x-amz-meta-*`** and no user-supplied headers.
- Encryption context: S3-managed (`aws:s3:arn` = the bucket ARN with Bucket Keys, F7).
- `forcePathStyle: true` only in local mode.
- **Pre-sign:** `GetObjectCommand {Bucket, Key, VersionId, ResponseContentDisposition, ResponseContentType}`, with `expiresIn ≤ PRESIGNED_URL_MAX_SECONDS`. The bucket policy enforces the same cap independently.
- `S3_PUBLIC_ENDPOINT` (local only) changes the presigner host; it is forbidden in `aws` mode (D22).
- **Upload checks:** magic bytes. `%PDF-`; PNG `89 50 4E 47 0D 0A 1A 0A`; JPEG `FF D8 FF`; DOCX `PK\x03\x04`; `text/plain` must be valid UTF-8 with no NUL.
- Malware scanning is out of scope: GuardDuty Malware Protection for S3 is paid and off [repo].

### 5.4 Audit event schema (`schemaVersion: "1"`)

```json
{"tenantId": "t-acme-01", "eventKey": "2026-10-16T12:00:00.123Z#0192b3c4-…",
 "schemaVersion": "1", "eventId": "<uuidv4>", "at": "2026-10-16T12:00:00.123Z",
 "action": "DOCUMENT_UPLOADED", "outcome": "SUCCESS",
 "actor": {"type": "user", "sub": "…", "tenantId": "t-acme-01", "groups": ["member"]},
 "resource": {"type": "document", "id": "0192…"},
 "sourceIp": "203.0.113.7", "sourceIpTrusted": true,
 "userAgent": "<≤256 chars, control chars stripped>", "requestId": "0192b3c4-…",
 "details": {"sha256": "…", "sizeBytes": 1024}}
```

- **`action` ∈** `DOCUMENT_CREATED`, `DOCUMENT_UPLOADED`, `DOCUMENT_UPDATED`, `DOCUMENT_DELETED`, `DOCUMENT_DOWNLOAD_URL_ISSUED`, `AGREEMENT_ACCEPTED`, `GRC_PROFILE_UPDATED`, `ACCESS_DENIED` (RBAC/ABAC 403s, at most 10/min per sub), `DECOY_ROUTE_HIT`, `SOC_EVIDENCE_VERIFIED`, `SOC_REPORT_EXPORTED`.
- `details` keys are allow-listed per action; values are ≤ 512 chars.
- The partition is the tenant that owns the resource. Platform resources (incidents, evidence, decoy) → `_platform`.
- FR-2/FR-3/FR-4 mapping (document handling, isolation, audit) [inferred: the plan PDF isn't in the repo]. Every state change plus every download-URL issuance is audited.

---

## 6. Decoy route (D13–D15)

1. **Mounted** at `/admin` (all methods), before authentication. No real route uses `/admin`: tenant administration lives under `/agreements` and `/grc/profile`.
2. **Capture:** method, path and query string, each truncated to 256 characters with control characters stripped; user agent (≤ 256); `sourceIp` + `sourceIpTrusted`; `requestId`. If an `Authorization: Bearer` is present, it is verified with the same verifier. On success, `actor = {sub, tenantId, groups}`; on failure, `actor.type = "anonymous"` and `tokenPresent: true`, with no error surfaced. **No body is read.**
3. **Audit:** a `DECOY_ROUTE_HIT` event in `_platform` (at most 5 per minute per IP, the rest counted in a log line). `details.incidentId` holds the id from step 4.
4. **Publish**, only when all hold:
   - `DECOY_PUBLISH_ENABLED=true`
   - `EDGE_BUS_NAME` is set
   - `sourceIpTrusted`
   - the IP parses
   - not already published for this IP within this hour (per task)
   - global cap of 30/min per task

   Then one `PutEvents` entry, exactly the `app/README.md` contract:
   - `Source: cloudshield.edge`, `DetailType: CloudShield Edge Finding`; `Time` is **not** set.
   - Detail: `id = edge-decoy-<ip non-alphanumerics → "-">-<yyyyMMddHH>`, `type = CloudShield:IPAddress/DecoyRouteHit`, `severity 5`, `createdAt`, `accountId` (`AWS_ACCOUNT_ID` from soar env), `region`, `resource.ipAddressDetails.ipAddressV4|V6`.
   - `service.additionalInfo = {sample: false, publisher: "docs-api-decoy", requestId, authenticated}`. `Finding` ignores extra keys [repo].

   One attempt with SDK default retries. A failure is logged and never changes the response.
5. **Response:** the same 403 problem body as any RBAC denial; no artificial delay.
6. **SOAR outcome** (no router change): RecordDetected → guard → `notify-only edge finding (decoy route hit): analyst review` → `BLOCKED_BY_GUARD` → SNS + ChatOps. The hourly id makes repeats router-level duplicates [repo `RecordDetected`]. Any block is a human decision (runbook `decoy-route.md`).
7. **Abuse:**
   - **Forged viewer header** (via a leaked origin secret, F15): creates notify-only noise and a false audit IP, never a block.
   - **IPv6 rotation flooding:** bounded by the per-task global cap, WAF `SoarApiRateLimit` on `/api/*`, and API Gateway throttling.
   - **Audit-table flooding:** bounded by the per-IP audit cap.

---

## 7. SOC read model (D16–D19)

### 7.1 Queries

| Need | Call |
|---|---|
| Overview | 6 × `Query status-eventTime` (one per status), `ScanIndexForward=false`, `Limit 50`; merge by `eventTime` desc; top 50. Cached 10 s. |
| Filtered list | `Query status=:s` + cursor `{incidentId, status, eventTime}`, each validated |
| Metrics window | per status `Query status=:s AND eventTime >= :since` (key condition, bounded) |
| Detail | `GetItem incidentId` (strongly consistent) |
| Decoy correlation | `Query _platform eventKey BETWEEN hourStart AND hourEnd+"~"` filtered on `details.incidentId = :id` |

### 7.2 `IncidentDetail` projection

An allow-list; strings truncated to 2 KiB:

- `incidentId`, `status`, `displayStatus`: the decoy mapping, and "in progress" for DETECTED.
- `findingType`, `severity`, `resourceType`, `eventTime`, `firstEventTime`, `findingCreatedAt`, `sfnStartedAt`, `containedAt`, `wouldContainAt`, `attempts`.
- `mttcSeconds`: `containedAt − eventTime`, CONTAINED only, exactly as the Python report.
- `triage {scenario, techniques, tactic, impact, eradication[], recovery[]}`.
- `timeline[]`: `DETECTED@eventTime` → `GUARD` (`allowed` / reason) → each `actions[]` entry `{at, playbook, step}` → `CONTAINED@containedAt` / `WOULD_CONTAIN@…` / `FAILED` → evidence steps.
- `guardReason`, `failure`, `evidenceRecords[]`, PB-05 `{blockedCidr, blockState, blockExpiresAt}`, `relatedAudit[]` (decoy only).
- `executionArn` is shown as-is: SOC staff only.

### 7.3 Evidence verification (`soc/evidence.ts`)

For each record (at most 20):

1. Check `record.bucket === EVIDENCE_BUCKET` and that the key starts with `incidents/`.
2. `GetObject {VersionId}`: abort above 5 MiB; `sha256` hex.
3. `ok = actual == recorded && (!sha256Base64 || b64(actual) == sha256Base64)`.
4. `GetObjectRetention` + `GetObjectLegalHold`. `ObjectLockConfigurationNotFoundError` or `InvalidRequest` → `retention: null, lockEnabled: false`.
5. `GetBucketObjectLockConfiguration` once per request → `defaultRetention {mode, days}` or "not enabled".

Output `EvidenceCheck {key, versionId, recordedSha256, actualSha256, ok, error?, retention?{mode, retainUntil}, legalHold?, lockEnabled}`, plus `chainOfCustodyOk` (null / true / false, same semantics as Python). Writes a `SOC_EVIDENCE_VERIFIED` audit event in `_platform`.

### 7.4 Report

`report.ts` builds the `IrReport` JSON with the same field names as Python. It renders Markdown with the same section order: executive summary, incident record, containment actions, evidence. The header reads "Live verification view generated by docs-api; authoritative report: `make ir-report INCIDENT=<id>`".

Response: `Content-Disposition: attachment; filename="ir-<id sanitised to [A-Za-z0-9._-]>.md"`. Writes a `SOC_REPORT_EXPORTED` audit event.

### 7.5 Posture

```json
{"build": {"commit": "<40 hex | local>", "builtAt": "…", "ciRunId": "…",
           "gates": {"secrets": "success", "sast": "success", "sca": "success", "app": "success"},
           "gatesEnforced": true},
 "imagePolicy": "CI pushes to ECR only when Trivy reports no fixable CRITICAL/HIGH vulnerabilities at scan time (audit A9).",
 "image": {"reference": "<repo>@sha256:…", "ecrScan": {"status": "COMPLETE", "critical": 0, "high": 0,
           "completedAt": "…"} | null},
 "containment": {"playbooksEnabled": true, "dryRun": false, "failedLast24h": 0,
                 "lastMttcSeconds": 23.4, "targetSeconds": 60}}
```

- Gate values ∈ {success, failure, skipped, unknown}.
- `build-info.json` is written in the builder stage from validated build args. Non-enum values become `unknown`.

---

## 8. GRC hub

### 8.1 Files: content in Stage 2, schemas in Stage 1

```
app/grc/schema/{ruleset,matrix,agreements,profile}.schema.json
app/grc/rules/2026.10.0.json        # versioned ruleset (semver; new file per revision)
app/grc/matrix/shared-responsibility.json
app/grc/platform-facts.json         # reviewed against Terraform defaults
app/grc/agreements/index.json + dpa-2026-10.txt + sla-2026-10.txt
app/grc/README.md                   # disclaimer, source list, review log, how to add a rule
```

### 8.2 Ruleset schema (summary)

```json
{"schemaVersion": "1", "rulesetId": "cloudshield-grc", "version": "2026.10.0",
 "lastReviewed": "2026-10-16", "disclaimer": "Informational … not legal advice …",
 "jurisdictions": [{"id": "EG", "name": "Egypt", "frameworks": ["EG-PDPL", "EG-CBE"]}],
 "regionCountry": {"us-east-1": "US", "me-central-1": "AE", "me-south-1": "BH", "eu-central-1": "EU"},
 "frameworks": [{"id": "EG-PDPL", "title": "…", "citation": "Law No. 151 of 2020",
                 "regulator": "…", "citationStatus": "doc", "notes": "…"}],
 "rules": [{"id": "EG-PDPL-BREACH-NOTICE", "framework": "EG-PDPL", "topic": "breach-notification",
   "appliesWhen": {"all": [{"fact": "tenant.jurisdictions", "op": "includes", "value": "EG"},
                           {"fact": "tenant.processesPersonalData", "op": "eq", "value": true}]},
   "obligation": "…", "parameters": {"deadlineHours": 72},
   "citations": [{"source": "Law 151/2020", "article": "Art. 7", "status": "verify"}],
   "assessment": {"type": "platform-control" | "customer-action" | "residency" | "info",
                  "metWhen": {…same DSL over platform.*…}, "partialWhen": {…}},
   "controls": ["soar.mttc", "soar.ir-report", "audit.insert-only"],
   "rationale": {"MET": "…", "GAP": "…"}}]}
```

- **Tenant profile:** `{jurisdictions: ("EG"|"EU"|"SA")[1..3], sector ∈ {general, financial, health, government, critical-infrastructure}, cbeRegulated, processesPersonalData, processesSensitiveData, governmentData: bool, dataSubjectRegions: ("EG"|"EU"|"SA"|"OTHER")[]}`.
- **Platform facts:**
  - `deploymentRegions` = `[AWS_REGION]` at runtime
  - `provider: "aws"`, `encryptionAtRest: "kms-cmk"`, `mfa: "totp-required"`, `auditTrail: "insert-only-by-convention"`
  - `incidentAutomation`: from `SOAR_PLAYBOOKS_ENABLED` and the dry-run switch
  - `mttcTargetSeconds: 60`
  - `erasureCompletesWithinDays: 30`
  - `transitInternalHop: "http-over-privatelink"`, said honestly [repo ADR-0004/compute]
- **Operators:** `eq`, `neq`, `in`, `includes`, `includesAny`, `gte`, `lte`, `exists`; combinators `all`, `any`, `not`; depth ≤ 8.
- **Fact paths:** an allow-listed enumeration (`tenant.*`, `platform.*`, `derived.crossBorder`, `derived.residencyCountries`). `derived.crossBorder` = some jurisdiction's country ∉ the deployment-region countries.
- **Finding status** ∈ `MET`, `PARTIAL`, `GAP`, `CUSTOMER_ACTION`, `NOT_APPLICABLE`, `INFO`, plus `citationStatus`.

### 8.3 Seed content outline (Stage 2)

Every item carries its mark. Article numbers marked [verify] must be checked before the demo.

| Framework | Rules (id: content) | Mark |
|---|---|---|
| **EG-PDPL** (Law No. 151 of 2020 [doc]; regulator: Personal Data Protection Center) | `SCOPE-CBE`: data held by the CBE and entities under its supervision is largely excluded; banking law applies instead (Art. 3)<br>`LAWFUL-BASIS-CONSENT` (Art. 6)<br>`BREACH-NOTICE`: notify the PDPC within 72 h; data subjects within a short period after (Art. 7)<br>`DPO` (Art. 8–9)<br>`CROSS-BORDER`: transfer only to an adequate destination, with a licence from the Center (Art. 14–15)<br>`LICENSING`: controller/processor licence or permit<br>`SENSITIVE-DATA`: incl. financial, health and children's data; explicit consent<br>`EXEC-REGS`: status and compliance grace period<br>`RETENTION` | law identity [doc]; **all article content [verify]** |
| **EG-CBE** | `CLOUD-OUTSOURCING-APPROVAL`: prior CBE approval or notification for material cloud outsourcing<br>`DATA-LOCATION-ACCESS`: regulator access, data location<br>`CYBER-FRAMEWORK-INCIDENT`: incident reporting to the CBE<br>`BANKING-SECRECY`: Banking Law No. 194 of 2020 | **all [verify]**: the instrument names and dates are to be identified by the builder from CBE publications; no article numbers until then |
| **EU-GDPR** (Regulation (EU) 2016/679 [doc]) | Art. 5(1)(e) storage limitation · Art. 6 lawful basis · **Art. 7** conditions for consent (demonstrable, withdrawable) · **Art. 17** erasure (→ D10, 30-day version expiry) · Art. 25 by design · **Art. 28** processor contract, incl. 28(3) content and 28(9) electronic form (→ DPA click-through) · Art. 30 records · Art. 32 security (→ KMS, MFA, WAF, SOAR) · **Art. 33** 72 h to the supervisory authority · Art. 34 data subjects · Art. 37 DPO · **Art. 44–46** transfers: SCCs, Commission Implementing Decision (EU) 2021/914; EU–US DPF adequacy decision of 10 Jul 2023 (us-east-1 hosting) | articles [doc]; whether AWS participates in the DPF [verify] |
| **SA-PDPL** (Royal Decree M/19, 1443H [doc]; SDAIA) | `AMENDMENTS-EFFECTIVE`: amended by Royal Decree M/148 (1444H); in force 14 Sep 2023 with a grace period to 14 Sep 2024<br>`BREACH-72H`: notify SDAIA within 72 h (Implementing Regulation)<br>`CROSS-BORDER`: Art. 29 + the Regulation on Personal Data Transfer outside the Kingdom: adequacy or safeguards, risk assessment<br>`DPO` | decree [doc]; **the rest [verify]** |
| **SA-NCA** | `ECC-2:2024`: applicability (government bodies, CNI); IAM, cryptography, logging and monitoring, incident management, third-party/cloud domains<br>`CCC`: Cloud Cybersecurity Controls, data hosting/localisation by classification<br>`GOV-DATA-RESIDENCY`: government data hosted inside KSA (NDMO / Cloud First) | **all [verify]** |

**Residency rules** compare `derived.residencyCountries` with the deployment-region countries. With `us-east-1`, they produce **GAP** with the rationale "deployed in us-east-1 (US); residency in <country> not met — multi-region deployment is out of the capstone scope".

**Shared-responsibility matrix**: rows are CloudShield controls, each with `layer` and, per provider, `{service, responsibility ∈ provider|shared|customer, notes, status}`. Product currency is marked [verify]; cross-cloud equivalence [inferred]:

| Control | AWS (built) | Azure | GCP |
|---|---|---|---|
| Edge WAF + rate limit | WAF on CloudFront | Front Door WAF | Cloud Armor |
| Identity + MFA | Cognito | Entra External ID [verify] | Identity Platform |
| Key management | KMS CMK | Key Vault | Cloud KMS |
| Containers | ECS Fargate | Container Apps | Cloud Run |
| Image scanning | ECR scan + Trivy (CI) | Defender for Containers | Artifact Analysis |
| Threat detection | GuardDuty | Defender for Cloud | Security Command Center |
| SOAR | EventBridge + Step Functions + Lambda | Sentinel + Logic Apps | Google SecOps SOAR / Workflows [verify] |
| Evidence WORM | S3 Object Lock | Immutable Blob (WORM) | Bucket Lock |
| Audit / logs | CloudTrail, VPC Flow Logs, WAF logs | Activity Log, VNet flow logs [verify] | Cloud Audit Logs, VPC Flow Logs |
| Posture | Config / Security Hub | Azure Policy / Defender CSPM | SCC posture |
| Tenant data store | DynamoDB + PITR | Cosmos DB PITR | Firestore PITR |
| Supply chain | GitHub OIDC → ECR | GitHub OIDC → ACR | GitHub OIDC → Artifact Registry |

Plus the generic layers: physical/hypervisor → provider; guest OS → customer (IaaS) or provider (Fargate, Cloud Run, Container Apps); data, identities and configuration → customer, always.

### 8.4 Agreement flow (D25)

1. `index.json` lists `{agreementId: "dpa"|"sla", version: "2026-10", title, file, effectiveDate, required: true}`. At startup the server reads each file as UTF-8 (LF-normalised) and computes `sha256`. The catalogue is served with those hashes, and the text is served as `text/plain`. The SPA renders it as plain text (`whitespace-pre-wrap`), never as HTML.
2. The admin opens `/onboarding`, reads the text, ticks "I confirm I have authority to bind <tenantId> to this agreement", and clicks **Accept**. That sends `{version, sha256, authorityConfirmed: true}`.
3. The server checks:
   - `agreement:accept`
   - the version exists and is current
   - `sha256` equals the server-computed hash. A mismatch → 409 `CONFLICT`, so stale or altered text can't be accepted.
4. A transaction writes:
   - **Marker** `AGREEMENT#dpa#2026-10`: `{agreementId, version, textSha256, textMediaType: "text/plain; charset=utf-8", acceptedBy: {sub, groups}, tenantId, acceptedAt (server UTC ms), sourceIp, sourceIpTrusted, userAgent, requestId, method: "click-through", authorityConfirmed: true, schemaVersion}`
   - **Event** `AGREEMENT_ACCEPTED` (time-ordered)

   Both are `attribute_not_exists`. First acceptance wins; a repeat returns 200 with the existing record.
5. Members and auditors see "Waiting for your tenant administrator to accept…". Document writes answer 403 `AGREEMENT_REQUIRED` until the tenant's status is `complete`.
6. Copy in the UI and the docs: "Recorded as click-through acceptance by an MFA-authenticated user. This is evidence of acceptance, not a qualified or advanced electronic signature. Templates are not legal advice."

---

## 9. Terraform deltas (tests first)

| File | Change | Owner |
|---|---|---|
| `modules/data/main.tf` | `DocumentObjects`: actions `s3:GetObject`, `s3:GetObjectVersion`, `s3:PutObject`, `s3:DeleteObject`; resource narrowed to **`${bucket}/tenants/*`**. Header comment: key layout `tenants/<tenantId>/docs/<docId>`; audit stream "no consumer yet (follow-up)" (F4). | S2 |
| `modules/data/tests/policies.tftest.hcl` (new; real provider + `override_resource`/`override_data`, the `soar/iam` pattern) | App policy:<ul><li>document objects only on `tenants/*`, incl. `GetObjectVersion`</li><li>audit: `PutItem` only for writes (**no `UpdateItem` / `DeleteItem`** on the audit ARN)</li><li>no `s3:*` or `dynamodb:*` wildcards</li><li>the four bucket-policy statements unchanged</li></ul>**Mutation check:** widen the resource to `/*` and confirm the run fails. | S2 |
| `modules/compute/main.tf` | New task-role policy `posture-read`: `ecr:DescribeImages`, `ecr:DescribeImageScanFindings` on `aws_ecr_repository.app.arn` only. | S1 |
| `modules/compute/service.tf` | `environment` = `merge(var.container_environment, {APP_IMAGE = var.container_image, ECR_REPOSITORY_NAME = aws_ecr_repository.app.name})`. The module injects these itself, so dev never references compute's own outputs as compute inputs. | S1 (+ S3) |
| `modules/compute/outputs.tf` | `+ ecr_repository_name` | S1 |
| `modules/compute/tests/task_role.tftest.hcl` (new, real provider) + `compute.tftest.hcl` | ECR read only on the repo ARN. The task-definition env holds `APP_IMAGE` and **never any key in {`CLOUDSHIELD_ENV=local`, `AUTH_LOCAL_ISSUER`, `AUTH_LOCAL_JWKS_URI`, `AWS_ENDPOINT_URL`, `S3_PUBLIC_ENDPOINT`}** (D22), with a test input that tries to pass them through `container_environment`. The module **filters** these keys out and a precondition fails if they are given. | S1 |
| `modules/soar/app-integration.tf` (new) | `count = var.enable_app_integration ? 1 : 0`. `aws_iam_role_policy "app_soc_read"` on `var.app_task_role_name`:<ul><li>`IncidentsRead`: `dynamodb:GetItem` on the table ARN; `dynamodb:Query` on `${table}/index/status-eventTime` **only**</li><li>`EvidenceRead`: `s3:GetObject`, `s3:GetObjectVersion`, `s3:GetObjectRetention`, `s3:GetObjectLegalHold` on `${evidence}/incidents/*`</li><li>`EvidenceLockConfig`: `s3:GetBucketObjectLockConfiguration` on the bucket ARN</li><li>`SoarKeyDecrypt`: `kms:Decrypt` on the SOAR key</li><li>`DryRunSwitch`: `ssm:GetParameter` on the `dry_run` parameter ARN</li><li>dynamic `PublishDecoy` (only `local.enable_pb05 && var.app_publishes_decoy`): `events:PutEvents` on the edge bus ARN with `StringEquals events:source = cloudshield.edge` and `events:detail-type = CloudShield Edge Finding`</li></ul>Preconditions: `app_publishes_decoy ⇒ enable_app_integration`; `enable_app_integration ⇒ app_task_role_name != null`. | S3 (+ S2) |
| `modules/soar/edge-bus.tf` | `pb05_publishers = concat(harvester, var.pb05_publisher_arns, var.app_publishes_decoy ? [var.app_task_role_arn] : [])`. The publisher is derived here so dev can't drift. | S3 |
| `modules/soar/variables.tf` / `outputs.tf` | Vars: `enable_app_integration` (false), `app_task_role_name`, `app_task_role_arn` (role-ARN regex), `app_publishes_decoy` (false).<br>Output `app_environment = {INCIDENTS_TABLE, INCIDENTS_STATUS_INDEX = "status-eventTime", EVIDENCE_BUCKET, SOAR_DRY_RUN_PARAM, SOAR_PLAYBOOKS_ENABLED, EDGE_EVENT_SOURCE, EDGE_BUS_NAME = (enable_pb05 && app_publishes_decoy ? local.edge_bus_name : ""), DECOY_PUBLISH_ENABLED, AWS_ACCOUNT_ID}`. Built from names and locals only (F35). | S3 |
| `modules/soar/tests/app_integration.tftest.hcl` (new, real provider) + `iam.tftest.hcl` (new run) | <ul><li>Absent by default.</li><li>Exact action set and exact resources.</li><li>**No** `dynamodb:Scan`, `PutItem`, `UpdateItem` or `DeleteItem`; no `s3:PutObject`, `s3:Delete*` or `s3:ListBucket`; no `kms:GenerateDataKey*`.</li><li>`Query` only on the index ARN.</li><li>`PutEvents` only with both flags and with both condition keys.</li><li>Bus policy: the Allow list and the `ArnNotEquals` Deny list both contain the task role **iff** `app_publishes_decoy`.</li></ul>Mutation checks: drop the `events:source` condition; widen the evidence prefix. | S3 |
| `modules/edge/api.tf` / `variables.tf` | `enable_decoy_route` (false): resources `admin` (under `api`) and `admin/{proxy+}`; methods `ANY` with authorisation `NONE`; HTTP_PROXY VPC-link integrations → `${backend}/admin` and `${backend}/admin/{proxy}` with `blank_origin_verify`; included in the deployment `triggers`. `#checkov:skip=CKV_AWS_59` / `CKV2_AWS_53` with reason: "decoy route: unauthenticated by design, returns a static 403; every other route requires Cognito". | S1 (+ S2) |
| `modules/edge/tests/edge.tftest.hcl` | Default: no `admin` resources. With the flag: NONE only on the two decoy methods, `{proxy+}` still `COGNITO_USER_POOLS`, origin header blanked, URIs exact. | S1 |
| `environments/dev/main.tf` / `variables.tf` / `outputs.tf` / `terraform.tfvars.example` | `module.soar`: `enable_app_integration = var.container_image != null`, `app_task_role_name/arn = module.compute.task_role_*`, `app_publishes_decoy = var.enable_decoy_publisher && local.enable_api`.<br>`module.edge`: `enable_decoy_route = var.enable_decoy_route`.<br>`module.compute.container_environment = merge(module.data.app_environment, module.identity.app_environment, module.soar.app_environment, {CLOUDSHIELD_ENV = "aws", AWS_REGION = var.aws_region, MAX_UPLOAD_BYTES = "5242880"})`.<br>New vars `enable_decoy_route` (false) and `enable_decoy_publisher` (false; documented as needing `enable_edge` + the package).<br>Output `spa_build_environment = {VITE_COGNITO_USER_POOL_ID, VITE_COGNITO_CLIENT_ID, VITE_AWS_REGION}`. | S1 / S3 banners |

**SOAR code** (S3, Stage 1):

- `core/finding.py`: `+ EDGE_NOTIFY_ONLY_TYPES = frozenset({"CloudShield:IPAddress/DecoyRouteHit"})`. It is **not** in `EDGE_FINDING_TYPES`.
- `core/guard.py` `_ip`: after the source check, a notify-only type → `Decision(False, dry_run, "notify-only edge finding (decoy route hit): analyst review")`.
- New `tools/export_attack_table.py`: a declarative mirror (`prefix` / `contains` matchers + `extraTechniquesWhenContains`), `--out` and `--check`.
- Fixtures `tests/fixtures/{triage_corpus.json, coc_golden.json}`.

**Not changed:** the state machine, PB-05 (it already refuses), the bus rule, `route_choices.json`.

---

## 10. Local compose (`docker-compose.local.yml`) and seed

| Service | Image / build | Hardening | Ports |
|---|---|---|---|
| `moto` | `motoserver/moto:5.2.4@sha256:…` | `read_only`, `tmpfs /tmp`, `cap_drop ALL`, `no-new-privileges`, healthcheck | `127.0.0.1:5000:5000`: the browser follows pre-signed URLs |
| `local-idp` | build `app/local-dev` (target `idp`) | non-root, `read_only`, `cap_drop ALL` | none (nginx proxies it) |
| `seed` | build `app/local-dev` (target `seed`), one-shot | same | none |
| `docs-api` | build context `./app`, `dockerfile: docs-api/Dockerfile`, **the production Dockerfile** | `user 1000:1000`, `read_only`, `tmpfs /tmp`, `cap_drop ALL`, `no-new-privileges` (mirrors the task definition, F11) | none |
| `spa` | build context `./app/spa`, target `local` (nginx-unprivileged by digest [verify tag]) | `read_only`, tmpfs for the nginx cache/run directories | `127.0.0.1:3000:8080` |

- **Ordering:** `depends_on`: `seed` waits for `moto` healthy; `docs-api` waits for `seed` `service_completed_successfully` and `local-idp` healthy; `spa` waits for `docs-api`.
- **docs-api env:**
  - `CLOUDSHIELD_ENV=local`, `AWS_ENDPOINT_URL=http://moto:5000`, `S3_PUBLIC_ENDPOINT=http://localhost:5000`
  - `AUTH_LOCAL_ISSUER=http://local-idp:9000`, `AUTH_LOCAL_JWKS_URI=http://local-idp:9000/.well-known/jwks.json`, `COGNITO_CLIENT_ID=cloudshield-local-spa`
  - `AWS_ACCESS_KEY_ID=local-only`, `AWS_SECRET_ACCESS_KEY=local-only` (not key-shaped, so Gitleaks-safe [inferred])
  - names prefixed `cloudshield-local-*`; `DECOY_PUBLISH_ENABLED=true`, `EDGE_BUS_NAME=cloudshield-local-soar-edge`
- **nginx** (`app/spa/nginx/default.conf`):
  - `location /api/ { proxy_pass http://docs-api:3000/; proxy_set_header CloudFront-Viewer-Address $remote_addr:$remote_port; }`. This **overwrites** any client value and strips `/api` like API Gateway.
  - `location /local-idp/ { proxy_pass http://local-idp:9000/; }`
  - SPA fallback to `index.html` for extension-less URIs.
  - The same four ZAP headers as CloudFront, with CSP `connect-src 'self'`.
- **local-idp:**
  - Generates an RSA-2048 key at boot, in memory only; no file, so nothing for Gitleaks or `.gitignore`.
  - `GET /.well-known/jwks.json`; `GET /users` (demo users, no secrets); `POST /token {username}` → an ID token (1 h) with `iss`, `aud`, `token_use: "id"`, `sub`, `email`, `custom:tenant_id`, `cognito:groups`, `auth_time`, `iat`, `exp`, `jti`.
  - Refuses to start unless `CLOUDSHIELD_ENV=local`.
- **Seed** (idempotent create-if-missing):
  - **Refuses unless the endpoint host ∈ the D22 allow-list** (exit 2): it can never seed real AWS.
  - Tables with the Terraform key schemas, including the `status-eventTime` GSI.
  - Buckets: documents (versioned); evidence (Object Lock on, default GOVERNANCE, 1 day).
  - KMS key, bus, SSM `dry_run = "true"`.
  - Data:

| Kind | Content |
|---|---|
| Tenants and users (`app/local-dev/fixtures/users.json`) | `t-acme-01` (EU+EG): alice (admin), bob (member), carol (auditor) · `t-nile-02` (EG, `cbeRegulated`): dina (admin), mallory (member, the IDOR demo) · `t-riyadh-03` (SA, government): omar (admin) · `t-cloudshield-soc`: sam (secops-analyst) |
| Documents | 2–3 per tenant (small text/PDF), real SHA-256 |
| Audit | a few events per tenant; acme has **accepted** DPA + SLA; nile and riyadh are **pending** |
| GRC | acme and nile have profiles; riyadh has none, which shows onboarding |
| Incidents (≈ 12, times relative to seed time) | A CONTAINED (MTTC 18 s, intact evidence, locked) · A-recon CONTAINED · B CONTAINED · C CONTAINED with **one tampered evidence object** (BROKEN) · D WOULD_CONTAIN_DRY_RUN · E CONTAINED (`blockState: active`) · decoy BLOCKED_BY_GUARD (notify-only reason) + its `_platform` audit · FAILED · NO_PLAYBOOK_ANALYST_REVIEW · DETECTED (in progress) |

---

## 11. Dockerfiles and CI deltas

**`app/docs-api/Dockerfile`** (context `app/`):

- **Build stage:** `node:24-bookworm-slim@sha256:…`
  - `COPY docs-api/package*.json docs-api/.npmrc`, then `npm ci --ignore-scripts`
  - copy `src`, `tsconfig`, `openapi.yaml`, `grc/`; `npm run build`
  - `npm prune --omit=dev`
  - `node scripts/write-build-info.mjs`, with `ARG GIT_SHA`, `BUILD_TIME`, `GATE_SECRETS`, `GATE_SAST`, `GATE_SCA`, `GATE_APP`, `GATES_ENFORCED` (enum-validated)
- **Runtime stage:** `gcr.io/distroless/nodejs24-debian12:nonroot@sha256:…` [verify the tag exists; fallback `node:24-alpine@sha256` + `USER node`]
  - copy `dist`, prod `node_modules`, `openapi.yaml`, `grc/`, `build-info.json`, owned by root and read-only
  - `ENV NODE_ENV=production CLOUDSHIELD_ENV=aws`
  - `USER 1000:1000`, `EXPOSE 3000`
  - `HEALTHCHECK CMD ["/nodejs/bin/node","dist/healthcheck.js"]` (ECS ignores it; Checkov CKV_DOCKER_2 wants it)
  - `CMD ["dist/server.js"]`
  - No npm at runtime (npm writes to `$HOME`).
- `--platform linux/amd64`.

**`.github/workflows/ci.yml`:**

1. `env`: `IMAGE_CONTEXT: ${{ vars.IMAGE_CONTEXT || 'app' }}`, `NODE_VERSION_FILE: app/.nvmrc`, `HADOLINT_IMAGE: hadolint/hadolint:<ver>@sha256:…` [verify], `MOTO_IMAGE` (digest).
2. **New job `app`**, "gate: app (lint + typecheck + test + build)". It always hard-fails and exports `result`.
   - `services.moto` (image by digest, port 5000, health options).
   - `actions/setup-node@<sha>` with an npm cache over the three lockfiles.
   - **docs-api:** `npm ci`; `lint`; `typecheck`; `openapi:check` (spec valid + generated types identical); `test -- --coverage` with `MOTO_ENDPOINT=http://localhost:5000`.
   - **spa:** `npm ci`; `lint`; `typecheck`; `vitest run --coverage`; `build` with `VITE_AUTH_MODE=cognito` and placeholder ids; then `! grep -R "local-idp" dist/`.
   - **local-dev:** `npm ci`; `lint`; `typecheck`; `test`.
   - hadolint on all three Dockerfiles; `docker compose -f docker-compose.local.yml config -q`.
3. **`soar` job:** add `python -m tools.export_attack_table --check ../app/docs-api/src/soc/attack-table.generated.json`.
4. **`sast`:** add `--config p/typescript --config p/react` [verify names]; same change in the Makefile.
5. **`iac`:** second Checkov command, `checkov -d app --framework dockerfile --quiet --compact` (same fail-open step).
6. **`image`:**
   - `needs: [secrets, sast, sca, app]`
   - build `docker build --pull --platform linux/amd64 -f "$APP_DIR/Dockerfile" --build-arg GIT_SHA=$GITHUB_SHA --build-arg GATE_*=${{ needs.*.outputs.scan / needs.app.result }} … "$IMAGE_CONTEXT"`
   - push condition `+ needs.app.result == 'success'`
7. **Optional job `app-smoke`** (not a required check at first): `make local-up local-smoke local-down`.

**Other files:**

- `.github/dependabot.yml`: npm × 3 and docker × 3 directories; the `docker-compose` ecosystem [verify support].
- `.hadolint.yaml`: failure threshold `warning`; trusted registries `docker.io`, `gcr.io`.
- **Makefile:** `app-lint app-test app-build dockerlint local-up local-down local-seed local-smoke`; `scan +=` app targets; `sca` skips `**/node_modules`.
- `scripts/gate-selftest.sh`: new `dockerfile` seed (`FROM node:latest` + `USER root` → hadolint DL3007 / Checkov CKV_DOCKER_3).

---

## 12. SPA design (`app/spa`)

- **Routes:** `/login`; `/` (portal home); `/documents`; `/documents/:id`; `/audit`; `/onboarding`; `/grc`; `/grc/matrix`; `/soc`; `/soc/incidents/:id`.
- **`RoleGuard`** reads `GET /me` permissions. This is UX only; the server enforces.
- **Auth:**
  - `VITE_AUTH_MODE=cognito`: Amplify `signIn` (SRP), TOTP challenge, `fetchAuthSession().tokens.idToken`, `sessionStorage`. `signOut({global: true})`.
  - `local`: a user picker against `/local-idp`. The branch is statically eliminated in cognito builds; CI greps the bundle to prove it.
- **`apiClient`:** attaches `Authorization: Bearer <idToken>` and parses problem+json. On 401 it re-authenticates; on 403 `AGREEMENT_REQUIRED` it routes to `/onboarding`.
- **SOC components:**
  - `PostureBanner`: the exact D18 wording; never "no vulnerabilities" when `ecrScan` is null; shows a "local build" state.
  - `IncidentsTable`: status chips with text (not colour alone); decoy and in-progress labels; filter by status.
  - `MttcMeter`: SVG gauge 0–120 s with a 60 s target line; p50/p90/last; an `aria-label` sentence.
  - `MitreBreakdown`: SVG bars per tactic with technique ids.
  - `SoarTimeline`: steps for every status, including PB-01..PB-05 actions.
  - `EvidencePanel`: recorded vs recomputed hashes in monospace with copy; ✓/✗; Object Lock mode and retain-until, or "Object Lock not enabled on the evidence bucket"; legal hold; **IR report download**: fetch with bearer → Blob → `<a download>`. Markdown is never rendered.
- **Polling:** `usePolling(15 s)` (D19).
- **Portal and GRC:**
  - `DocumentsPage`: upload in two steps, computing SHA-256 with `crypto.subtle`; download by navigating to the pre-signed URL.
  - `AuditPage`, `OnboardingPage` (plain-text agreement, authority checkbox, Accept for admin only), `GrcHub` (profile form, assessment grouped by framework, status and `verify` badges, **the disclaimer always visible**), `ResponsibilityMatrix`.

---

## 13. Test matrix (written before the code)

| Suite | Kind | Cases |
|---|---|---|
| `docs-api/test/config.test.ts` | Jest unit | Default `aws` mode. Cognito issuer regex and pool-id match. **Startup throws** when: `aws` mode has `AUTH_LOCAL_*`, `AWS_ENDPOINT_URL` or `S3_PUBLIC_ENDPOINT`; `local` mode lacks `AWS_ENDPOINT_URL`; `local` points at a non-allow-listed host (e.g. `https://dynamodb.us-east-1.amazonaws.com`, `http://moto.evil`); the issuer isn't https in `aws` mode. |
| `auth.test.ts` | Jest unit; `CognitoJwtVerifier.cacheJwks` + jose-signed tokens; offline | Valid ID token → principal. 401 for: wrong `aud` (another client); wrong `iss`; `token_use=access`; expired; `alg: none`; HS256 signed with the public key; unknown `kid`; tampered payload; **a local-idp-style token (`iss http://local-idp:9000`) against the prod config**; a token signed by a different key with the correct `iss`. Tenant: missing / invalid format / `_platform` → 403 `TENANT_INVALID`. Groups: unknown ignored; union; none → only `/me`. Never logs the token (pino destination capture). |
| `rbac.test.ts` | Jest | **The whole §4.2 matrix as a table-driven test**: every route × every group → the expected 2xx/403. secops-analyst gets 403 on every document route. |
| `documents.int.test.ts` | Jest + **moto** | CRUD happy path; transaction writes doc + audit together. **IDOR:** mallory (`t-nile-02`) reads, patches, deletes and downloads an acme doc id → 404, and the acme item is unchanged. Cross-tenant cursor (another tenant's `docId` in the cursor) still returns only own items. Member editing another member's doc → 403. Auditor writes → 403. Upload: declared ≠ actual SHA → 422 and no item flip; bad magic bytes → 415; > MAX → 413; S3 key is exactly `tenants/<t>/docs/<id>`; `SSEKMSKeyId` = the configured ARN. Pre-sign: `X-Amz-Expires ≤ max`, `VersionId` present, disposition `attachment` with an encoded file name (CRLF / quotes / unicode). Delete → tombstone fields cleared, delete marker present. Agreement gate: nile writes → 403 `AGREEMENT_REQUIRED`; acme OK. |
| `injection.test.ts` | Jest | `?limit[$gt]=` / `?status[$ne]=` → 400 (simple parser + validator). Body extra props → 400. `docId` with `../`, `#`, `%2F` → 400. Tags/title with `${}`, `:`, `#` are stored literally (expressions use placeholders: a spy on the SDK command asserts no user text in `UpdateExpression`). Header injection in the file name → sanitised. Prototype pollution `{"__proto__":…}` → 400. |
| `audit.int.test.ts` | Jest + moto | `attribute_not_exists` is always sent; a duplicate `eventKey` → no overwrite (ConditionalCheckFailed surfaced as 500, never silently swallowed); tenant query excludes `AGREEMENT#` markers; `_platform` is unreachable through `/audit`; schema shape matches §5.4; `ACCESS_DENIED` rate cap. |
| `agreements.int.test.ts` | Jest + moto | Only admin can accept; stale `sha256` → 409; unknown version → 404; first acceptance wins and a repeat returns 200 with the same record; the marker holds every §8.4 field; catalogue load failure → 503 on gated routes. |
| `grc.test.ts` | Jest unit | Ruleset schema rejects unknown operators, depth > 8, `__proto__`/`constructor` fact paths, unknown fact paths; an invalid ruleset → 503; deterministic output and sha256; residency GAP for EG/SA with `us-east-1`; `cbeRegulated` → EG-PDPL scope note; every finding carries `citationStatus`; the disclaimer is always present. |
| `decoy.test.ts` | Jest (unit + moto EventBridge) | Fires with no token, a valid token (actor recorded) and an invalid token (anonymous, `tokenPresent`); response identical to a real 403; **exact event shape** vs `app/README.md` (no `Time`; id regex; v4/v6 field; IPv4-mapped → v4); not published when untrusted IP / no bus / flag off / same IP and hour / global cap hit; `X-Forwarded-For` ignored; audit cap 5/min per IP; a PutEvents failure doesn't change the response. |
| `soc.int.test.ts` | Jest + moto | Overview merges six status queries (spy: **no Scan** command ever sent); filtered pagination; projection allow-list (no unknown attributes leak); decoy `displayStatus`; MTTC = Python formula, dry-run excluded. **Golden parity** (`soar/tests/fixtures/coc_golden.json`): intact, tampered, missing object, base64 mismatch, versioned, not contained → identical `evidence[]`, `chain_of_custody_ok`, `mttc_seconds`. A record naming another bucket or a key outside `incidents/` → error, no `GetObject` issued. > 20 records / > 5 MiB handled. Object Lock on/off. Report Markdown has no raw HTML passthrough. Triage(TS) == Python for the corpus. Non-secops → 403 on every `/soc/*`. |
| `posture.test.ts` | Jest | `build-info` enum validation; ECR unavailable → `ecrScan: null` (the wording test lives in the SPA); digest parsed only from a valid `APP_IMAGE`. |
| `security-headers.test.ts` / `errors.test.ts` | Jest + supertest | helmet set + `no-store` + `X-Request-Id` on 2xx/4xx/5xx; no `X-Powered-By`; a 500 body has only `code` + `requestId` (a thrown AWS error with an ARN is not echoed); a JSON `SyntaxError` → 400 generic; responses validated against the spec (`validateResponses`). |
| `server.test.ts` | Jest | SIGTERM closes within 1.5 s. |
| `app/docs-api/test/grc-content.test.ts` (Stage 2) | Jest | The real ruleset, matrix, agreements and platform facts validate against the schemas; every rule has ≥ 1 citation; every citation not about GDPR articles is `verify` unless its id is in a reviewed allow-list; the agreement hashes are stable. |
| SPA (Vitest + RTL) | component | `PostureBanner` (all three gate states, null scan never "clean", local build); `MttcMeter` thresholds + aria; `IncidentsTable` (sorting, filter, decoy and in-progress labels, text not colour-only); `SoarTimeline` per status; `EvidencePanel` (BROKEN, lock off/on, full-hash expand, report download calls the API with bearer); `OnboardingPage` (Accept only for admin; sends version + sha256 + authority; member waiting text); `GrcHub` (disclaimer always rendered; verify badges); `RoleGuard`; `apiClient` (bearer, problem+json, 401 refresh, 403 `AGREEMENT_REQUIRED` redirect); **no `dangerouslySetInnerHTML`** (ESLint) and the cognito build excludes the local branch. |
| `app/local-dev` | Jest | The seed refuses non-local endpoints (exit 2); idempotent re-run; the IdP refuses to start without `CLOUDSHIELD_ENV=local`; token claims are exactly the Cognito shape. |
| `soar/tests/test_guard.py` (+) | pytest | `DecoyRouteHit` → `allowed False` with the notify-only reason, even with a fresh, global, non-never-blocked IP; never in `EDGE_FINDING_TYPES`; exact `bool` types. |
| `soar/tests/test_pb05.py` (+) | pytest | PB-05 invoked directly with a decoy event and a forged `allowed` decision → refused, no WAF call. |
| `soar/tests/test_export_attack_table.py` (new) | pytest | The declarative mirror == `triage()` for the corpus (all scenario types, edge types, `CryptoCurrency`, unknown, None); `--check` detects drift; output deterministic. |
| `soar/tests/test_ir_golden.py` (new) | pytest + moto | `build_report` output for each golden case == the committed `coc_golden.json`. |
| Terraform | `terraform test` | `data/policies`, `compute/task_role` + `compute`, `soar/app_integration` + `iam`, `edge` (§9). All existing suites stay green. |

---

## 14. Quality gates (Validator)

- **docs-api:** ESLint (typescript-eslint strict + `eslint-plugin-security`) clean; `tsc --noEmit`; **Jest coverage ≥ 90 % lines / statements / functions and ≥ 85 % branches**; OpenAPI valid; generated types without drift.
- **SPA:** ESLint (+ `react/no-danger: error`), `tsc`, Vitest coverage ≥ 80 %, `vite build`, bundle contains no `local-idp`.
- **local-dev:** lint, `tsc`, tests.
- **Dockerfiles:** hadolint 0 at `warning`; Checkov dockerfile 0 failed.
- **Images:** Trivy image on docs-api: 0 fixable CRITICAL/HIGH at scan time; if a base digest has any, bump the digest.
- **Repo-wide scanners:** Trivy fs 0 fixable CRITICAL, with all three lockfiles committed; Semgrep ERROR 0, including `p/typescript` and `p/react`; Gitleaks 0 over the full history.
- **Terraform:** `fmt` clean; `validate` in bootstrap, dev and all 10 modules; `terraform test` all green; Checkov (terraform) 0 failed, every new skip with a reason.
- **SOAR:** ruff clean; pytest ≥ 95 %; Lambda zip still deterministic (no new packaged code; `tools/` isn't shipped).
- **CI and compose:** actionlint clean; `docker compose config` valid; `make local-smoke` passes locally:
  1. `/api/healthz`
  2. mint alice → list docs
  3. mallory → acme doc 404
  4. decoy hit → `_platform` audit + bus event in moto
  5. sam → `/soc/overview` shows the BROKEN chain on scenario C

---

## 15. Cost (lab, us-east-1)

| Item | Cost | Default |
|---|---|---|
| New IAM policies, API Gateway decoy resources | free | decoy off |
| EventBridge custom events (decoy) | $1.00 per million | with `enable_decoy_publisher` |
| DynamoDB on-demand reads for SOC polling (≈ 6 queries per 15 s per open dashboard, server-cached 10 s) | cents per month | with the service |
| S3 GET (evidence verification, pre-signed downloads), KMS requests ($0.03 / 10k) | cents | with the service |
| ECR `DescribeImageScanFindings` | free | with the service |
| Local stack (moto, Apache-2.0 [verify]) | $0; no LocalStack licence needed | local |
| Follow-up WAF decoy rule (D13) | about $1/month | **not built** |

**Net Phase E fixed cost: about $0/month** on top of Phase D.

---

## 16. Verify on the first apply ([inferred] items)

1. HTTP_PROXY passes `CloudFront-Viewer-Address` to the container. Check its IPv6 format, and that a viewer-supplied header of that name is overwritten by CloudFront (F15).
2. With `enable_decoy_route`: `/api/admin/x` (no token) reaches the app (NONE beats `{proxy+}` [inferred]), while `/api/documents` with no token is still 401.
3. The task role publishes with the `events:source` / `events:detail-type` conditions; the bus Deny doesn't catch it; the router records `BLOCKED_BY_GUARD` with the notify-only reason; SNS email and ChatOps arrive.
4. GSI `Query` and `GetItem` on the SOAR-CMK incidents table with only `kms:Decrypt`.
5. Evidence: `GetObject` with `VersionId` (`GetObjectVersion`); `GetObjectRetention` / `GetObjectLegalHold` error codes with Object Lock off and on; `GetBucketObjectLockConfiguration` when off.
6. Pre-signed GET with SSE-KMS + `VersionId` + `ResponseContentDisposition` downloads in a browser under the 300 s `signatureAge` cap and the role-session expiry.
7. `PutObject` with `SSEKMSKeyId` = the full ARN + `ChecksumSHA256` passes `DenyForeignKmsKey` with Bucket Keys on.
8. ECR `DescribeImageScanFindings` on the KMS-encrypted repo works with no KMS grant.
9. The distroless (or alpine) image runs as `1000:1000` with a read-only rootfs and `/tmp`; the NLB health check is green; SIGTERM exit < 2 s.
10. First-request JWKS fetch to `cognito-idp` through NAT; latency acceptable.
11. `TransactWriteItems` across the documents and audit tables with the existing IAM.
12. SPA: Amplify SRP + TOTP under the CloudFront CSP (`connect-src` cognito-idp only); `sessionStorage`; blob download of the IR report.
13. ZAP baseline still passes on `STAGING_URL`.
14. CloudTrail data events show the task role's evidence `GetObject` calls (the chain-of-custody access trail).
15. `GET /soc/posture` shows the build gates for the deployed commit, and an ECR scan result for the running digest.

---

## 17. Builder order: 3 sequential stages, disjoint files

**Step 0 (before Stage 1; record the outcomes in "Deviations" in ADR-0006):**

1. moto 5.2.4 server: GSI Query, Object Lock retention/legal hold, EventBridge custom-bus PutEvents, SSM, KMS. If anything is missing, use `aws-sdk-client-mock` for that case and note it.
2. Whether `aws-jwt-verify`'s generic verifier accepts an `http://` JWKS URI. If not, local mode uses `jose.createRemoteJWKSet`; production stays `CognitoJwtVerifier`.
3. That the distroless `nodejs24` tag exists, and its digest; otherwise the alpine fallback.
4. Node 24 latest patch.
5. hadolint version and digest; the names `p/typescript` and `p/react`; Dependabot `docker-compose` ecosystem support.
6. Amplify v6 `sessionStorage` API.

### Stage 1: backend, Terraform, SOAR touchpoints (S2 lead; S1/S3 review)

**Files:**
- `app/.nvmrc`, `app/openapi.yaml`
- `app/docs-api/**` (except `test/grc-content.test.ts`), including `Dockerfile`, `Dockerfile.dockerignore`, `.npmrc`, `scripts/write-build-info.mjs` and `src/soc/attack-table.generated.json`
- `app/grc/schema/*.schema.json`
- `infra/terraform/modules/data/{main.tf, tests/policies.tftest.hcl}`
- `infra/terraform/modules/compute/{main.tf, service.tf, outputs.tf, tests/task_role.tftest.hcl, tests/compute.tftest.hcl}`
- `infra/terraform/modules/soar/{app-integration.tf, edge-bus.tf, variables.tf, outputs.tf, tests/app_integration.tftest.hcl, tests/iam.tftest.hcl}`
- `infra/terraform/modules/edge/{api.tf, variables.tf, tests/edge.tftest.hcl}`
- `infra/terraform/environments/dev/{main.tf, variables.tf, outputs.tf, terraform.tfvars.example}`
- `soar/core/{finding.py, guard.py}`, `soar/tools/export_attack_table.py`, `soar/tests/{test_guard.py, test_pb05.py, test_export_attack_table.py, test_ir_golden.py, fixtures/triage_corpus.json, fixtures/coc_golden.json}`

**Order:**
1. Terraform tests → modules → dev wiring → fmt / validate / test / Checkov.
2. SOAR guard tests → guard → export tool + golden fixtures → pytest ≥ 95 %.
3. `openapi.yaml` → generated types.
4. docs-api, in order: config + auth (tests first) → RBAC matrix test → documents/audit (moto) → agreements → GRC engine (fixture rulesets) → decoy → SOC/posture.
5. Dockerfile + Trivy + hadolint.

**Exit:** all §14 items for these files are green.

### Stage 2: SPA, GRC content, agreements (S2)

**Files:**
- `app/spa/**` except `Dockerfile`, `Dockerfile.dockerignore` and `nginx/`
- `app/grc/{rules/2026.10.0.json, matrix/shared-responsibility.json, platform-facts.json, agreements/index.json, agreements/dpa-2026-10.txt, agreements/sla-2026-10.txt, README.md}`
- `app/docs-api/test/grc-content.test.ts`

**Order:** generated client types → `apiClient` + auth (both modes) → RoleGuard → SOC components (tests first) → portal → onboarding → GRC hub → GRC content with every citation marked → content test → `vite build` + bundle check.

### Stage 3: local compose, CI, docs (S2 + S1)

**Files:**
- `docker-compose.local.yml`, `app/local-dev/**`, `app/spa/{Dockerfile, Dockerfile.dockerignore, nginx/default.conf}`, `.hadolint.yaml`
- `.github/{workflows/ci.yml, dependabot.yml, CODEOWNERS}`, `Makefile`, `scripts/gate-selftest.sh`
- `README.md` (layout, flags `enable_decoy_route` / `enable_decoy_publisher`, Phase E costs, local quick start), `app/README.md` (layout, D2 context, decoy now notify-only, local mode)
- `docs/HANDOFF.md` §13
- **New** `docs/adr/0006-app-soc-grc-local.md` (D1–D28, the deviations, residual risks D13/D16/D22, follow-ups)
- `docs/adr/0005-*.md` (amendment: `DecoyRouteHit` notify-only), `docs/adr/0002-*.md` §5 (SOC read path; the app role reads TB5)
- `soar/README.md` (guard notify-only types)
- `docs/runbooks/{local-dev.md, spa-deploy.md, decoy-route.md}` (new); `tenant-provisioning.md` (tenant-id format D7, onboarding D26); `repo-admin-setup.md` (`IMAGE_CONTEXT`, required check `gate: app`)

**CODEOWNERS additions:**

```
/app/docs-api/src/soc/                         @YasseenAbdelghany @ahklsfg
/app/docs-api/src/decoy/                       @YasseenAbdelghany @ahklsfg
/app/docs-api/src/auth/                        @YasseenAbdelghany @ELSHAHALY
/app/docs-api/Dockerfile                       @YasseenAbdelghany @ELSHAHALY
/app/grc/                                      @YasseenAbdelghany @ahklsfg
/docker-compose.local.yml                      @YasseenAbdelghany @ELSHAHALY
/infra/terraform/modules/soar/app-integration.tf  @ahklsfg @YasseenAbdelghany
```

**Follow-ups recorded, not built:**
- the WAF-corroborated decoy block (D13);
- an audit-stream tamper consumer (F4);
- per-request STS session tags with `dynamodb:LeadingKeys` (ADR-0002 §5);
- a separate SOC read service in the Security account (D16);
- GuardDuty Malware Protection for uploads;
- a sim for the decoy (S3).

---

## 18. Independent Auditor focus, Validator, PR

**Auditor** (a fresh agent):

- **Tenant leakage / IDOR:**
  - Any repository path taking a tenant from the request?
  - Cursors rebuilt with the token's tenant?
  - 404 vs 403 consistency?
  - `_platform` reachable by tenants?
  - The SOC projection leaking tenant data?
  - Shared caches holding tenant data?
- **Authz bypass:** routes missing `requirePermission`; the decoy router or `/healthz` mounted so later routes skip auth; owner checks on upload, patch and delete; the agreement gate on every write; group union surprises.
- **Local-auth bypass in production:**
  - Can any env combination make the `aws`-mode verifier accept a non-Cognito issuer?
  - Is `AWS_ENDPOINT_URL` coupling enforced?
  - Does Terraform filter the forbidden env keys?
  - Does the local IdP or seed ship in the production image (inspect the layers)?
  - Is the SPA local branch eliminated?
- **Injection:**
  - NoSQL: expression construction, `qs` objects, type confusion.
  - Path traversal in S3 keys and evidence keys.
  - Header / Content-Disposition injection.
  - Markdown or agreement text rendered as HTML.
  - Prototype pollution in the GRC DSL; ReDoS.
- **SSRF:** any user-influenced URL (JWKS, evidence bucket or key from the row, S3 public endpoint, ECR digest); `X-Forwarded-For` usage.
- **Decoy abuse:**
  - Can a decoy hit ever cause a WAF block?
  - Guard and PB-05 refusal of `DecoyRouteHit`.
  - Viewer-IP spoofing via a leaked origin secret.
  - Publish and audit flood caps.
  - Event shape vs contract.
  - Least privilege of `PutEvents` (conditions).
- **Least privilege:**
  - `app-integration.tf` exactly as specified (no Scan, writes or GenerateDataKey).
  - Data policy narrowed to `tenants/*`.
  - ECR read on one repo.
  - Bus publisher list derivation.
- **Secrets in images and logs:** tokens, `x-origin-verify`, viewer address in logs; build args; `.npmrc`; local-idp keys; Gitleaks; Trivy secret scan of the image.
- **Chain of custody:** TS verification parity with Python (golden tests really exercise mismatch cases); foreign-bucket and prefix refusal; honest Object Lock status; posture wording never over-claims.
- **Supply chain:** lockfiles committed; `--ignore-scripts`; exact versions; digest-pinned base, moto and hadolint images; setup-node SHA; Dependabot coverage; image push gated on `app`.
- **GRC honesty:** every non-GDPR legal claim marked `verify`; disclaimer always rendered; acceptance described as logging, not e-signature; "insert-only by convention", never "immutable".

**Validator:** run every item of §14, push, and open **PR #4** (base `feat/s1-s2-edge-identity-waf`; merge order #1 → #2 → #3 → #4). The PR body lists the verify-on-apply items (§16) and the [verify] legal items still open.
