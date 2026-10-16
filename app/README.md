# app/ — S2 (App / Identity)

Multi-tenant document API and portal (plan §10).

| Path | What goes here |
|---|---|
| `docs-api/` | Node.js / Express API. **Needs a `Dockerfile` here**: the CI image gate builds `app/docs-api/Dockerfile` (override with the repo variable `APP_DIR`). |
| `spa/` | React SPA (customer portal + SecOps SOC dashboard, plan §8.8). |
| `openapi.yaml` | Contract-first API spec. **Day 4–8 deliverable**: S1 (API Gateway) and S3 (audit events, FR-4) build against it in parallel. |

Container rules the pipeline and design expect:

- Non-root user, read-only root filesystem (plan §4.3), and no secrets baked in.
- A `/healthz` endpoint (Section 7 of the runbook curls it).
- Every state-changing request writes an audit event with actor, action, resource, source IP, request ID and UTC time (FR-4).

## Identity and request contract (Phase D, S2, ADR-0004 D5)

The edge is built (`modules/edge`, `modules/identity`). The API runs behind CloudFront → regional WAF → REST API Gateway (Cognito authorizer) → VPC Link → NLB → the docs-api task. The container receives `COGNITO_USER_POOL_ID`, `COGNITO_CLIENT_ID` and `COGNITO_ISSUER` (`module.identity.app_environment`).

**Token contract (plan F8).** The SPA signs in with SRP and sends the Cognito **ID token** as `Authorization: Bearer <jwt>`. The API Gateway authorizer checks the signature, issuer and expiry, but is believed **not** to check `aud` for ID tokens [inferred]. So docs-api must re-verify every request itself, against the pool's JWKS:

- signature (RS256, key from `<COGNITO_ISSUER>/.well-known/jwks.json`), `exp`;
- `iss == COGNITO_ISSUER`;
- `aud == COGNITO_CLIENT_ID` (rejects tokens minted for any other client of the pool);
- `token_use == "id"` (rejects access tokens, which carry no custom attributes).

Reject with 401 on any failure; never fall back to an unverified decode.

**Tenant.** The tenant comes **only** from the verified `custom:tenant_id` claim. Never from a header, path, query or body value, and never from a field a user can edit: the attribute is immutable and is not in the client's `write_attributes`, so users cannot change it. A request naming another tenant's resource is a 404, not a 403.

**RBAC.** From the verified `cognito:groups` claim only: `admin`, `member`, `auditor` (read-only, including the audit trail) and `secops-analyst` (the SOC dashboard, plan §8.8). The groups carry no IAM roles; enforcement is in the API.

**Audit source IP (FR-4).** Behind CloudFront, the TCP peer is CloudFront and `X-Forwarded-For` is client-controlled (F3). Take `sourceIp` from the `CloudFront-Viewer-Address` header (`<ip>:<port>`; strip the port) [inferred: forwarded by the Managed-AllViewerExceptHostHeader origin request policy; verify on the first apply, ADR-0004]. Treat any other forwarded header as untrusted.

**Origin header.** CloudFront adds `x-origin-verify`; API Gateway blanks it before the backend. docs-api must never log or echo it (it is a WAF bypass deterrent, not authentication).

## Phase E: PB-05 publisher contract (docs-api decoy route)

A decoy route that only an attacker would call may ask PB-05 to block the caller. docs-api becomes a publisher on the dedicated bus. SOAR needs two changes too (ADR-0005, audit A1): the new type must be added to the edge allow-list (`EDGE_FINDING_TYPES` in `soar/core/finding.py`), and PB-05 needs a **corroboration** check for it that reads a source the caller cannot write (for example the decoy route's own WAF rule metrics or a WAF label match in the logs). Until both exist, the guard and PB-05 refuse the type.

1. Add the docs-api **task-role ARN** to `pb05_publisher_arns` (modules/soar). The bus policy explicitly denies `events:PutEvents` to every principal not on that list. Grant the task role `events:PutEvents` on the bus ARN (output `edge_event_bus_arn`) only.
2. Put **one** event per hit on the bus named by output `edge_event_bus_name`:
   - `Source`: `cloudshield.edge`; `DetailType`: `CloudShield Edge Finding`;
   - **do not set `Time`**: EventBridge stamps it, and the guard refuses events older than 15 min or more than 60 s in the future;
   - `Detail` (JSON):

   ```json
   {"schemaVersion": "2.0",
    "id": "edge-decoy-<ip-with-non-alphanumerics-as-dashes>-<yyyyMMddHH>",
    "type": "CloudShield:IPAddress/DecoyRouteHit",
    "severity": 5.0,
    "createdAt": "<ISO-8601 UTC>",
    "accountId": "<account id>",
    "region": "us-east-1",
    "resource": {"resourceType": "IPAddress",
                 "ipAddressDetails": {"ipAddressV4": "<the viewer IP>"}},
    "service": {"serviceName": "cloudshield",
                "additionalInfo": {"sample": false, "publisher": "docs-api-decoy"}}}
   ```

   Use `ipAddressV6` for IPv6. Exactly one address, no prefix. The id must match `^[\w.:-]{1,128}$`; the hourly suffix makes repeats within the hour router-level duplicates.
3. The address must be the **viewer** IP (`CloudFront-Viewer-Address`), never `X-Forwarded-For`, or anyone could get a third party blocked. The guard and PB-05 still refuse non-global, never-block-listed, stale or malformed addresses, and blocks are lifted automatically by the sweeper at `blockExpiresAt` (D15, audit A2).
