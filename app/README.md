# app/ — S2 (App / Identity)

Multi-tenant document API, customer portal, SecOps SOC dashboard and Regional GRC hub (Phase E, [ADR-0006](../docs/adr/0006-app-soc-grc-local.md), plan `docs/plans/s2-app-soc-ui-grc.md`).

| Path | What |
|---|---|
| `openapi.yaml` | Contract-first API spec (OpenAPI 3.1). It **is** the request validator; responses are validated against it in tests. `npm run openapi:types` (docs-api) regenerates the types in both packages; CI fails on drift. |
| `docs-api/` | Express 5 / TypeScript API. Image: `docs-api/Dockerfile`, **build context `app/`** (repo variable `IMAGE_CONTEXT`, default `app`), so the contract and `grc/` are inside it; `docs-api/Dockerfile.dockerignore` allow-lists what enters the context. |
| `spa/` | React SPA (portal, SOC dashboard, GRC hub), one static build for the SPA bucket. `spa/Dockerfile` (target `local`) is for compose only and is never pushed. |
| `grc/` | GRC rules, matrix, platform facts and DPA/SLA templates as validated data. **Not legal advice**: see `grc/README.md`. |
| `local-dev/` | DEV ONLY: the local IdP, the moto seed and `make local-smoke`. Never in a pushed image. |
| `.nvmrc` | Node 24 (Active LTS), used by CI and the images. |

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

## Phase E: decoy route publisher contract (built, notify-only)

The decoy (`ANY /admin*` in the container, `/api/admin*` at the edge) is **notify-only** in Phase E (plan D13): docs-api publishes `CloudShield:IPAddress/DecoyRouteHit`, and SOAR records it and notifies but **never blocks**. The guard returns `notify-only edge finding (decoy route hit): analyst review` (`EDGE_NOTIFY_ONLY_TYPES` in `soar/core/finding.py`), the router records `BLOCKED_BY_GUARD` and sends SNS + ChatOps, and PB-05 independently refuses the type (audit A1 unchanged). A WAF-corroborated block is a recorded follow-up (ADR-0006). Any block of a decoy caller is an analyst decision ([runbook](../docs/runbooks/decoy-route.md)).

1. The publisher grant is derived, not hand-wired: `app_publishes_decoy` in `modules/soar` adds the task-role ARN to the bus Allow list (and exempts it from the explicit Deny) and grants `events:PutEvents` on the bus ARN only with `events:source = cloudshield.edge` and `events:detail-type = CloudShield Edge Finding` (`app-integration.tf`). Set `enable_decoy_publisher = true` in dev.
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

## Local mode (plan D22)

`docker-compose.local.yml` runs the **production** docs-api image with `CLOUDSHIELD_ENV=local`. The config validator accepts local mode only when `AWS_ENDPOINT_URL` points at a local emulator host (`moto`, `localhost`, `127.0.0.1`, `::1`), and verifies tokens from the dev-only local IdP (`iss = http://local-idp:9000`). In the default `aws` mode, any of `AUTH_LOCAL_*`, `S3_PUBLIC_ENDPOINT` or `AWS_ENDPOINT_URL[_*]` makes the process exit at startup, and `modules/compute` filters those keys (including every `AWS_ENDPOINT_URL_<SERVICE>`) out of the task definition and fails a precondition if any is given. Local auth is thereby coupled to a fake data plane. See `docs/runbooks/local-dev.md`.
