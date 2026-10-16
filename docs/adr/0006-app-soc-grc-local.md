# ADR-0006: docs-api, SPA (portal + SOC), Regional GRC hub and the local stack

- **Status:** Accepted (16 Oct 2026, Phase E)
- **Deciders:** @YasseenAbdelghany (S2, owner), @ELSHAHALY (S1: edge decoy route, compute posture read, CI, compose), @ahklsfg (S3: SOC read and decoy publisher IAM, notify-only guard type, ATT&CK export)
- **Relates to:** plan `docs/plans/s2-app-soc-ui-grc.md` (D1–D28, §16 verify list); ADR-0002 §5 (amended); ADR-0004 (edge, token contract); ADR-0005 (amended: `DecoyRouteHit` is notify-only)

## Context

Phases A–D built the platform, SOAR and the edge, but no application ran behind the edge. Phase E adds the multi-tenant document API (`app/docs-api`), one SPA holding the customer portal, the SecOps SOC dashboard and the Regional GRC hub (`app/spa`), GRC content as data (`app/grc`) and a local stack that needs no AWS account (`docker-compose.local.yml`, `app/local-dev`).

## Decision (summary; full rationale in the plan)

| # | Decision |
|---|---|
| D1–D2 | Keep `app/`: `app/docs-api` and `app/spa`. The image is built with context `app/` (`IMAGE_CONTEXT`), with a BuildKit per-Dockerfile allow-list. |
| D3–D4 | Reuse the existing tables: typed sort keys (`doc#<uuidv7>`, `meta#grc-profile`) in `documents`; the brief's `AUDIT_EVENT` **is** the `audit` table. Every audit write is conditional. Wording: "insert-only by convention", never "immutable". |
| D5–D7 | `CognitoJwtVerifier` (+ explicit `iss`) re-verifies every ID token; tenant only from `custom:tenant_id` (strict format, `_platform` reserved); RBAC from `cognito:groups`; ABAC owner checks; cross-tenant = 404; `secops-analyst` has no tenant-document access. |
| D8–D12 | Server-generated UUIDv7 ids; uploads through the API (SHA-256 recomputed, magic bytes, SSE-KMS with the data key ARN); version-pinned pre-signed GET downloads; tombstone delete; RFC 9457 errors; OpenAPI 3.1 is the request validator and, in tests, the response validator. |
| **D13–D15** | **Decoy route, notify-only.** Pre-auth `/admin*`, no body read, the same 403 as any denial, `_platform` audit (5/min/IP), one `DecoyRouteHit` publish per IP per hour (30/min per task). SOAR records and notifies; the guard refuses the type and PB-05 refuses it independently. The unauthenticated edge route is behind `enable_decoy_route`. |
| **D16–D19** | **SOC read model.** docs-api reads TB5 directly with a read-only, prefix-scoped policy owned by `modules/soar`; one GSI Query per status, never a Scan; chain-of-custody and MTTC parity with `generate_ir_report.py` pinned by shared golden fixtures; posture from build-time gate outcomes + static image policy + a live ECR scan; polling, not streaming. |
| D20 | React + Vite + Tailwind (compiled CSS only), Amplify v6 with `sessionStorage`, hand-written SVG charts, no inline script/style, Vitest for the SPA, Jest for docs-api. |
| **D21–D22** | **moto server** (Apache-2.0) instead of LocalStack. A dev-only local IdP; local mode is accepted **only** next to a local emulator endpoint; `aws` mode refuses every local or endpoint-override variable; `modules/compute` filters them out of the task definition. |
| D23–D26 | GRC rules as versioned, schema-validated JSON with a fixed DSL; every legal claim carries `doc`/`verify`; DPA/SLA click-through **acceptance logging** (not an e-signature) gates document writes; onboarding via `/onboarding`. |
| D27–D28 | CI gate `gate: app (lint + typecheck + test + build)` (hard-fail), image `needs: app`; exact versions, committed lockfiles, `--ignore-scripts`, digest-pinned images, Dependabot for npm/docker/compose. |

## Deviations from the plan, recorded at build time

**Step 0 outcomes**

1. **moto 5.2.4:** GSI Query, `TransactWriteItems` conditions, EventBridge custom buses (and rule → SQS delivery), SSM, Object Lock bucket configuration and legal hold work. **`GetObjectRetention` does not**: the JS SDK cannot parse moto's response. The retention, legal-hold and size-cap cases run against `aws-sdk-client-mock` (`soc-evidence.test.ts`), and docs-api reports retention as `null` ("not reported") whenever it cannot read it, never as locked.
2. **Local token verification** uses `jose` (`createRemoteJWKSet`), the plan's fallback; production stays on `CognitoJwtVerifier`. `jose` is pinned to **5.10.0**: 6.x is ESM-only and does not load under Jest's CommonJS runtime.
3. **Runtime base image:** `gcr.io/distroless/nodejs24-debian13:nonroot` (Node 24.22.0). The Debian 12 variant carried a fixable CRITICAL and five fixable HIGH `libssl3` CVEs on 16 Oct 2026, which the image gate would fail. The build stage stays on `node:24-bookworm-slim` (it never ships; no native addons at runtime).
4. **Versions:** Node 24.22.0; TypeScript 5.9.3 (TypeScript 7 is not supported by ts-jest or typescript-eslint); ESLint 10; React Router 7.18 (not 8); Vite 8, Vitest 5, Tailwind 4; hadolint 2.14.0; setup-node v7.1.0 by SHA.
5. **Semgrep `p/typescript` and `p/react`** could not be fetched in the build sandbox (semgrep.dev is blocked there); CI is the first run. **Dependabot `docker-compose` ecosystem** support is [verify].
6. **Amplify v6:** `sessionStorage` from `aws-amplify/utils` and `cognitoUserPoolsTokenProvider.setKeyValueStorage` exist in 6.22.2 (checked in the package typings).

**Design changes**

- **Authentication runs before any body parser and the validator** (plan §4.1 had the validator first). Up to 5 MiB is never parsed for an unauthenticated caller; unknown paths answer 401 instead of 404 without a token, as API Gateway already does.
- **Pre-auth limiter:** 60 failed authentications per minute per IP, then 429 before any verification work. The decoy keeps its own caps (it always answers the same 403).
- **No `pino-http`:** a small access-log middleware logs the route **template**, status, latency, `sub` and tenant only.
- **`GET /soc/incidents/{id}/evidence`** returns an `EvidenceVerification` object (checks, chain verdict, bucket Object Lock, `truncated`) instead of a bare array. A check truncated at 20 objects never reports an intact chain (`null`), where the Python tool checks every record.
- **Agreement markers** are read with one `GetItem` each: the task role has no `BatchGetItem` on the audit table, and the IAM was not widened.
- **ESLint `react/no-danger`:** `eslint-plugin-react` does not support ESLint 10, so the SPA uses core `no-restricted-syntax` rules: no `dangerouslySetInnerHTML`, no `style` props (the CSP blocks them), no `innerHTML`/`outerHTML` assignment, no `localStorage`.
- **Local stack:** moto does not validate SSE-KMS key ids and ignores `_custom_key_id_` over its API, so local mode uses a fixed `DATA_KMS_KEY_ARN` and the seed creates no KMS key. The seed adds an SQS queue and a rule on the local edge bus so `make local-smoke` can observe the decoy publish, and a dataset sentinel row in a reserved `_seed` partition for idempotency.

## Residual risks

- **Decoy (D13).** A caller holding the leaked origin secret can reach `execute-api` directly and forge `CloudFront-Viewer-Address`: that yields false audit IPs and notify-only noise, **never a block**. Bounded by the per-task caps, WAF `SoarApiRateLimit` and API Gateway throttling. Without `enable_decoy_route`, only authenticated probing reaches the decoy.
- **SOC read path (D16).** A compromised docs-api task can read every incident row and every evidence object under `incidents/` (read-only; no Scan, no writes, no `GenerateDataKey`). Mitigations: prefix scope, CloudTrail S3 data events on the evidence bucket, SOC routes only for `secops-analyst`. Target design: a separate SOC read service in the Security account (ADR-0001).
- **Local mode in the production image (D22).** The code path exists in the image. Defence in depth: the config validator (local only with a local endpoint, `aws` refuses every local variable), the Terraform filter + precondition, and the API Gateway Cognito authorizer, which rejects non-Cognito tokens before the app sees them.
- **Tenant isolation is not cryptographic or IAM-enforced** (ADR-0002 §5): the task role can reach every tenant's items; the API enforces the partition key from the token.
- **Pre-signed download URLs are bearer URLs** for up to `PRESIGNED_URL_MAX_SECONDS` (300 s; the bucket policy caps `signatureAge` independently). Every issuance is audited.
- **Rate limits and caches are per task** (×2 with two tasks). The agreement gate caches per tenant for 60 s, so another task may keep blocking writes for up to a minute after acceptance (fail closed, never open).
- **Click-through acceptance is evidence, not a qualified or advanced electronic signature;** the DPA/SLA are templates no counsel has reviewed. GRC items marked `verify` are unestablished.

## Follow-ups (recorded, not built)

- WAF-corroborated decoy blocking: a rate-based `SoarDecoyRateLimit` rule scoped to `/api/admin` (limit 10 per 60 s; about $1/month) so PB-05 can corroborate a decoy hit against WAF's own keys. Needs S1 + S3 review.
- An audit-stream tamper consumer (the stream exists; nothing alarms on Modify/Remove yet).
- Per-request STS session tags with `dynamodb:LeadingKeys` (ADR-0002 §5).
- A separate SOC read service in the Security account.
- GuardDuty Malware Protection for S3 uploads (paid; off).
- A decoy scenario in the attack sims (S3).

## Verify on the first apply

Plan §16, items 1–15: notably `CloudFront-Viewer-Address` through HTTP_PROXY (and its IPv6 form), the NONE-authorised decoy routes beating `{proxy+}`, the conditioned `PutEvents` passing the bus policy, GSI Query with only `kms:Decrypt`, Object Lock error codes with lock off/on, pre-signed SSE-KMS + `VersionId` downloads under the 300 s cap, `TransactWriteItems` across the two tables, distroless as 1000:1000 with a read-only rootfs, Amplify SRP + TOTP under the CloudFront CSP, ZAP still passing, and `/soc/posture` showing the deployed commit's gates.
