# Runbook: local development stack (Phase E)

**Owner:** S2 (@YasseenAbdelghany), compose review S1. **DEV ONLY**: nothing here talks to AWS.

The stack (`docker-compose.local.yml`) runs:

| Service | What | Port |
|---|---|---|
| `moto` | moto server 5.2.4 (DynamoDB, S3, EventBridge, SQS, SSM) | `127.0.0.1:5000` (the browser follows pre-signed download URLs here) |
| `local-idp` | dev-only IdP: mints Cognito-shaped RS256 ID tokens, key in memory only, refuses to start unless `CLOUDSHIELD_ENV=local` | none (nginx proxies `/local-idp/`) |
| `seed` | one-shot, idempotent seed; **refuses** any endpoint that is not a local emulator (exit 2) | none |
| `docs-api` | the **production** image in `CLOUDSHIELD_ENV=local` | none |
| `spa` | local-auth SPA build on unprivileged nginx with the edge's security headers; strips `/api` like API Gateway and overwrites `CloudFront-Viewer-Address` | `127.0.0.1:3000` |

Every container is non-root, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`.

## Start, check, stop

```bash
make local-up      # docker compose up -d --build --wait
open http://localhost:3000
make local-smoke   # five end-to-end checks (below)
make local-down    # removes the containers and moto's data
```

Requirements: Docker with Compose v2.20+ and Node 24 (for `make local-smoke`).

## Demo users (`app/local-dev/fixtures/users.json`)

| User | Tenant | Group | Shows |
|---|---|---|---|
| alice | `t-acme-01` (EU + EG) | admin | documents, audit, GRC assessment; agreements already accepted |
| bob / carol | `t-acme-01` | member / auditor | owner-only writes; read-only + audit trail |
| dina | `t-nile-02` (EG, CBE-regulated) | admin | onboarding: agreements **pending**, writes blocked (`AGREEMENT_REQUIRED`) |
| mallory | `t-nile-02` | member | the IDOR demo: Acme's document ids answer 404 |
| omar | `t-riyadh-03` (SA, government) | admin | no GRC profile yet: residency GAPs once set |
| sam | `t-cloudshield-soc` | secops-analyst | SOC dashboard only, no tenant documents |

Seeded incidents (times relative to the seed): A (credential exfiltration, CONTAINED, intact evidence), A-recon, B, **C with a tampered evidence object (chain BROKEN)**, D (would contain, dry run), E (WAF block active), a decoy hit (notify only) with its `_platform` audit, FAILED, NO_PLAYBOOK, and an in-progress DETECTED.

## What `make local-smoke` proves

1. `/api/healthz` answers 200 through nginx.
2. alice lists Acme's documents.
3. mallory (another tenant) gets **404** for an Acme document id.
4. A tokenless `/api/admin/…` hit answers 403, lands in the `_platform` audit, and a `DecoyRouteHit` event reaches the local edge bus (captured in an SQS queue).
5. sam sees scenario C on `/soc/overview`, and its chain of custody verifies as **BROKEN**.

## Integration tests without compose

```bash
make local-moto                           # moto alone on 127.0.0.1:5000
cd app/docs-api && npx jest --coverage    # *.int.test.ts use MOTO_ENDPOINT
```

## Why local auth cannot leak into production

- docs-api accepts `CLOUDSHIELD_ENV=local` only together with `AWS_ENDPOINT_URL` on `moto`, `localhost`, `127.0.0.1` or `::1`; a local token can therefore only ever reach fake data.
- In the default `aws` mode, any of `AUTH_LOCAL_ISSUER`, `AUTH_LOCAL_JWKS_URI`, `S3_PUBLIC_ENDPOINT`, `AWS_ENDPOINT_URL` or `AWS_ENDPOINT_URL_*` stops the process at startup.
- `modules/compute` filters those keys out of the task definition and fails a precondition if they are passed.
- The local IdP's issuer is `http://local-idp:9000`: not https and not a Cognito URL, so the production verifier rejects its tokens, and so does the API Gateway Cognito authorizer before them.
- The SPA's local sign-in is removed from production builds at compile time; CI fails if `local-idp` appears in the bundle.

## Differences from AWS

moto does not enforce IAM, KMS key ids, bucket policies or Object Lock retention reads (`GetObjectRetention` is unsupported through the JS SDK, so evidence retention shows "not reported"). Use it for behaviour, never as proof of a security control.
