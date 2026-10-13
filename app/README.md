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
