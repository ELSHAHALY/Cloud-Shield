# ADR-0004: Edge, identity and two WAFs (TB1)

- **Status:** Accepted (16 Oct 2026)
- **Deciders:** @ELSHAHALY (S1, edge), @YasseenAbdelghany (S2, identity), @ahklsfg (S3, WAF logs and PB-05 IP sets)
- **Relates to:** plan `docs/plans/s1-s2-edge-identity-waf.md` §1–§3 (D2–D11, D18), ADR-0002 §1 and §4, HANDOFF gap 9

## Context

Until Phase D the application had no internet edge: the REST API Gateway + VPC Link design (ADR-0002 §4) existed only on paper, there was no identity provider, and the ZAP gate had nothing to scan. Phase D builds trust boundary TB1: `modules/identity` (Cognito) and `modules/edge` (CloudFront, two WAF web ACLs, the private SPA bucket, and the REST API).

Facts that shaped the design (plan §1.1):

- A `CLOUDFRONT`-scope web ACL and its IP sets can only be created in us-east-1 (F2).
- Behind CloudFront, a regional ACL on API Gateway sees CloudFront's address; `X-Forwarded-For` is client-controlled (F3).
- `count` on an ARN that is unknown until apply fails (F4), so every feature is a plan-time bool (D6).
- A CloudFront `custom_error_response` for 403/404 would also rewrite WAF and API errors to `200 index.html` (F11).
- REST Cognito authorizers check signature, issuer and expiry, but not `aud`, for ID tokens [inferred, F8].

## Decision

| # | Decision |
|---|---|
| D2 | One CloudFront distribution: `/*` → private SPA bucket (OAC, SSE-KMS); `/api/*` → a REGIONAL REST API. Same origin, so no CORS. |
| D3 | CloudFront adds a random `x-origin-verify` header (48 characters, `random_password`, so it lives only in state). Regional ACL rule 0 blocks any request without it; API Gateway blanks it before the backend. It is a bypass deterrent, **not** authentication: anyone who can read the WAF or CloudFront configuration can see it. |
| D4 | **Per-IP controls live on the CloudFront ACL**, where the client address is real: p0 `SoarBlockedIps` (the PB-05 IPv4 and IPv6 IP sets, block 403), p1 Amazon IP reputation, p2 `SoarApiRateLimit` (scoped down to URI paths starting `/api/`, `waf_api_rate_limit` default 200 per 5 min, block **429**; the **only** PB-05 feed, audit A2), p3 `RateLimitPerIp` (site-wide, default 300 per 5 min, block **429**, never harvested), p4 Common rule set, p5 KnownBadInputs. `SoarApiRateLimit` sits before the site-wide rule so it keeps counting `/api/*` requests while `RateLimitPerIp` answers 429. **Regional ACL:** p0 `OriginVerify`, p1 KnownBadInputs, p2 SQLi. |
| D5 | The Cognito authorizer takes the **ID token**; the app re-verifies `iss`, `aud` and `token_use = id` (F8; see `app/README.md`). SRP from the SPA; no hosted UI or OAuth in Phase D. |
| D6 | `identity` is always on. `enable_edge` defaults to **false** (≈ US$20/month for the WAFs: 2 ACLs + 10 rules; plan §8 counted 9 before audit A2 added `SoarApiRateLimit`). `enable_api` (= `enable_edge` and a container image), `enable_pb04` and `enable_pb05` are plan-time bools. |
| D7 | The ECR push role trusts only `repo:<owner>/<repo>:ref:refs/heads/main` (`sub` StringEquals). CI pushes; it never deploys (gap 9 stays: deploy is a local S1 apply). |
| D8 | WAF logs go to a dedicated `aws-waf-logs-<name>-<acct>` bucket (the name prefix WAF requires) encrypted with the log-archive key, with `authorization`, `cookie` and `x-origin-verify` redacted. Query them with the `waf_logs` Glue table and hunt query 04. **Sampled requests are off** (`sampled_requests_enabled = false`) on every rule of both ACLs and on the ACLs themselves (audit A7): a sampled request in the WAF console/API carries the request headers, including the `Authorization` ID token and the origin secret, and the redaction above applies to the **logs only**. CloudWatch metrics stay on; the logs are the investigation source. |
| D9 | us-east-1 for the CloudFront ACL and IP sets: **built with the F17 fallback**, see "Deviations". |
| D10 | SPA deep links are rewritten to `/index.html` by a CloudFront Function (viewer request, URIs without an extension). There is **no** `custom_error_response`; a test asserts it. |
| D11 | Default CloudFront certificate (no custom domain yet), so the minimum viewer TLS version is fixed by AWS. The TLS-version Checkov checks are skipped with that reason; follow-up: custom domain + ACM. |
| D18 | The scope tag stays `cloudshield:soar-scope = in-scope`, as in every IAM condition, the guard and the sims. New code reads it from `SCOPE_TAG_KEY` / `SCOPE_TAG_VALUE`; nothing hard-codes it. |

Identity specifics (S2): TOTP-only MFA (`ON` by default, `OPTIONAL` allowed, `OFF` rejected), admin-created users only, 14-character passwords, `custom:tenant_id` **immutable and not in the client's `write_attributes`**, exactly four groups (`admin`, `member`, `auditor`, `secops-analyst`) with no IAM roles, and `ESSENTIALS` tier by default (threat protection needs `PLUS`, enforced by validation).

## Deviations from the plan, recorded at build time

- **No provider alias in `modules/edge`.** Plan D9 asked for `configuration_aliases = [aws.us_east_1]`. Builder step 0 (F17) showed that `terraform validate` on Terraform **1.16.5** fails when run standalone on a module that declares `configuration_aliases`, and CI validates every module directory on its own. The module therefore uses the F17 fallback: **no alias, and `precondition`s that the provider region is `us-east-1`** (on the web ACL and both IP sets). Every edge resource lives in us-east-1; this matches plan §1.2 (single region). `modules/soar` repeats the same us-east-1 precondition on the PB-05 edge bus.
- Consequence: the "CloudFront logging configuration only when the region is us-east-1" branch from the plan is always true in practice.

## Consequences

- **`execute-api` is still reachable directly** on its public endpoint. The regional ACL's `OriginVerify` rule blocks requests without the header, and every `/api/{proxy+}` method needs a valid Cognito ID token, but per-IP controls (reputation, rate limit, PB-05 blocks) apply only through CloudFront. A leaked origin header removes the first control only.
- The CloudFront ACL is the only place a PB-05 block takes effect; see ADR-0005.
- Terraform never manages the IP sets' addresses (`ignore_changes = [addresses]`), so an apply can neither add nor lift a PB-05 block.
- With sampled requests off, the WAF console's "Sampled requests" view is empty; use the `waf_logs` table (hunt query 04) instead.
- The SPA bucket's object-level access is recorded by CloudTrail S3 data events: dev adds its ARN (output `spa_bucket_arn`) to `modules/detection` `data_event_bucket_arns` whenever `enable_edge` is on (audit A8), which is what the CKV_AWS_18 skip on that bucket relies on.
- Checkov skips added by the edge (each with an inline reason): CKV_AWS_174 / CKV2_AWS_42 (default certificate), CKV_AWS_86 (WAF already logs every request), CKV_AWS_310 (single region), CKV_AWS_374 (no geo restriction), CKV_AWS_120 / CKV_AWS_225 (per-tenant responses are never cached), CKV2_AWS_51 (VPC Link only), CKV2_AWS_53 (OpenAPI validation in the app), CKV_AWS_59 (healthz only), CKV2_AWS_47 / CKV2_AWS_77 (the Log4j rules are attached through KnownBadInputs; the checks also demand the anonymous-IP list, which D4 leaves out), CKV_AWS_338 (30-day log retention, lab cost), and bucket logging / replication / notifications (CKV_AWS_18, CKV_AWS_144, CKV2_AWS_62) as for the evidence bucket.

## Verify on the first apply (plan §9)

1. ECR push: whether the role needs a KMS grant.
2. Whether Managed-AllViewerExceptHostHeader forwards `CloudFront-Viewer-Address` (the app's audit `sourceIp`).
3. WAF S3 delivery works under the archive key's `aws:SourceArn` condition, and a `waf_logs` smoke query returns rows.
4. The API Gateway CloudWatch role trust works without conditions.
5. A SPA deep link returns 200, while an unauthenticated `/api/x` returns **401** (not a rewritten 200).
