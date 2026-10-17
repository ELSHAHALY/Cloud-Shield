# Runbook: decoy route hits (Phase E, notify-only)

**Owner:** S3 (@ahklsfg) triage, S1 for edge settings.

## What a hit is

`/api/admin` and `/api/admin/*` are routes no real client calls. docs-api answers them with the same 403 as any denial and records `DECOY_ROUTE_HIT` in the `_platform` audit. With `enable_decoy_publisher`, it also publishes `CloudShield:IPAddress/DecoyRouteHit` (one per IP per hour per task). SOAR records the incident as **`BLOCKED_BY_GUARD`** with the reason `notify-only edge finding (decoy route hit): analyst review` and sends the SNS email and the ChatOps message. **Nothing is blocked automatically.**

Flags (`environments/dev`): `enable_decoy_route` exposes the unauthenticated edge routes; without it only authenticated callers reach the decoy (insider or stolen-token probing). `enable_decoy_publisher` adds the bus publish.

## Triage (SOC dashboard)

1. Open the incident (`edge-decoy-<ip>-<yyyyMMddHH>`): the "Decoy route audit (this hour)" card lists each hit's method, path, source IP, whether the IP was trusted, and the actor (a verified user, or anonymous with/without a token).
2. **An authenticated actor** is the important case: a real user's token probing admin paths. Treat it as a possible account compromise: check the user's recent audit trail, then disable the user and sign them out globally (`docs/runbooks/tenant-provisioning.md`, deprovision).
3. **Anonymous scanner:** usually noise. Check WAF logs for the same IP (Athena `waf_logs`).
4. **Spoofing caveat:** a caller holding the leaked origin secret can reach `execute-api` directly and forge `CloudFront-Viewer-Address`. A hit is therefore never proof of the IP. If you see `sourceIpTrusted: false` or IPs that make no sense, rotate the origin secret (ADR-0004).

## Blocking (human decision)

Only if the IP is clearly abusive, and not shared (NAT, carrier, corporate proxy, VPN exit):

- Add it to the PB-05 IP set by hand with an expiry note, following `docs/runbooks/pb04-pb05-recovery.md`, **or**
- prefer a WAF rule change reviewed by S1.

Never add `DecoyRouteHit` to `EDGE_FINDING_TYPES`: that would let anyone who can produce a decoy hit trigger a block. Corroborated blocking is a recorded follow-up (ADR-0006).
