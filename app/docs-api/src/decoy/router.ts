// Decoy route (plan D13–D15, §6). Mounted at /admin BEFORE authentication and
// before any body parser: it fires with or without a token and never reads a
// body. A hit is audited in `_platform` and, when enabled, published to the
// edge bus as CloudShield:IPAddress/DecoyRouteHit, which SOAR records and
// notifies on but never blocks (the guard refuses the type: notify-only).
import { isIP } from "node:net";
import { PutEventsCommand, type EventBridgeClient } from "@aws-sdk/client-eventbridge";
import { Router, type Request, type Response } from "express";
import type { Logger } from "pino";
import { PLATFORM_PARTITION, toPrincipal } from "../auth/principal";
import { bearer, type TokenVerifier } from "../auth/verifier";
import type { AuditActor, AuditLog } from "../audit/audit";
import { problem } from "../lib/errors";
import { RateLimiter } from "../lib/rate-limit";
import { clean } from "../lib/sanitize";

export const DECOY_FINDING_TYPE = "CloudShield:IPAddress/DecoyRouteHit";
export const EDGE_DETAIL_TYPE = "CloudShield Edge Finding";

export interface DecoyDeps {
  audit: AuditLog;
  verifier: TokenVerifier;
  events: EventBridgeClient;
  logger: Logger;
  publishEnabled: boolean;
  busName?: string;
  source: string;
  accountId?: string;
  region: string;
  now?: () => Date;
}

function hourStamp(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}`;
}

/** `edge-decoy-<ip non-alphanumerics → "-">-<yyyyMMddHH>`; matches ^[\w.:-]{1,128}$. */
export function decoyIncidentId(ip: string, at: Date): string {
  return `edge-decoy-${ip.replace(/[^A-Za-z0-9]/g, "-")}-${hourStamp(at)}`;
}

export function decoyEvent(input: { ip: string; at: Date; accountId?: string; region: string; requestId: string; authenticated: boolean; busName: string; source: string }) {
  const v6 = isIP(input.ip) === 6;
  const detail = {
    schemaVersion: "2.0",
    id: decoyIncidentId(input.ip, input.at),
    type: DECOY_FINDING_TYPE,
    severity: 5.0,
    createdAt: input.at.toISOString(),
    accountId: input.accountId ?? "",
    region: input.region,
    resource: {
      resourceType: "IPAddress",
      ipAddressDetails: v6 ? { ipAddressV6: input.ip } : { ipAddressV4: input.ip },
    },
    service: {
      serviceName: "cloudshield",
      additionalInfo: { sample: false, publisher: "docs-api-decoy", requestId: input.requestId, authenticated: input.authenticated },
    },
  };
  // `Time` is deliberately not set: EventBridge stamps it (guard freshness check).
  return { EventBusName: input.busName, Source: input.source, DetailType: EDGE_DETAIL_TYPE, Detail: JSON.stringify(detail) };
}

export function createDecoyRouter(d: DecoyDeps): Router {
  const now = d.now ?? (() => new Date());
  const published = new Map<string, string>(); // ip -> hour stamp (one publish per IP per hour per task)
  const globalCap = new RateLimiter(30, 60_000, 1);
  const auditCap = new RateLimiter(5, 60_000);
  let auditSuppressed = 0;

  const handler = async (req: Request, res: Response): Promise<void> => {
    const at = now();
    const ip = req.source.trusted ? req.source.ip : null;
    const token = bearer(req.get("authorization"));
    let actor: AuditActor = { type: "anonymous", tokenPresent: Boolean(token) };
    if (token) {
      try {
        const p = toPrincipal(await d.verifier.verify(token));
        actor = { type: "user", sub: p.sub, tenantId: p.tenantId, groups: [...p.groups], tokenPresent: true };
      } catch {
        // Silent: the decoy never reveals whether a token was valid.
      }
    }
    const incidentId = ip ? decoyIncidentId(ip, at) : null;

    let publishSkipped: string | null = null;
    if (!d.publishEnabled || !d.busName) publishSkipped = "publisher-disabled";
    else if (!ip) publishSkipped = "untrusted-source-ip";
    else if (published.get(ip) === hourStamp(at)) publishSkipped = "already-published-this-hour";
    else if (globalCap.take("all") > 0) publishSkipped = "global-cap";

    let didPublish = false;
    if (publishSkipped === null && ip && d.busName) {
      if (published.size > 10_000) published.clear();
      published.set(ip, hourStamp(at));
      try {
        const out = await d.events.send(
          new PutEventsCommand({
            Entries: [decoyEvent({ ip, at, accountId: d.accountId, region: d.region, requestId: req.requestId, authenticated: actor.type === "user", busName: d.busName, source: d.source })],
          }),
        );
        didPublish = (out.FailedEntryCount ?? 0) === 0;
        if (!didPublish) d.logger.error({ requestId: req.requestId }, "decoy publish rejected by EventBridge");
      } catch (err) {
        d.logger.error({ err, requestId: req.requestId }, "decoy publish failed");
      }
    }

    if (auditCap.take(ip ?? "unknown") === 0) {
      const event = d.audit.build(req, {
        partition: PLATFORM_PARTITION,
        action: "DECOY_ROUTE_HIT",
        outcome: "DENIED",
        actor,
        resource: { type: "decoy-route", id: clean(req.path, 256) ?? "/" },
        details: {
          method: clean(req.method, 16),
          path: clean(req.originalUrl.split("?")[0], 256),
          query: clean(req.originalUrl.includes("?") ? req.originalUrl.slice(req.originalUrl.indexOf("?") + 1) : null, 256),
          incidentId,
          published: didPublish,
          publishSkipped,
          tokenPresent: Boolean(token),
          authenticated: actor.type === "user",
        },
      });
      try {
        await d.audit.put(event);
      } catch (err) {
        d.logger.error({ err, requestId: req.requestId }, "decoy audit write failed");
      }
    } else {
      auditSuppressed += 1;
      d.logger.warn({ requestId: req.requestId, auditSuppressed }, "decoy audit cap reached for source");
    }

    // Byte-identical in shape to any RBAC denial.
    res.status(403).type("application/problem+json").json(problem("FORBIDDEN", req.requestId));
  };

  const router = Router();
  router.all("/", handler);
  router.all("/{*rest}", handler);
  return router;
}
