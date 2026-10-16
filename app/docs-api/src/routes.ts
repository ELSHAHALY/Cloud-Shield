// Route table (plan §3.3 / §4.2). Every route names its permission; document
// writes also pass the agreement gate. The request validator has already
// enforced the OpenAPI shapes, but handlers still parse defensively.
import { Router, type NextFunction, type Request, type Response } from "express";
import type { Principal } from "./auth/principal";
import { requirePermission } from "./auth/rbac";
import { auditWindow, type AuditLog } from "./audit/audit";
import type { AgreementService } from "./agreements/service";
import type { DocumentService } from "./documents/service";
import type { GrcService } from "./grc/service";
import { AppError } from "./lib/errors";
import { parseLimit } from "./lib/cursor";
import { RateLimiter } from "./lib/rate-limit";
import { rateLimit } from "./middleware/http";
import { PLATFORM_PARTITION, PERMISSIONS } from "./auth/principal";
import type { SocService } from "./soc/service";
import { STATUSES, type IncidentStatus } from "./soc/repository";
import type { Window } from "./soc/metrics";

export interface Services {
  documents: DocumentService;
  audit: AuditLog;
  agreements: AgreementService;
  grc: GrcService;
  soc: SocService;
  now: () => Date;
}

function principal(req: Request): Principal {
  if (!req.principal) throw new AppError("UNAUTHENTICATED");
  return req.principal;
}

function q(req: Request, name: string): unknown {
  const v = (req.query as Record<string, unknown>)[name];
  return Array.isArray(v) ? NaN : v;
}

function cursor(req: Request): string | undefined {
  const v = q(req, "cursor");
  return typeof v === "string" ? v : v === undefined ? undefined : "!";
}

function param(req: Request, name: string): string {
  const v = req.params[name];
  return typeof v === "string" ? v : "";
}

export function createRoutes(s: Services): Router {
  const r = Router();
  const bySub = (req: Request) => req.principal?.sub ?? "anonymous";
  const uploads = rateLimit(new RateLimiter(30, 60_000), bySub);
  const downloads = rateLimit(new RateLimiter(120, 60_000), bySub);
  const socLimit = rateLimit(new RateLimiter(240, 60_000), bySub);
  const agreementGate = async (req: Request, _res: Response, next: NextFunction) => {
    await s.agreements.assertComplete(principal(req));
    next();
  };

  r.get("/me", (req, res) => {
    const p = principal(req);
    res.json({
      sub: p.sub,
      ...(p.email ? { email: p.email } : {}),
      tenantId: p.tenantId,
      groups: [...p.groups],
      permissions: PERMISSIONS.filter((x) => p.permissions.has(x)),
    });
  });

  // ---- documents ----
  r.get("/documents", requirePermission("doc:read"), async (req, res) => {
    res.json(await s.documents.list(principal(req), parseLimit(q(req, "limit")), cursor(req)));
  });
  r.post("/documents", requirePermission("doc:write"), agreementGate, async (req, res) => {
    res.status(201).json(await s.documents.create(req, principal(req), req.body));
  });
  r.get("/documents/:docId", requirePermission("doc:read"), async (req, res) => {
    res.json(await s.documents.get(principal(req), param(req, "docId")));
  });
  r.patch("/documents/:docId", requirePermission("doc:write"), agreementGate, async (req, res) => {
    res.json(await s.documents.patch(req, principal(req), param(req, "docId"), req.body, req.get("if-match")));
  });
  r.delete("/documents/:docId", requirePermission("doc:delete"), agreementGate, async (req, res) => {
    await s.documents.delete(req, principal(req), param(req, "docId"));
    res.status(204).end();
  });
  r.put("/documents/:docId/content", requirePermission("doc:write"), uploads, agreementGate, async (req, res) => {
    res.json(await s.documents.upload(req, principal(req), param(req, "docId"), req.body, req.get("content-type")));
  });
  r.get("/documents/:docId/download", requirePermission("doc:read"), downloads, async (req, res) => {
    res.json(await s.documents.downloadUrl(req, principal(req), param(req, "docId")));
  });

  // ---- tenant audit ----
  r.get("/audit", requirePermission("audit:read"), async (req, res) => {
    const { from, to } = auditWindow(q(req, "from"), q(req, "to"), s.now());
    res.json(await s.audit.query(principal(req).tenantId, from, to, parseLimit(q(req, "limit")), cursor(req)));
  });

  // ---- agreements ----
  r.get("/agreements", requirePermission("agreement:read"), (_req, res) => {
    res.json(s.agreements.list());
  });
  r.get("/agreements/status", requirePermission("agreement:read"), async (req, res) => {
    res.json(await s.agreements.status(principal(req)));
  });
  r.get("/agreements/:agreementId/:version/text", requirePermission("agreement:read"), (req, res) => {
    res.type("text/plain; charset=utf-8").send(s.agreements.text(param(req, "agreementId"), param(req, "version")));
  });
  r.post("/agreements/:agreementId/accept", requirePermission("agreement:accept"), async (req, res) => {
    const out = await s.agreements.accept(req, principal(req), param(req, "agreementId"), req.body);
    res.status(out.created ? 201 : 200).json(out.acceptance);
  });

  // ---- GRC ----
  r.get("/grc/ruleset", requirePermission("grc:read"), (_req, res) => {
    res.json(s.grc.summary());
  });
  r.get("/grc/responsibility-matrix", requirePermission("grc:read"), (_req, res) => {
    res.json(s.grc.matrix());
  });
  r.get("/grc/profile", requirePermission("grc:assess"), async (req, res) => {
    res.json(await s.grc.getProfile(principal(req)));
  });
  r.put("/grc/profile", requirePermission("grc:profile:write"), async (req, res) => {
    res.json(await s.grc.putProfile(req, principal(req), req.body));
  });
  r.get("/grc/assessment", requirePermission("grc:assess"), async (req, res) => {
    res.json(await s.grc.assessment(principal(req)));
  });

  // ---- SOC (secops-analyst only) ----
  r.get("/soc/overview", requirePermission("soc:read"), socLimit, async (_req, res) => {
    res.json(await s.soc.overview());
  });
  r.get("/soc/incidents", requirePermission("soc:read"), socLimit, async (req, res) => {
    const status = q(req, "status");
    if (typeof status !== "string" || !(STATUSES as readonly string[]).includes(status)) {
      throw new AppError("VALIDATION_FAILED", "invalid status", [{ path: "/query/status", message: "invalid status" }]);
    }
    res.json(await s.soc.list(status as IncidentStatus, parseLimit(q(req, "limit")), cursor(req)));
  });
  r.get("/soc/incidents/:incidentId", requirePermission("soc:read"), socLimit, async (req, res) => {
    res.json(await s.soc.incident(param(req, "incidentId")));
  });
  r.get("/soc/incidents/:incidentId/evidence", requirePermission("soc:evidence"), socLimit, async (req, res) => {
    res.json(await s.soc.evidence(req, param(req, "incidentId")));
  });
  r.get("/soc/incidents/:incidentId/report", requirePermission("soc:evidence"), socLimit, async (req, res) => {
    const format = q(req, "format") === "md" ? "md" : "json";
    const id = param(req, "incidentId");
    const out = await s.soc.report(req, id, format);
    if ("markdown" in out) {
      res.setHeader("Content-Disposition", `attachment; filename="ir-${id.replace(/[^A-Za-z0-9._-]/g, "_")}.md"`);
      res.type("text/markdown; charset=utf-8").send(out.markdown);
      return;
    }
    res.json(out.report);
  });
  r.get("/soc/metrics", requirePermission("soc:read"), socLimit, async (req, res) => {
    const w = q(req, "window");
    const window: Window = w === "7d" || w === "30d" ? w : "24h";
    res.json(await s.soc.metrics(window));
  });
  r.get("/soc/posture", requirePermission("posture:read"), socLimit, async (_req, res) => {
    res.json(await s.soc.posture());
  });
  r.get("/soc/audit", requirePermission("soc:read"), socLimit, async (req, res) => {
    const { from, to } = auditWindow(q(req, "from"), q(req, "to"), s.now());
    res.json(await s.audit.query(PLATFORM_PARTITION, from, to, parseLimit(q(req, "limit")), cursor(req)));
  });

  return r;
}
