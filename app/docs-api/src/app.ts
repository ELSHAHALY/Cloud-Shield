// Express app factory (plan §4.1). The order is the security design:
// request id → headers → source IP → access log → decoy (pre-auth, no body)
// → /healthz → authenticate → per-user limit → body parsers → OpenAPI
// validator → routes → 404 → error handler. Authentication runs BEFORE any
// body is parsed (a deliberate tightening of the plan's order, ADR-0006).
import path from "node:path";
import express, { type Express } from "express";
import * as OpenApiValidator from "express-openapi-validator";
import type { Logger } from "pino";
import type { TokenVerifier } from "./auth/verifier";
import { createDecoyRouter, type DecoyDeps } from "./decoy/router";
import { CONTENT_TYPES } from "./documents/magic";
import { RateLimiter } from "./lib/rate-limit";
import { errorHandler, notFound } from "./middleware/errors";
import { accessLog, authenticate, rateLimit, requestId, securityHeaders } from "./middleware/http";
import { sourceIp } from "./middleware/source-ip";
import { createRoutes, type Services } from "./routes";

export interface AppDeps {
  services: Services;
  verifier: TokenVerifier;
  logger: Logger;
  decoy: Omit<DecoyDeps, "audit" | "verifier" | "logger">;
  contentRoot: string;
  maxUploadBytes: number;
  validateResponses?: boolean;
}

export function buildApp(d: AppDeps): Express {
  const app = express();
  app.disable("x-powered-by");
  app.disable("etag");
  app.set("trust proxy", false);
  app.set("query parser", "simple");

  app.use(requestId);
  app.use(securityHeaders);
  app.use(sourceIp);
  app.use(accessLog(d.logger));

  app.use("/admin", createDecoyRouter({ ...d.decoy, audit: d.services.audit, verifier: d.verifier, logger: d.logger }));
  app.get("/healthz", (_req, res) => {
    res.json({ status: "ok" });
  });

  const preAuth = new RateLimiter(60, 60_000);
  app.use(authenticate(d.verifier, preAuth));
  app.use(rateLimit(new RateLimiter(600, 60_000), (req) => req.principal?.sub ?? "anonymous"));

  app.use(express.json({ limit: "64kb", strict: true, type: "application/json" }));
  app.use("/documents/:docId/content", express.raw({ limit: d.maxUploadBytes, type: [...CONTENT_TYPES] }));
  app.use(
    OpenApiValidator.middleware({
      apiSpec: path.join(d.contentRoot, "openapi.yaml"),
      validateApiSpec: true,
      validateRequests: { allowUnknownQueryParameters: false, removeAdditional: false },
      validateResponses: d.validateResponses ? { removeAdditional: false } : false,
      validateSecurity: false,
      ignoreUndocumented: false,
      fileUploader: false,
    }),
  );

  app.use(createRoutes(d.services));
  app.use(notFound);
  app.use(errorHandler(d.logger, d.services.audit));
  return app;
}
