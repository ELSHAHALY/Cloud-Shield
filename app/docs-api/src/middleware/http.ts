import { randomUUID } from "node:crypto";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import helmet from "helmet";
import type { Logger } from "pino";
import { toPrincipal } from "../auth/principal";
import { bearer, type TokenVerifier } from "../auth/verifier";
import { AppError } from "../lib/errors";
import type { RateLimiter } from "../lib/rate-limit";

/** Server-generated UUIDv4; any inbound X-Request-Id is ignored. */
export function requestId(req: Request, res: Response, next: NextFunction): void {
  req.requestId = randomUUID();
  res.setHeader("X-Request-Id", req.requestId);
  next();
}

const helmetMiddleware = helmet({
  contentSecurityPolicy: { useDefaults: false, directives: { "default-src": ["'none'"], "frame-ancestors": ["'none'"] } },
  referrerPolicy: { policy: "no-referrer" },
  strictTransportSecurity: { maxAge: 31_536_000, includeSubDomains: true },
  xFrameOptions: { action: "deny" },
  crossOriginResourcePolicy: { policy: "same-origin" },
  crossOriginOpenerPolicy: { policy: "same-origin" },
  crossOriginEmbedderPolicy: false,
});

export function securityHeaders(req: Request, res: Response, next: NextFunction): void {
  res.setHeader("Cache-Control", "no-store");
  helmetMiddleware(req, res, next);
}

/** One line per request: route TEMPLATE, never the URL, query values, bodies or tokens. */
export function accessLog(logger: Logger): RequestHandler {
  return (req, res, next) => {
    const start = process.hrtime.bigint();
    res.on("finish", () => {
      const route = req.route?.path !== undefined ? `${req.baseUrl}${String(req.route.path)}` : req.baseUrl || "unmatched";
      logger.info(
        {
          requestId: req.requestId,
          method: req.method,
          route,
          status: res.statusCode,
          latencyMs: Number((process.hrtime.bigint() - start) / 1000n) / 1000,
          sub: req.principal?.sub,
          tenantId: req.principal?.tenantId,
        },
        "request",
      );
    });
    next();
  };
}

export function rateLimit(limiter: RateLimiter, key: (req: Request) => string): RequestHandler {
  return (req, _res, next) => {
    const retry = limiter.take(key(req));
    if (retry > 0) {
      next(new AppError("RATE_LIMITED", undefined, undefined, retry));
      return;
    }
    next();
  };
}

/**
 * D5/D22: verify the bearer ID token, then build the frozen Principal. Failed
 * attempts count toward the per-IP pre-auth limiter; past it, 429 before any
 * verification work is done.
 */
export function authenticate(verifier: TokenVerifier, preAuth: RateLimiter): RequestHandler {
  return async (req, _res, next) => {
    const ipKey = req.source.ip ?? "unknown";
    const retry = preAuth.blocked(ipKey);
    if (retry > 0) throw new AppError("RATE_LIMITED", undefined, undefined, retry);
    const token = bearer(req.get("authorization"));
    if (!token) {
      preAuth.take(ipKey);
      throw new AppError("UNAUTHENTICATED");
    }
    let claims;
    try {
      claims = await verifier.verify(token);
    } catch {
      preAuth.take(ipKey);
      throw new AppError("UNAUTHENTICATED");
    }
    req.principal = toPrincipal(claims);
    next();
  };
}
