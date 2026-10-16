import type { NextFunction, Request, Response } from "express";
import type { Logger } from "pino";
import type { AuditLog } from "../audit/audit";
import { AppError, problem, type FieldError, type ProblemCode } from "../lib/errors";
import { RateLimiter } from "../lib/rate-limit";

interface ValidatorError {
  status: number;
  errors: { path?: unknown; message?: unknown }[];
  path?: unknown;
}

function isValidatorError(err: unknown): err is ValidatorError {
  return (
    err !== null &&
    typeof err === "object" &&
    typeof (err as ValidatorError).status === "number" &&
    Array.isArray((err as ValidatorError).errors) &&
    "path" in err
  );
}

function bodyParserType(err: unknown): string | undefined {
  const t = (err as { type?: unknown } | null)?.type;
  return typeof t === "string" ? t : undefined;
}

const VALIDATOR_CODES: Readonly<Record<number, ProblemCode>> = {
  400: "VALIDATION_FAILED",
  404: "NOT_FOUND",
  405: "NOT_FOUND",
  413: "PAYLOAD_TOO_LARGE",
  415: "UNSUPPORTED_MEDIA_TYPE",
};

export function notFound(_req: Request, _res: Response, next: NextFunction): void {
  next(new AppError("NOT_FOUND"));
}

export function errorHandler(logger: Logger, audit: AuditLog) {
  const deniedCap = new RateLimiter(10, 60_000);
  return async (err: unknown, req: Request, res: Response, _next: NextFunction): Promise<void> => {
    let code: ProblemCode = "INTERNAL";
    let detail: string | undefined;
    let errors: FieldError[] | undefined;
    let retryAfter: number | undefined;

    if (err instanceof AppError) {
      ({ code, detail, errors } = err);
      retryAfter = err.retryAfterSeconds;
    } else if (isValidatorError(err) && Object.prototype.hasOwnProperty.call(VALIDATOR_CODES, err.status)) {
      code = VALIDATOR_CODES[err.status]!;
      errors = err.errors.map((e) => ({ path: String(e.path ?? ""), message: String(e.message ?? "invalid") }));
    } else if (bodyParserType(err) === "entity.too.large") {
      code = "PAYLOAD_TOO_LARGE";
    } else if (bodyParserType(err) === "entity.parse.failed") {
      code = "VALIDATION_FAILED";
      detail = "malformed JSON body";
    } else if (bodyParserType(err) === "charset.unsupported" || bodyParserType(err) === "encoding.unsupported") {
      code = "UNSUPPORTED_MEDIA_TYPE";
    } else {
      // Logged with the stack server-side; the body carries only the requestId.
      logger.error({ err, requestId: req.requestId, validation: isValidatorError(err) ? err.errors : undefined }, "unhandled error");
    }

    if (code === "UNAUTHENTICATED") res.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
    if (retryAfter) res.setHeader("Retry-After", String(retryAfter));

    if ((code === "FORBIDDEN" || code === "AGREEMENT_REQUIRED") && req.principal && deniedCap.take(req.principal.sub) === 0) {
      try {
        await audit.put(
          audit.build(req, {
            partition: req.principal.tenantId,
            action: "ACCESS_DENIED",
            outcome: "DENIED",
            resource: { type: "route", id: req.route?.path !== undefined ? `${req.baseUrl}${String(req.route.path)}` : "unmatched" },
            details: { code, method: req.method, route: req.route?.path !== undefined ? `${req.baseUrl}${String(req.route.path)}` : "unmatched" },
          }),
        );
      } catch (auditErr) {
        logger.error({ err: auditErr, requestId: req.requestId }, "ACCESS_DENIED audit write failed");
      }
    }

    if (res.headersSent) {
      res.end();
      return;
    }
    res.status(problem(code, req.requestId).status).type("application/problem+json").json(problem(code, req.requestId, detail, errors));
  };
}
