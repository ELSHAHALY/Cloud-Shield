// RFC 9457 problem details (plan D11). Bodies never carry stack traces, AWS
// error messages, ARNs or input values: only a stable code and the requestId.
export type ProblemCode =
  | "UNAUTHENTICATED"
  | "TENANT_INVALID"
  | "FORBIDDEN"
  | "AGREEMENT_REQUIRED"
  | "NOT_FOUND"
  | "VALIDATION_FAILED"
  | "CONFLICT"
  | "PRECONDITION_FAILED"
  | "PAYLOAD_TOO_LARGE"
  | "UNSUPPORTED_MEDIA_TYPE"
  | "INTEGRITY_MISMATCH"
  | "RATE_LIMITED"
  | "SERVICE_UNAVAILABLE"
  | "INTERNAL";

const STATUS: Record<ProblemCode, [number, string]> = {
  UNAUTHENTICATED: [401, "Unauthorized"],
  TENANT_INVALID: [403, "Forbidden"],
  FORBIDDEN: [403, "Forbidden"],
  AGREEMENT_REQUIRED: [403, "Forbidden"],
  NOT_FOUND: [404, "Not Found"],
  VALIDATION_FAILED: [400, "Bad Request"],
  CONFLICT: [409, "Conflict"],
  PRECONDITION_FAILED: [412, "Precondition Failed"],
  PAYLOAD_TOO_LARGE: [413, "Content Too Large"],
  UNSUPPORTED_MEDIA_TYPE: [415, "Unsupported Media Type"],
  INTEGRITY_MISMATCH: [422, "Unprocessable Content"],
  RATE_LIMITED: [429, "Too Many Requests"],
  SERVICE_UNAVAILABLE: [503, "Service Unavailable"],
  INTERNAL: [500, "Internal Server Error"],
};

export interface FieldError {
  path: string;
  message: string;
}

export interface Problem {
  type: string;
  title: string;
  status: number;
  code: ProblemCode;
  requestId: string;
  detail?: string;
  errors?: FieldError[];
}

export class AppError extends Error {
  readonly status: number;
  constructor(
    readonly code: ProblemCode,
    readonly detail?: string,
    readonly errors?: FieldError[],
    readonly retryAfterSeconds?: number,
  ) {
    super(code);
    this.name = "AppError";
    this.status = STATUS[code][0];
  }
}

export function statusOf(code: ProblemCode): number {
  return STATUS[code][0];
}

export function problem(code: ProblemCode, requestId: string, detail?: string, errors?: FieldError[]): Problem {
  const [status, title] = STATUS[code];
  const body: Problem = {
    type: `urn:cloudshield:problem:${code.toLowerCase().replace(/_/g, "-")}`,
    title,
    status,
    code,
    requestId,
  };
  if (detail) body.detail = detail.slice(0, 256);
  if (errors && errors.length > 0) {
    body.errors = errors.slice(0, 20).map((e) => ({ path: e.path.slice(0, 256), message: e.message.slice(0, 256) }));
  }
  return body;
}
