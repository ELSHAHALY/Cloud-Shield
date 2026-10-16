// The only way the SPA talks to docs-api (plan §12). Attaches the Cognito ID
// token, parses RFC 9457 problems, re-authenticates once on 401 and routes
// AGREEMENT_REQUIRED to onboarding. Security is enforced by the server.
import type { Problem } from "./types";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly requestId: string | undefined,
    readonly retryAfterSeconds?: number,
  ) {
    super(`${status} ${code}`);
    this.name = "ApiError";
  }
}

export interface ClientOptions {
  getToken(forceRefresh?: boolean): Promise<string | null>;
  onUnauthenticated(): void;
  onAgreementRequired(): void;
  fetchImpl?: typeof fetch;
  base?: string;
}

type Accept = "json" | "text" | "blob";

export interface RequestOptions {
  body?: unknown;
  raw?: Blob | ArrayBuffer | Uint8Array;
  contentType?: string;
  headers?: Record<string, string>;
  accept?: Accept;
}

export interface ApiClient {
  request<T>(method: string, path: string, opts?: RequestOptions): Promise<T>;
  get<T>(path: string, accept?: Accept): Promise<T>;
  post<T>(path: string, body: unknown): Promise<T>;
  put<T>(path: string, body: unknown): Promise<T>;
  patch<T>(path: string, body: unknown, headers?: Record<string, string>): Promise<T>;
  del(path: string): Promise<undefined>;
}

async function toError(res: Response): Promise<ApiError> {
  let problem: Partial<Problem> = {};
  if ((res.headers.get("content-type") ?? "").includes("json")) {
    try {
      problem = (await res.json()) as Partial<Problem>;
    } catch {
      problem = {};
    }
  }
  const retry = Number(res.headers.get("retry-after"));
  return new ApiError(res.status, typeof problem.code === "string" ? problem.code : "HTTP_ERROR", problem.requestId, Number.isFinite(retry) && retry > 0 ? retry : undefined);
}

export function createApiClient(o: ClientOptions): ApiClient {
  const doFetch = o.fetchImpl ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
  const base = o.base ?? "/api";

  async function send(method: string, path: string, opts: RequestOptions, token: string | null): Promise<Response> {
    const headers: Record<string, string> = { Accept: opts.accept === "text" || opts.accept === "blob" ? "*/*" : "application/json", ...opts.headers };
    if (token) headers.Authorization = `Bearer ${token}`;
    let body: BodyInit | undefined;
    if (opts.raw !== undefined) {
      body = opts.raw as BodyInit;
      headers["Content-Type"] = opts.contentType ?? "application/octet-stream";
    } else if (opts.body !== undefined) {
      body = JSON.stringify(opts.body);
      headers["Content-Type"] = "application/json";
    }
    return doFetch(`${base}${path}`, { method, headers, body, credentials: "omit", cache: "no-store", redirect: "error" });
  }

  async function request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
    let res = await send(method, path, opts, await o.getToken());
    if (res.status === 401) {
      const fresh = await o.getToken(true);
      if (fresh) res = await send(method, path, opts, fresh);
      if (res.status === 401) {
        o.onUnauthenticated();
        throw await toError(res);
      }
    }
    if (!res.ok) {
      const err = await toError(res);
      if (err.code === "AGREEMENT_REQUIRED") o.onAgreementRequired();
      throw err;
    }
    if (res.status === 204) return undefined as T;
    if (opts.accept === "text") return (await res.text()) as T;
    if (opts.accept === "blob") return (await res.blob()) as T;
    return (await res.json()) as T;
  }

  return {
    request,
    get: (path, accept) => request("GET", path, accept ? { accept } : {}),
    post: (path, body) => request("POST", path, { body }),
    put: (path, body) => request("PUT", path, { body }),
    patch: (path, body, headers) => request("PATCH", path, { body, ...(headers ? { headers } : {}) }),
    del: (path) => request<undefined>("DELETE", path),
  };
}

export function messageFor(err: unknown): string {
  if (!(err instanceof ApiError)) return "Something went wrong. Try again.";
  const ref = err.requestId ? ` (reference ${err.requestId})` : "";
  const text: Record<string, string> = {
    UNAUTHENTICATED: "Your session has ended. Sign in again.",
    FORBIDDEN: "You do not have permission for this action.",
    AGREEMENT_REQUIRED: "Your tenant administrator must accept the required agreements first.",
    NOT_FOUND: "Not found.",
    VALIDATION_FAILED: "Some fields are invalid.",
    CONFLICT: "This changed in the meantime. Reload and try again.",
    PRECONDITION_FAILED: "Someone else edited this document. Reload and try again.",
    PAYLOAD_TOO_LARGE: "The file is too large.",
    UNSUPPORTED_MEDIA_TYPE: "The file type does not match its content.",
    INTEGRITY_MISMATCH: "The uploaded bytes did not match their checksum. Try again.",
    RATE_LIMITED: "Too many requests. Wait a moment.",
    SERVICE_UNAVAILABLE: "This part of the service is unavailable right now.",
  };
  return (text[err.code] ?? "Something went wrong.") + ref;
}
