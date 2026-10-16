import { describe, expect, it, vi } from "vitest";
import { ApiError, createApiClient, messageFor } from "./client";

function res(status: number, body?: unknown, headers: Record<string, string> = {}) {
  const isJson = body !== undefined && typeof body !== "string";
  return new Response(body === undefined ? null : isJson ? JSON.stringify(body) : (body as string), {
    status,
    headers: { ...(isJson ? { "content-type": status >= 400 ? "application/problem+json" : "application/json" } : {}), ...headers },
  });
}

describe("apiClient", () => {
  it("attaches the bearer token and parses JSON", async () => {
    const fetchImpl = vi.fn(async () => res(200, { ok: 1 }));
    const api = createApiClient({ getToken: async () => "tok", onUnauthenticated: vi.fn(), onAgreementRequired: vi.fn(), fetchImpl });
    expect(await api.get("/me")).toEqual({ ok: 1 });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/me");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok");
    expect(init.credentials).toBe("omit");
  });

  it("sends JSON bodies and raw uploads with the declared type", async () => {
    const fetchImpl = vi.fn(async () => res(200, {}));
    const api = createApiClient({ getToken: async () => null, onUnauthenticated: vi.fn(), onAgreementRequired: vi.fn(), fetchImpl });
    await api.post("/documents", { a: 1 });
    await api.request("PUT", "/documents/x/content", { raw: new Uint8Array([1]), contentType: "text/plain" });
    await api.patch("/documents/x", { t: 1 }, { "If-Match": '"2"' });
    await api.put("/grc/profile", {});
    const headers = fetchImpl.mock.calls.map((c) => (c as unknown as [string, RequestInit])[1].headers as Record<string, string>);
    expect(headers[0]!["Content-Type"]).toBe("application/json");
    expect(headers[0]!.Authorization).toBeUndefined();
    expect(headers[1]!["Content-Type"]).toBe("text/plain");
    expect(headers[2]!["If-Match"]).toBe('"2"');
  });

  it("refreshes the token once on 401, then signs out", async () => {
    const onUnauthenticated = vi.fn();
    const getToken = vi.fn(async (force?: boolean) => (force ? "fresh" : "stale"));
    const fetchImpl = vi.fn().mockResolvedValueOnce(res(401, { code: "UNAUTHENTICATED" })).mockResolvedValueOnce(res(200, { ok: true }));
    const api = createApiClient({ getToken, onUnauthenticated, onAgreementRequired: vi.fn(), fetchImpl });
    expect(await api.get("/me")).toEqual({ ok: true });
    expect(getToken).toHaveBeenCalledWith(true);
    const fetch2 = vi.fn(async () => res(401, { code: "UNAUTHENTICATED", requestId: "r1" }));
    const api2 = createApiClient({ getToken, onUnauthenticated, onAgreementRequired: vi.fn(), fetchImpl: fetch2 });
    await expect(api2.get("/me")).rejects.toMatchObject({ status: 401, code: "UNAUTHENTICATED", requestId: "r1" });
    expect(onUnauthenticated).toHaveBeenCalledTimes(1);
  });

  it("routes AGREEMENT_REQUIRED to onboarding and exposes Retry-After", async () => {
    const onAgreementRequired = vi.fn();
    const fetchImpl = vi.fn().mockResolvedValueOnce(res(403, { code: "AGREEMENT_REQUIRED" })).mockResolvedValueOnce(res(429, { code: "RATE_LIMITED" }, { "retry-after": "7" })).mockResolvedValueOnce(res(500, "oops"));
    const api = createApiClient({ getToken: async () => "t", onUnauthenticated: vi.fn(), onAgreementRequired, fetchImpl });
    await expect(api.post("/documents", {})).rejects.toBeInstanceOf(ApiError);
    expect(onAgreementRequired).toHaveBeenCalled();
    await expect(api.get("/x")).rejects.toMatchObject({ code: "RATE_LIMITED", retryAfterSeconds: 7 });
    await expect(api.get("/x")).rejects.toMatchObject({ status: 500, code: "HTTP_ERROR" });
  });

  it("handles 204, text and blob responses", async () => {
    const fetchImpl = vi.fn().mockResolvedValueOnce(res(204)).mockResolvedValueOnce(res(200, "plain")).mockResolvedValueOnce(res(200, "blob!"));
    const api = createApiClient({ getToken: async () => "t", onUnauthenticated: vi.fn(), onAgreementRequired: vi.fn(), fetchImpl });
    expect(await api.del("/documents/x")).toBeUndefined();
    expect(await api.get("/agreements/dpa/2026-10/text", "text")).toBe("plain");
    expect(await (await api.get<Blob>("/report", "blob")).text()).toBe("blob!");
  });

  it("maps codes to safe messages", () => {
    expect(messageFor(new ApiError(403, "FORBIDDEN", "rid"))).toContain("permission");
    expect(messageFor(new ApiError(403, "FORBIDDEN", "rid"))).toContain("rid");
    expect(messageFor(new ApiError(418, "WEIRD", undefined))).toBe("Something went wrong.");
    expect(messageFor(new Error("x"))).toContain("Try again");
  });
});
