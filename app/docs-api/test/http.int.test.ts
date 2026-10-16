// Security headers, error model and request-id behaviour on 2xx/4xx/5xx.
import { api, makeApp, type TestApp } from "./helpers/app";
import { createResources, testConfig } from "./helpers/moto";

let t: TestApp;
beforeAll(async () => {
  t = await makeApp(testConfig(await createResources()));
});

function expectHeaders(res: { headers: Record<string, string> }) {
  expect(res.headers["x-request-id"]).toMatch(/^[0-9a-f-]{36}$/);
  expect(res.headers["cache-control"]).toBe("no-store");
  expect(res.headers["content-security-policy"]).toBe("default-src 'none';frame-ancestors 'none'");
  expect(res.headers["x-frame-options"]).toBe("DENY");
  expect(res.headers["x-content-type-options"]).toBe("nosniff");
  expect(res.headers["referrer-policy"]).toBe("no-referrer");
  expect(res.headers["strict-transport-security"]).toBe("max-age=31536000; includeSubDomains");
  expect(res.headers["cross-origin-resource-policy"]).toBe("same-origin");
  expect(res.headers["cross-origin-opener-policy"]).toBe("same-origin");
  expect(res.headers["x-powered-by"]).toBeUndefined();
  expect(res.headers["access-control-allow-origin"]).toBeUndefined();
}

describe("headers and errors", () => {
  it("sets the headers on 2xx, 401, 404 and 500, and ignores an inbound X-Request-Id", async () => {
    const ok = await api(t).get("/healthz").set("X-Request-Id", "attacker-chosen").expect(200);
    expect(ok.body).toEqual({ status: "ok" });
    expect(ok.headers["x-request-id"]).not.toBe("attacker-chosen");
    expectHeaders(ok);
    const unauth = await api(t).get("/documents").expect(401);
    expectHeaders(unauth);
    expect(unauth.headers["www-authenticate"]).toBe('Bearer error="invalid_token"');
    expect(unauth.headers["content-type"]).toMatch(/^application\/problem\+json/);
    expect(unauth.body).toEqual({ type: "urn:cloudshield:problem:unauthenticated", title: "Unauthorized", status: 401, code: "UNAUTHENTICATED", requestId: unauth.headers["x-request-id"] });
    const { auth } = await t.as("alice");
    const nf = await api(t).get("/nope").set(...auth).expect(404);
    expectHeaders(nf);
    expect(nf.body.code).toBe("NOT_FOUND");

    jest.spyOn(t.deps.services.agreements, "list").mockImplementationOnce(() => {
      throw Object.assign(new Error("User: arn:aws:sts::123456789012:assumed-role/x is not authorized"), { name: "AccessDeniedException" });
    });
    const boom = await api(t).get("/agreements").set(...auth).expect(500);
    expectHeaders(boom);
    expect(boom.body).toEqual({ type: "urn:cloudshield:problem:internal", title: "Internal Server Error", status: 500, code: "INTERNAL", requestId: boom.headers["x-request-id"] });
    expect(JSON.stringify(boom.body)).not.toContain("arn:aws");
    expect(t.logs.join("")).toContain("unhandled error");
  });

  it("maps a malformed JSON body to a generic 400 and a wrong content type to 415", async () => {
    const { auth } = await t.as("alice");
    const bad = await api(t).post("/documents").set(...auth).set("Content-Type", "application/json").send('{"title": ').expect(400);
    expect(bad.body).toMatchObject({ code: "VALIDATION_FAILED", detail: "malformed JSON body" });
    const big = await api(t).post("/documents").set(...auth).set("Content-Type", "application/json").send(JSON.stringify({ title: "x".repeat(70 * 1024) })).expect(413);
    expect(big.body.code).toBe("PAYLOAD_TOO_LARGE");
    const form = await api(t).post("/documents").set(...auth).set("Content-Type", "text/xml").send("<a/>");
    expect([400, 415]).toContain(form.status);
  });

  it("returns TENANT_INVALID for a token without a valid tenant", async () => {
    const res = await api(t).get("/me").set("Authorization", `Bearer ${await t.token("alice", { tenant: "_platform" })}`).expect(403);
    expect(res.body.code).toBe("TENANT_INVALID");
    const none = await api(t).get("/me").set("Authorization", `Bearer ${await t.token("alice", { tenant: null })}`).expect(403);
    expect(none.body.code).toBe("TENANT_INVALID");
  });

  it("serves /me from the verified claims only", async () => {
    const { auth } = await t.as("carol");
    const me = await api(t).get("/me").set(...auth).set("X-Tenant-Id", "t-nile-02").expect(200);
    expect(me.body).toEqual({ sub: "sub-carol", email: "sub-carol@example.test", tenantId: "t-acme-01", groups: ["auditor"], permissions: ["doc:read", "audit:read", "agreement:read", "grc:read", "grc:assess"] });
  });

  it("rate-limits repeated authentication failures per IP with Retry-After", async () => {
    const fresh = await makeApp(testConfig(await createResources()));
    for (let i = 0; i < 60; i++) await api(fresh).get("/me").set("CloudFront-Viewer-Address", "198.51.100.99:1").set("Authorization", "Bearer x.y.z").expect(401);
    const limited = await api(fresh).get("/me").set("CloudFront-Viewer-Address", "198.51.100.99:1").set("Authorization", `Bearer ${await fresh.token("alice")}`).expect(429);
    expect(limited.body.code).toBe("RATE_LIMITED");
    expect(Number(limited.headers["retry-after"])).toBeGreaterThan(0);
    await api(fresh).get("/me").set("CloudFront-Viewer-Address", "198.51.100.100:1").set("Authorization", `Bearer ${await fresh.token("alice")}`).expect(200);
  });
});

describe("GRC routes", () => {
  const profile = { jurisdictions: ["EG", "EU"], sector: "financial", cbeRegulated: true, processesPersonalData: true, processesSensitiveData: true, governmentData: false, dataSubjectRegions: ["EG", "EU"] };

  it("stores a versioned profile, audits it and assesses it with the disclaimer", async () => {
    const admin = await t.as("alice");
    const auditor = await t.as("carol");
    await api(t).get("/grc/profile").set(...admin.auth).expect(404);
    await api(t).get("/grc/assessment").set(...auditor.auth).expect(404);
    const v1 = await api(t).put("/grc/profile").set(...admin.auth).send(profile).expect(200);
    expect(v1.body).toMatchObject({ profile, version: 1, updatedBy: "sub-alice" });
    const v2 = await api(t).put("/grc/profile").set(...admin.auth).send({ ...profile, sector: "general" }).expect(200);
    expect(v2.body.version).toBe(2);
    expect((await api(t).get("/grc/profile").set(...auditor.auth).expect(200)).body.profile.sector).toBe("general");
    const a = await api(t).get("/grc/assessment").set(...auditor.auth).expect(200);
    expect(a.body.disclaimer).toContain("not legal advice");
    expect(a.body.profileVersion).toBe(2);
    expect(a.body.rulesetSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(a.body.platformFacts).toMatchObject({ deploymentRegions: ["us-east-1"], deploymentCountries: ["US"], incidentAutomation: "dry-run" });
    expect(a.body.findings.find((f: { ruleId: string }) => f.ruleId === "EG-PDPL-SCOPE-CBE").status).toBe("INFO");
    const rs = await api(t).get("/grc/ruleset").set(...auditor.auth).expect(200);
    expect(rs.body.sha256).toBe(a.body.rulesetSha256);
    const audit = await api(t).get("/audit?limit=100").set(...auditor.auth).expect(200);
    expect(audit.body.items.filter((e: { action: string }) => e.action === "GRC_PROFILE_UPDATED")).toHaveLength(2);
  });

  it("answers 503 on GRC routes only when the ruleset is invalid", async () => {
    const broken = await makeApp(testConfig(await createResources()), { grc: null });
    const { auth } = await broken.as("alice");
    expect((await api(broken).get("/grc/ruleset").set(...auth).expect(503)).body.code).toBe("SERVICE_UNAVAILABLE");
    await api(broken).get("/grc/responsibility-matrix").set(...auth).expect(503);
    await api(broken).put("/grc/profile").set(...auth).send(profile).expect(503);
    await api(broken).get("/me").set(...auth).expect(200);
  });
});
