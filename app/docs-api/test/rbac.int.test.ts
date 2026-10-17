// Plan §4.2 as a table: every route × every group → allowed or 403.
// "Allowed" means the request got past RBAC (any status but 401/403).
import { api, makeApp, sha256Hex, type TestApp } from "./helpers/app";
import { acceptAll } from "./helpers/flows";
import { createResources, testConfig } from "./helpers/moto";
import type { UserName } from "./helpers/tokens";

let t: TestApp;
let dpaSha = "";
const MISSING = "0192b3c4-0000-7000-8000-000000000000";
const body = Buffer.from("rbac\n");

beforeAll(async () => {
  const r = await createResources();
  t = await makeApp(testConfig(r));
  await acceptAll(t, "alice");
  const { auth } = await t.as("alice");
  dpaSha = (await api(t).get("/agreements").set(...auth)).body.find((a: { agreementId: string }) => a.agreementId === "dpa").sha256;
});

type Who = "admin" | "member" | "auditor" | "secops";
const USER: Record<Who, UserName> = { admin: "alice", member: "bob", auditor: "carol", secops: "sam" };
const ALL: Who[] = ["admin", "member", "auditor", "secops"];
const profile = { jurisdictions: ["EU"], sector: "general", cbeRegulated: false, processesPersonalData: true, processesSensitiveData: false, governmentData: false, dataSubjectRegions: ["EU"] };

const ROUTES: { name: string; allowed: Who[]; send: (auth: [string, string]) => Promise<{ status: number }> }[] = [
  { name: "GET /me", allowed: ALL, send: (a) => api(t).get("/me").set(...a) },
  { name: "GET /documents", allowed: ["admin", "member", "auditor"], send: (a) => api(t).get("/documents").set(...a) },
  {
    name: "POST /documents",
    allowed: ["admin", "member"],
    send: (a) => api(t).post("/documents").set(...a).send({ title: "r", contentType: "text/plain", sizeBytes: body.length, sha256: sha256Hex(body), classification: "public" }),
  },
  { name: "GET /documents/{id}", allowed: ["admin", "member", "auditor"], send: (a) => api(t).get(`/documents/${MISSING}`).set(...a) },
  { name: "PATCH /documents/{id}", allowed: ["admin", "member"], send: (a) => api(t).patch(`/documents/${MISSING}`).set(...a).send({ title: "x" }) },
  { name: "DELETE /documents/{id}", allowed: ["admin", "member"], send: (a) => api(t).delete(`/documents/${MISSING}`).set(...a) },
  { name: "PUT /documents/{id}/content", allowed: ["admin", "member"], send: (a) => api(t).put(`/documents/${MISSING}/content`).set(...a).set("Content-Type", "text/plain").send(body) },
  { name: "GET /documents/{id}/download", allowed: ["admin", "member", "auditor"], send: (a) => api(t).get(`/documents/${MISSING}/download`).set(...a) },
  { name: "GET /audit", allowed: ["admin", "auditor"], send: (a) => api(t).get("/audit").set(...a) },
  { name: "GET /agreements", allowed: ALL, send: (a) => api(t).get("/agreements").set(...a) },
  { name: "GET /agreements/status", allowed: ALL, send: (a) => api(t).get("/agreements/status").set(...a) },
  { name: "GET /agreements/{id}/{v}/text", allowed: ALL, send: (a) => api(t).get("/agreements/dpa/2026-10/text").set(...a) },
  { name: "POST /agreements/{id}/accept", allowed: ["admin"], send: (a) => api(t).post("/agreements/dpa/accept").set(...a).send({ version: "2026-10", sha256: dpaSha, authorityConfirmed: true }) },
  { name: "GET /grc/ruleset", allowed: ALL, send: (a) => api(t).get("/grc/ruleset").set(...a) },
  { name: "GET /grc/responsibility-matrix", allowed: ALL, send: (a) => api(t).get("/grc/responsibility-matrix").set(...a) },
  { name: "GET /grc/profile", allowed: ["admin", "auditor"], send: (a) => api(t).get("/grc/profile").set(...a) },
  { name: "PUT /grc/profile", allowed: ["admin"], send: (a) => api(t).put("/grc/profile").set(...a).send(profile) },
  { name: "GET /grc/assessment", allowed: ["admin", "auditor"], send: (a) => api(t).get("/grc/assessment").set(...a) },
  { name: "GET /soc/overview", allowed: ["secops"], send: (a) => api(t).get("/soc/overview").set(...a) },
  { name: "GET /soc/incidents", allowed: ["secops"], send: (a) => api(t).get("/soc/incidents?status=FAILED").set(...a) },
  { name: "GET /soc/incidents/{id}", allowed: ["secops"], send: (a) => api(t).get("/soc/incidents/nope").set(...a) },
  { name: "GET /soc/incidents/{id}/evidence", allowed: ["secops"], send: (a) => api(t).get("/soc/incidents/nope/evidence").set(...a) },
  { name: "GET /soc/incidents/{id}/report", allowed: ["secops"], send: (a) => api(t).get("/soc/incidents/nope/report").set(...a) },
  { name: "GET /soc/metrics", allowed: ["secops"], send: (a) => api(t).get("/soc/metrics").set(...a) },
  { name: "GET /soc/posture", allowed: ["secops"], send: (a) => api(t).get("/soc/posture").set(...a) },
  { name: "GET /soc/audit", allowed: ["secops"], send: (a) => api(t).get("/soc/audit").set(...a) },
];

describe.each(ROUTES)("$name", (route) => {
  it.each(ALL)("as %s", async (who) => {
    const { auth } = await t.as(USER[who]);
    const res = await route.send(auth);
    if (route.allowed.includes(who)) {
      expect([401, 403]).not.toContain(res.status);
      // fail closed must not masquerade as "allowed": content and SOC config are present here
      expect(res.status).not.toBe(503);
    }
    else expect(res.status).toBe(403);
  });
});

it("a user with no known group can only call /me", async () => {
  const { auth } = await t.as("nobody");
  await api(t).get("/me").set(...auth).expect(200);
  for (const route of ROUTES.filter((x) => x.name !== "GET /me")) expect((await route.send(auth)).status).toBe(403);
});

it("every route except /healthz and the decoy needs a token", async () => {
  for (const route of ROUTES) {
    const res = await route.send(["X-No-Auth", "1"]);
    expect(res.status).toBe(401);
  }
});
