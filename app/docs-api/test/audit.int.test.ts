import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb";
import type { Request } from "express";
import { AuditLog, auditWindow, toPublicEvent } from "../src/audit/audit";
import type { TenantId } from "../src/auth/principal";
import { AppError } from "../src/lib/errors";
import { api, makeApp, type TestApp } from "./helpers/app";
import { acceptAll, createDoc } from "./helpers/flows";
import { createResources, raw, testConfig, type Resources } from "./helpers/moto";

const ddb = DynamoDBDocumentClient.from(raw.ddb);
let r: Resources;
let t: TestApp;
beforeAll(async () => {
  r = await createResources();
  t = await makeApp(testConfig(r));
  await acceptAll(t, "alice");
});

function fakeReq(requestId = "00000000-0000-4000-8000-000000000001"): Request {
  return { requestId, source: { ip: "203.0.113.7", trusted: true }, get: (h: string) => (h === "user-agent" ? "ua\u0007bad" : undefined) } as unknown as Request;
}

describe("audit trail", () => {
  it("always sends attribute_not_exists and surfaces a duplicate key instead of overwriting", async () => {
    const fixed = new Date("2026-10-16T12:00:00.123Z");
    const log = new AuditLog(ddb, r.auditTable, () => fixed);
    const event = log.build(fakeReq(), { partition: "t-acme-01" as TenantId, action: "DOCUMENT_CREATED", resource: { type: "document", id: "x" }, details: { sizeBytes: 1, smuggled: "nope" } as never });
    expect(event.eventKey).toBe("2026-10-16T12:00:00.123Z#00000000-0000-4000-8000-000000000001");
    expect(event.details).toEqual({ sizeBytes: 1 });
    expect(event.userAgent).toBe("uabad");
    expect(log.transactPut(event).Put.ConditionExpression).toBe("attribute_not_exists(eventKey)");
    await log.put(event);
    await expect(log.put({ ...event, action: "DOCUMENT_DELETED" })).rejects.toMatchObject({ name: "ConditionalCheckFailedException" });
  });

  it("matches the §5.4 schema and excludes agreement markers from the tenant trail", async () => {
    await createDoc(t, "alice", "audited\n");
    const { auth } = await t.as("carol");
    const res = await api(t).get("/audit?limit=100").set(...auth).expect(200);
    const actions = res.body.items.map((e: { action: string }) => e.action);
    expect(actions).toContain("DOCUMENT_CREATED");
    expect(actions).toContain("AGREEMENT_ACCEPTED");
    expect(res.body.items.every((e: { eventKey: string }) => /^\d{4}-/.test(e.eventKey))).toBe(true);
    const created = res.body.items.find((e: { action: string }) => e.action === "DOCUMENT_CREATED");
    expect(created).toMatchObject({ schemaVersion: "1", outcome: "SUCCESS", actor: { type: "user", sub: "sub-alice", tenantId: "t-acme-01", groups: ["admin"] }, resource: { type: "document" }, sourceIpTrusted: false, sourceIp: null });
  });

  it("paginates newest first and validates the cursor and the window", async () => {
    const { auth } = await t.as("alice");
    const first = await api(t).get("/audit?limit=1").set(...auth).expect(200);
    const second = await api(t).get(`/audit?limit=1&cursor=${first.body.nextCursor}`).set(...auth).expect(200);
    expect(second.body.items[0].eventKey < first.body.items[0].eventKey).toBe(true);
    await api(t).get("/audit?from=2026-10-20T00:00:00Z&to=2026-10-01T00:00:00Z").set(...auth).expect(400);
    await api(t).get("/audit?from=yesterday").set(...auth).expect(400);
  });

  it("keeps _platform unreachable through /audit", async () => {
    await ddb.send(new PutCommand({ TableName: r.auditTable, Item: { tenantId: "_platform", eventKey: `${new Date().toISOString()}#00000000-0000-4000-8000-0000000000aa`, action: "DECOY_ROUTE_HIT", requestId: "x", eventId: "e", at: new Date().toISOString(), details: {} } }));
    for (const user of ["alice", "carol"] as const) {
      const { auth } = await t.as(user);
      const res = await api(t).get("/audit?limit=100").set(...auth).expect(200);
      expect(res.body.items.some((e: { action: string }) => e.action === "DECOY_ROUTE_HIT")).toBe(false);
    }
  });

  it("caps ACCESS_DENIED events at 10 per minute per user", async () => {
    const { auth } = await t.as("carol");
    for (let i = 0; i < 14; i++) await api(t).post("/documents").set(...auth).send({ title: "x", contentType: "text/plain", sizeBytes: 1, sha256: "a".repeat(64), classification: "public" }).expect(403);
    const res = await api(t).get("/audit?limit=100").set(...auth).expect(200);
    const denied = res.body.items.filter((e: { action: string; actor: { sub: string } }) => e.action === "ACCESS_DENIED" && e.actor.sub === "sub-carol");
    expect(denied.length).toBe(10);
    expect(denied[0]).toMatchObject({ outcome: "DENIED", details: { code: "FORBIDDEN", method: "POST", route: "/documents" } });
  });

  it("projects stored rows to the public schema only", () => {
    const e = toPublicEvent({ eventKey: "k", eventId: "e", at: "a", action: "DOCUMENT_UPLOADED", requestId: "r", actor: { type: "user", sub: "s", groups: ["admin", 7], secret: 1 }, resource: { id: "d" }, details: { sha256: "h", secret: "x" }, extra: "leak" });
    expect(e).not.toHaveProperty("extra");
    expect(e.actor).toEqual({ type: "user", sub: "s", groups: ["admin"] });
    expect(e.details).toEqual({ sha256: "h" });
    expect(e.resource).toEqual({ type: "unknown", id: "d" });
    expect(toPublicEvent({ action: "NOPE", actor: null, details: null }).details).toEqual({});
  });

  it("defaults the window to 30 days", () => {
    const now = new Date("2026-10-16T00:00:00.000Z");
    expect(auditWindow(undefined, undefined, now)).toEqual({ from: "2026-09-16T00:00:00.000Z", to: "2026-10-16T00:00:00.000Z" });
    expect(() => auditWindow(["a"], undefined, now)).toThrow(AppError);
  });
});
