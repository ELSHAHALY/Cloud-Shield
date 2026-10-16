import { PutEventsCommand } from "@aws-sdk/client-eventbridge";
import { QueryCommand } from "@aws-sdk/client-dynamodb";
import { api, makeApp } from "./helpers/app";
import { createResources, raw, testConfig, type Resources } from "./helpers/moto";
import { decoyEvent, decoyIncidentId } from "../src/decoy/router";
import { parseViewerAddress } from "../src/middleware/source-ip";

let r: Resources;
beforeAll(async () => {
  r = await createResources();
});

async function setup(overrides: Parameters<typeof testConfig>[1] = {}) {
  let clock = new Date("2026-10-16T12:30:00.000Z");
  const t = await makeApp(testConfig(r, overrides), { now: () => clock });
  const send = jest.spyOn(t.deps.decoy.events, "send");
  return { t, send, tick: (ms: number) => (clock = new Date(clock.getTime() + ms)) };
}

const putEntries = (send: jest.SpyInstance) =>
  send.mock.calls.map((c) => c[0]).filter((c): c is PutEventsCommand => c instanceof PutEventsCommand).flatMap((c) => c.input.Entries ?? []);

async function platformAudit(): Promise<Record<string, unknown>[]> {
  const out = await raw.ddb.send(new QueryCommand({ TableName: r.auditTable, KeyConditionExpression: "tenantId = :t", ExpressionAttributeValues: { ":t": { S: "_platform" } } }));
  return (out.Items ?? []) as Record<string, unknown>[];
}

describe("decoy route", () => {
  it("fires without a token, answers exactly like an RBAC 403 and publishes the contract event", async () => {
    const { t, send } = await setup();
    const res = await api(t).get("/admin/users?id=1").set("CloudFront-Viewer-Address", "203.0.113.9:51234").set("X-Forwarded-For", "198.51.100.66").expect(403);
    const real = await api(t).get("/soc/overview").set(...(await t.as("alice")).auth).expect(403);
    expect(Object.keys(res.body).sort()).toEqual(Object.keys(real.body).sort());
    expect({ ...res.body, requestId: "x" }).toEqual({ ...real.body, requestId: "x" });
    expect(res.headers["content-type"]).toBe(real.headers["content-type"]);

    const entries = putEntries(send);
    expect(entries).toHaveLength(1);
    const e = entries[0]!;
    expect(e).toMatchObject({ EventBusName: r.busName, Source: "cloudshield.edge", DetailType: "CloudShield Edge Finding" });
    expect(e).not.toHaveProperty("Time");
    const detail = JSON.parse(e.Detail!);
    expect(detail).toEqual({
      schemaVersion: "2.0",
      id: "edge-decoy-203-0-113-9-2026101612",
      type: "CloudShield:IPAddress/DecoyRouteHit",
      severity: 5,
      createdAt: "2026-10-16T12:30:00.000Z",
      accountId: "123456789012",
      region: "us-east-1",
      resource: { resourceType: "IPAddress", ipAddressDetails: { ipAddressV4: "203.0.113.9" } },
      service: { serviceName: "cloudshield", additionalInfo: { sample: false, publisher: "docs-api-decoy", requestId: res.body.requestId, authenticated: false } },
    });
    expect(detail.id).toMatch(/^[\w.:-]{1,128}$/);
    const audit = (await platformAudit()).find((i) => (i.requestId as { S: string }).S === res.body.requestId)!;
    expect(audit).toBeDefined();
    expect(JSON.stringify(audit)).toContain("203.0.113.9");
    expect(JSON.stringify(audit)).not.toContain("198.51.100.66");
  });

  it("records the actor for a valid token and stays anonymous (tokenPresent) for an invalid one", async () => {
    const { t } = await setup({ decoy: { publishEnabled: false, source: "cloudshield.edge" } });
    const ok = await api(t).post("/admin").set("Authorization", `Bearer ${await t.token("bob")}`).set("CloudFront-Viewer-Address", "203.0.113.20:1").expect(403);
    const bad = await api(t).delete("/admin/x").set("Authorization", "Bearer a.b.c").set("CloudFront-Viewer-Address", "203.0.113.21:1").expect(403);
    const rows = await platformAudit();
    const okRow = JSON.stringify(rows.find((i) => (i.requestId as { S: string }).S === ok.body.requestId));
    const badRow = JSON.stringify(rows.find((i) => (i.requestId as { S: string }).S === bad.body.requestId));
    expect(okRow).toContain("sub-bob");
    expect(okRow).toContain("publisher-disabled");
    expect(badRow).toContain('"anonymous"');
    expect(badRow).toContain('"tokenPresent":{"BOOL":true}');
  });

  it("does not publish for an untrusted IP, a missing bus, a repeat in the same hour or past the global cap", async () => {
    const { t, send, tick } = await setup();
    await api(t).get("/admin").expect(403); // no viewer header
    await api(t).get("/admin").set("CloudFront-Viewer-Address", "203.0.113.30:1").expect(403);
    await api(t).get("/admin").set("CloudFront-Viewer-Address", "203.0.113.30:2").expect(403);
    expect(putEntries(send)).toHaveLength(1);
    tick(3_600_000);
    await api(t).get("/admin").set("CloudFront-Viewer-Address", "203.0.113.30:3").expect(403);
    expect(putEntries(send)).toHaveLength(2);
    for (let i = 0; i < 40; i++) await api(t).get("/admin").set("CloudFront-Viewer-Address", `2001:db8::${(i + 1).toString(16)}:443`);
    expect(putEntries(send).length).toBe(30);
    const v6 = JSON.parse(putEntries(send)[2]!.Detail!);
    expect(v6.resource.ipAddressDetails).toEqual({ ipAddressV6: "2001:db8::1" });

    const noBus = await setup({ decoy: { publishEnabled: true, source: "cloudshield.edge" } });
    await api(noBus.t).get("/admin").set("CloudFront-Viewer-Address", "203.0.113.40:1").expect(403);
    expect(putEntries(noBus.send)).toHaveLength(0);
  });

  it("caps audit writes at 5 per minute per IP and survives a PutEvents failure", async () => {
    const { t, send } = await setup();
    (send as jest.SpyInstance).mockRejectedValueOnce(new Error("boom"));
    const before = (await platformAudit()).length;
    for (let i = 0; i < 8; i++) await api(t).get("/admin/x").set("CloudFront-Viewer-Address", "203.0.113.50:1").expect(403);
    expect((await platformAudit()).length - before).toBe(5);
    expect(t.logs.join("")).toContain("decoy audit cap reached");
    expect(t.logs.join("")).toContain("decoy publish failed");
  });

  it("never logs the viewer address, the token or the origin secret", async () => {
    const { t } = await setup();
    const token = await t.token("bob");
    await api(t).get("/admin").set("Authorization", `Bearer ${token}`).set("x-origin-verify", "s3cr3t-origin").set("CloudFront-Viewer-Address", "203.0.113.77:1");
    await api(t).get("/me").set("Authorization", `Bearer ${token}`);
    const logs = t.logs.join("");
    expect(logs).not.toContain(token);
    expect(logs).not.toContain("s3cr3t-origin");
    expect(logs).not.toContain("203.0.113.77");
  });
});

describe("viewer address parsing", () => {
  it.each([
    ["203.0.113.7:443", "203.0.113.7"],
    ["[2001:DB8::1]:443", "2001:db8::1"],
    ["2001:db8::1:443", "2001:db8::1"],
    ["::ffff:198.51.100.2:443", "198.51.100.2"],
    ["203.0.113.7", null],
    ["203.0.113.7:99999", null],
    ["evil:80", null],
    [":80", null],
    ["", null],
    [undefined, null],
    ["1".repeat(70), null],
  ])("%s -> %s", (input, expected) => {
    expect(parseViewerAddress(input)).toBe(expected);
  });

  it("builds ids that match the finding id contract", () => {
    expect(decoyIncidentId("2001:db8::1", new Date("2026-01-02T03:04:05Z"))).toBe("edge-decoy-2001-db8--1-2026010203");
    expect(decoyEvent({ ip: "1.2.3.4", at: new Date(), region: "us-east-1", requestId: "r", authenticated: true, busName: "b", source: "cloudshield.edge" }).Detail).toContain('"accountId":""');
  });
});
