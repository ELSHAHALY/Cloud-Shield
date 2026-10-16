import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { api, makeApp, type TestApp } from "./helpers/app";
import { acceptAll, uploadedDoc } from "./helpers/flows";
import { createResources, testConfig } from "./helpers/moto";

let t: TestApp;
beforeAll(async () => {
  t = await makeApp(testConfig(await createResources()));
  await acceptAll(t, "alice");
});

describe("query and path injection", () => {
  it("rejects qs-style operator objects and unknown query parameters", async () => {
    const { auth } = await t.as("alice");
    await api(t).get("/documents?limit[$gt]=1").set(...auth).expect(400);
    await api(t).get("/documents?limit=1&limit=2").set(...auth).expect(400);
    await api(t).get("/documents?debug=1").set(...auth).expect(400);
    const sam = await t.as("sam");
    await api(t).get("/soc/incidents?status[$ne]=x").set(...sam.auth).expect(400);
    await api(t).get("/soc/incidents?status=SCAN").set(...sam.auth).expect(400);
  });

  it.each(["..%2F..%2Fetc", "doc%23x", "%2F", "0192b3c4-0000-7000-8000-00000000000Z", "x'--"])("rejects docId %s", async (id) => {
    const { auth } = await t.as("alice");
    const res = await api(t).get(`/documents/${id}`).set(...auth);
    expect([400, 404]).toContain(res.status);
    expect(res.body.code).toMatch(/VALIDATION_FAILED|NOT_FOUND/);
  });

  it("rejects extra and prototype-polluting body properties", async () => {
    const { auth } = await t.as("alice");
    const base = { title: "x", contentType: "text/plain", sizeBytes: 1, sha256: "a".repeat(64), classification: "public" };
    await api(t).post("/documents").set(...auth).send({ ...base, ownerSub: "someone-else" }).expect(400);
    await api(t).post("/documents").set(...auth).send({ ...base, tenantId: "t-nile-02" }).expect(400);
    await api(t).post("/documents").set(...auth).set("Content-Type", "application/json").send(`{"__proto__":{"admin":true},"title":"x","contentType":"text/plain","sizeBytes":1,"sha256":"${"a".repeat(64)}","classification":"public"}`).expect(400);
    await api(t).post("/documents").set(...auth).send({ ...base, title: "a".repeat(201) }).expect(400);
    await api(t).post("/documents").set(...auth).send({ ...base, tags: ["a", "a"] }).expect(400);
    const bad = await api(t).patch("/documents/0192b3c4-0000-7000-8000-000000000000").set(...auth).send({});
    expect(bad.status).toBe(400);
  });

  it("keeps user text out of DynamoDB expressions (placeholders only)", async () => {
    const spy = jest.spyOn(DynamoDBDocumentClient.prototype, "send");
    const d = await uploadedDoc(t, "alice", "expr\n");
    const hostile = { title: "#title = :x, REMOVE ownerSub", tags: ["${}", ":v", "#t"], description: "SET status = :deleted" };
    const res = await api(t).patch(`/documents/${d.meta.docId}`).set(...d.auth).send(hostile).expect(200);
    expect(res.body).toMatchObject(hostile);
    const inputs = spy.mock.calls.map((c) => (c[0] as unknown as { input: Record<string, unknown> }).input);
    const expressions = JSON.stringify(
      inputs.flatMap((i) => {
        const items = (i.TransactItems as { Update?: Record<string, unknown>; Put?: Record<string, unknown> }[] | undefined) ?? [];
        return [i.UpdateExpression, i.ConditionExpression, i.KeyConditionExpression, i.FilterExpression, ...items.flatMap((x) => [x.Update?.UpdateExpression, x.Update?.ConditionExpression, x.Put?.ConditionExpression])];
      }),
    );
    expect(expressions).not.toContain("REMOVE ownerSub");
    expect(expressions).not.toContain("${}");
    expect(expressions).not.toContain("status = :deleted");
    spy.mockRestore();
  });
});
