import { createHash } from "node:crypto";
import { DynamoDBDocumentClient, GetCommand } from "@aws-sdk/lib-dynamodb";
import { mkdtempSync, cpSync, writeFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadCatalogue, normaliseText } from "../src/agreements/catalogue";
import { api, makeApp, type TestApp } from "./helpers/app";
import { createResources, raw, testConfig, type Resources } from "./helpers/moto";

const ddb = DynamoDBDocumentClient.from(raw.ddb);
const CONTENT = path.resolve(__dirname, "..", "..");
let r: Resources;
let t: TestApp;
beforeAll(async () => {
  r = await createResources();
  t = await makeApp(testConfig(r));
});

async function catalogue(user: "alice" | "bob") {
  const { auth } = await t.as(user);
  return { auth, list: (await api(t).get("/agreements").set(...auth).expect(200)).body as { agreementId: string; version: string; sha256: string; required: boolean }[] };
}

describe("agreements (click-through acceptance logging)", () => {
  it("serves the catalogue with server-computed hashes and the text as text/plain", async () => {
    const { auth, list } = await catalogue("alice");
    expect(list.map((a) => a.agreementId).sort()).toEqual(["dpa", "sla"]);
    const text = await api(t).get("/agreements/dpa/2026-10/text").set(...auth).expect(200);
    expect(text.headers["content-type"]).toMatch(/^text\/plain; charset=utf-8/);
    expect(createHash("sha256").update(text.text, "utf8").digest("hex")).toBe(list.find((a) => a.agreementId === "dpa")!.sha256);
    await api(t).get("/agreements/dpa/2099-01/text").set(...auth).expect(404);
  });

  it("only admin accepts; stale hash 409; unknown version 404; first acceptance wins", async () => {
    const { list } = await catalogue("alice");
    const dpa = list.find((a) => a.agreementId === "dpa")!;
    const bob = await t.as("bob");
    await api(t).post("/agreements/dpa/accept").set(...bob.auth).send({ version: dpa.version, sha256: dpa.sha256, authorityConfirmed: true }).expect(403);
    const alice = await t.as("alice");
    await api(t).post("/agreements/dpa/accept").set(...alice.auth).send({ version: dpa.version, sha256: "b".repeat(64), authorityConfirmed: true }).expect(409);
    await api(t).post("/agreements/dpa/accept").set(...alice.auth).send({ version: "2099-01", sha256: dpa.sha256, authorityConfirmed: true }).expect(404);
    await api(t).post("/agreements/dpa/accept").set(...alice.auth).send({ version: dpa.version, sha256: dpa.sha256, authorityConfirmed: false }).expect(400);

    const first = await api(t).post("/agreements/dpa/accept").set(...alice.auth).set("User-Agent", "agreement-test").set("CloudFront-Viewer-Address", "198.51.100.4:443").send({ version: dpa.version, sha256: dpa.sha256, authorityConfirmed: true }).expect(201);
    expect(first.body).toMatchObject({
      agreementId: "dpa",
      version: "2026-10",
      textSha256: dpa.sha256,
      textMediaType: "text/plain; charset=utf-8",
      acceptedBy: { sub: "sub-alice", groups: ["admin"] },
      tenantId: "t-acme-01",
      sourceIp: "198.51.100.4",
      sourceIpTrusted: true,
      userAgent: "agreement-test",
      method: "click-through",
      authorityConfirmed: true,
      schemaVersion: "1",
    });
    const again = await api(t).post("/agreements/dpa/accept").set(...alice.auth).send({ version: dpa.version, sha256: dpa.sha256, authorityConfirmed: true }).expect(200);
    expect(again.body).toEqual(first.body);
    const marker = await ddb.send(new GetCommand({ TableName: r.auditTable, Key: { tenantId: "t-acme-01", eventKey: "AGREEMENT#dpa#2026-10" } }));
    expect(marker.Item).toMatchObject({ requestId: first.body.requestId, acceptedAt: first.body.acceptedAt });

    const status = await api(t).get("/agreements/status").set(...bob.auth).expect(200);
    expect(status.body.complete).toBe(false);
    expect(status.body.pending.map((p: { agreementId: string }) => p.agreementId)).toEqual(["sla"]);
    const sla = list.find((a) => a.agreementId === "sla")!;
    await api(t).post("/agreements/sla/accept").set(...alice.auth).send({ version: sla.version, sha256: sla.sha256, authorityConfirmed: true }).expect(201);
    expect((await api(t).get("/agreements/status").set(...bob.auth).expect(200)).body.complete).toBe(true);
  });

  it("fails closed (503) on agreement routes and document writes when the catalogue cannot load", async () => {
    const broken = await makeApp(testConfig(r), { catalogue: null });
    const { auth } = await broken.as("alice");
    expect((await api(broken).get("/agreements").set(...auth).expect(503)).body.code).toBe("SERVICE_UNAVAILABLE");
    await api(broken).post("/documents").set(...auth).send({ title: "x", contentType: "text/plain", sizeBytes: 1, sha256: "a".repeat(64), classification: "public" }).expect(503);
    await api(broken).get("/documents").set(...auth).expect(200);
  });
});

describe("catalogue loader", () => {
  it("normalises text and refuses unsafe or duplicate entries", () => {
    expect(normaliseText("﻿a\r\nb\rc")).toBe("a\nb\nc");
    const dir = mkdtempSync(path.join(os.tmpdir(), "cat-"));
    try {
      cpSync(path.join(CONTENT, "grc"), path.join(dir, "grc"), { recursive: true });
      const index = path.join(dir, "grc", "agreements", "index.json");
      const good = loadCatalogue(dir);
      expect(good.required().length).toBe(2);
      writeFileSync(index, JSON.stringify({ schemaVersion: "1", agreements: [{ agreementId: "dpa", version: "2026-10", title: "x", file: "../../etc/passwd", effectiveDate: "2026-10-16", required: true, current: true }] }));
      expect(() => loadCatalogue(dir)).toThrow();
      const entry = { agreementId: "dpa", version: "2026-10", title: "x", file: "dpa-2026-10.txt", effectiveDate: "2026-10-16", required: true, current: true };
      writeFileSync(index, JSON.stringify({ schemaVersion: "1", agreements: [entry, entry] }));
      expect(() => loadCatalogue(dir)).toThrow("duplicate");
      writeFileSync(index, JSON.stringify({ schemaVersion: "1", agreements: [entry, { ...entry, version: "2026-11" }] }));
      expect(() => loadCatalogue(dir)).toThrow("more than one current");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
