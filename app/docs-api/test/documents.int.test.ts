import { GetCommand } from "@aws-sdk/lib-dynamodb";
import { GetObjectCommand, HeadObjectCommand, ListObjectVersionsCommand } from "@aws-sdk/client-s3";
import { QueryCommand, DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { api, makeApp, sha256Hex, type TestApp } from "./helpers/app";
import { acceptAll, createDoc, uploadedDoc } from "./helpers/flows";
import { createResources, raw, testConfig, type Resources } from "./helpers/moto";

const doc = DynamoDBDocumentClient.from(raw.ddb as unknown as DynamoDBClient);
let r: Resources;
let t: TestApp;

beforeAll(async () => {
  r = await createResources();
  t = await makeApp(testConfig(r));
  await acceptAll(t, "alice");
});

async function auditActions(tenant: string): Promise<string[]> {
  const out = await raw.ddb.send(
    new QueryCommand({ TableName: r.auditTable, KeyConditionExpression: "tenantId = :t", ExpressionAttributeValues: { ":t": { S: tenant } } }),
  );
  return (out.Items ?? []).map((i) => i.action?.S ?? "").filter(Boolean);
}

describe("documents: happy path", () => {
  it("creates, uploads, lists, reads, patches, downloads and deletes, auditing every change", async () => {
    const d = await createDoc(t, "bob", "first doc\n", { tags: ["q3", "${x}:#y"], description: "desc" });
    expect(d.meta).toMatchObject({ status: "PENDING_UPLOAD", version: 1, ownerSub: "sub-bob", tags: ["q3", "${x}:#y"] });

    const up = await api(t).put(`/documents/${d.meta.docId}/content`).set(...d.auth).set("Content-Type", "text/plain").send(d.body).expect(200);
    expect(up.body).toMatchObject({ status: "AVAILABLE", version: 2 });
    expect(up.body).not.toHaveProperty("s3VersionId");

    const obj = await raw.s3.send(new HeadObjectCommand({ Bucket: r.documentsBucket, Key: `tenants/t-acme-01/docs/${d.meta.docId}` }));
    expect(obj.ServerSideEncryption).toBe("aws:kms");
    expect(obj.SSEKMSKeyId).toBe(r.kmsKeyArn);

    const list = await api(t).get("/documents").set(...d.auth).expect(200);
    expect(list.body.items.map((i: { docId: string }) => i.docId)).toContain(d.meta.docId);

    await api(t).get(`/documents/${d.meta.docId}`).set(...d.auth).expect(200);

    const patched = await api(t).patch(`/documents/${d.meta.docId}`).set(...d.auth).set("If-Match", '"2"').send({ title: "Renamed" }).expect(200);
    expect(patched.body).toMatchObject({ title: "Renamed", version: 3, tags: ["q3", "${x}:#y"] });
    await api(t).patch(`/documents/${d.meta.docId}`).set(...d.auth).set("If-Match", '"2"').send({ title: "Stale" }).expect(412);

    const dl = await api(t).get(`/documents/${d.meta.docId}/download`).set(...d.auth).expect(200);
    const url = new URL(dl.body.url);
    expect(url.host).toBe("localhost:5000");
    expect(Number(url.searchParams.get("X-Amz-Expires"))).toBeLessThanOrEqual(300);
    expect(url.searchParams.get("versionId")).toBeTruthy();
    expect(url.searchParams.get("response-content-disposition")).toMatch(/^attachment; filename="Renamed.txt"; filename\*=UTF-8''Renamed.txt$/);

    await api(t).delete(`/documents/${d.meta.docId}`).set(...d.auth).expect(204);
    await api(t).get(`/documents/${d.meta.docId}`).set(...d.auth).expect(404);
    const item = await doc.send(new GetCommand({ TableName: r.documentsTable, Key: { tenantId: "t-acme-01", docId: `doc#${d.meta.docId}` } }));
    expect(item.Item).toMatchObject({ status: "DELETED" });
    expect(item.Item).not.toHaveProperty("title");
    expect(item.Item).not.toHaveProperty("description");
    expect(item.Item).not.toHaveProperty("tags");
    const versions = await raw.s3.send(new ListObjectVersionsCommand({ Bucket: r.documentsBucket, Prefix: `tenants/t-acme-01/docs/${d.meta.docId}` }));
    expect(versions.DeleteMarkers?.length).toBe(1);
    // DELETE is idempotent on a tombstone
    await api(t).delete(`/documents/${d.meta.docId}`).set(...d.auth).expect(204);

    const actions = await auditActions("t-acme-01");
    for (const a of ["DOCUMENT_CREATED", "DOCUMENT_UPLOADED", "DOCUMENT_UPDATED", "DOCUMENT_DOWNLOAD_URL_ISSUED", "DOCUMENT_DELETED", "AGREEMENT_ACCEPTED"]) {
      expect(actions).toContain(a);
    }
  });

  it("encodes hostile titles in the download disposition", async () => {
    const d = await uploadedDoc(t, "alice", "x\n");
    await api(t).patch(`/documents/${d.meta.docId}`).set(...d.auth).send({ title: 'a"b\r\nSet-Cookie: x=1; é/..\\' }).expect(200);
    const dl = await api(t).get(`/documents/${d.meta.docId}/download`).set(...d.auth).expect(200);
    const disp = new URL(dl.body.url).searchParams.get("response-content-disposition")!;
    expect(disp).not.toMatch(/[\r\n]/);
    expect(disp.split('filename="')[1]!.split('"')[0]).toMatch(/^[A-Za-z0-9._ -]+$/);
    expect(disp).toContain("filename*=UTF-8''");
    expect(disp).toContain("%C3%A9");
  });

  it("paginates with an opaque cursor and never crosses tenants", async () => {
    for (let i = 0; i < 3; i++) await createDoc(t, "alice", `page ${i}\n`);
    const { auth } = await t.as("alice");
    const first = await api(t).get("/documents?limit=2").set(...auth).expect(200);
    expect(first.body.items).toHaveLength(2);
    expect(first.body.nextCursor).toBeDefined();
    const second = await api(t).get(`/documents?limit=2&cursor=${first.body.nextCursor}`).set(...auth).expect(200);
    expect(second.body.items.length).toBeGreaterThan(0);
    // mallory replays acme's cursor: the partition is rebuilt from her token
    const m = await t.as("mallory");
    const cross = await api(t).get(`/documents?cursor=${first.body.nextCursor}`).set(...m.auth).expect(200);
    expect(cross.body.items).toEqual([]);
    await api(t).get("/documents?cursor=bm90LWpzb24").set(...auth).expect(400);
  });
});

describe("documents: IDOR and ABAC", () => {
  it("returns 404 for another tenant's document on every route and leaves it unchanged", async () => {
    const d = await uploadedDoc(t, "alice", "acme secret\n");
    const { auth } = await t.as("mallory");
    await api(t).get(`/documents/${d.meta.docId}`).set(...auth).expect(404);
    await api(t).get(`/documents/${d.meta.docId}/download`).set(...auth).expect(404);
    await api(t).patch(`/documents/${d.meta.docId}`).set(...auth).send({ title: "pwned" }).expect((res) => expect([403, 404]).toContain(res.status));
    await api(t).delete(`/documents/${d.meta.docId}`).set(...auth).expect((res) => expect([403, 404]).toContain(res.status));
    const still = await api(t).get(`/documents/${d.meta.docId}`).set(...d.auth).expect(200);
    expect(still.body.title).toBe("Quarterly report");
  });

  it("lets a member write only their own documents", async () => {
    const d = await uploadedDoc(t, "bob", "bob's\n");
    const bea = await t.as("bea");
    await api(t).patch(`/documents/${d.meta.docId}`).set(...bea.auth).send({ title: "bea" }).expect(403);
    await api(t).delete(`/documents/${d.meta.docId}`).set(...bea.auth).expect(403);
    const pending = await createDoc(t, "bob", "pending\n");
    await api(t).put(`/documents/${pending.meta.docId}/content`).set(...bea.auth).set("Content-Type", "text/plain").send(pending.body).expect(403);
    // admin may write any document in the tenant
    const alice = await t.as("alice");
    await api(t).patch(`/documents/${d.meta.docId}`).set(...alice.auth).send({ classification: "restricted" }).expect(200);
  });

  it("forbids writes by auditors and the SOC role", async () => {
    const carol = await t.as("carol");
    await api(t).post("/documents").set(...carol.auth).send({ title: "x", contentType: "text/plain", sizeBytes: 1, sha256: "a".repeat(64), classification: "public" }).expect(403);
    const sam = await t.as("sam");
    await api(t).get("/documents").set(...sam.auth).expect(403);
  });
});

describe("documents: upload checks", () => {
  it("rejects a SHA-256 mismatch with 422 and leaves the item pending", async () => {
    const d = await createDoc(t, "alice", "abc\n");
    await api(t).put(`/documents/${d.meta.docId}/content`).set(...d.auth).set("Content-Type", "text/plain").send(Buffer.from("abd\n")).expect(422);
    const g = await api(t).get(`/documents/${d.meta.docId}`).set(...d.auth).expect(200);
    expect(g.body.status).toBe("PENDING_UPLOAD");
  });

  it("rejects bad magic bytes (415), a content type that differs from the declared one (415) and oversize bodies (413)", async () => {
    const pdfLie = Buffer.from("not a pdf");
    const d = await createDoc(t, "alice", pdfLie, { contentType: "application/pdf" });
    await api(t).put(`/documents/${d.meta.docId}/content`).set(...d.auth).set("Content-Type", "application/pdf").send(pdfLie).expect(415);
    const txt = await createDoc(t, "alice", "plain\n");
    await api(t).put(`/documents/${txt.meta.docId}/content`).set(...txt.auth).set("Content-Type", "image/png").send(txt.body).expect(415);
    const nul = Buffer.from([0x61, 0x00, 0x62]);
    const n = await createDoc(t, "alice", nul);
    await api(t).put(`/documents/${n.meta.docId}/content`).set(...n.auth).set("Content-Type", "text/plain").send(nul).expect(415);
    const big = Buffer.alloc(70 * 1024, 0x61);
    await api(t).post("/documents").set(...txt.auth).send({ title: "big", contentType: "text/plain", sizeBytes: big.length, sha256: sha256Hex(big), classification: "public" }).expect(413);
    await api(t).put(`/documents/${txt.meta.docId}/content`).set(...txt.auth).set("Content-Type", "text/plain").send(big).expect(413);
  });

  it("accepts real PNG, JPEG, PDF and DOCX signatures", async () => {
    const samples: [string, Buffer][] = [
      ["image/png", Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2])],
      ["image/jpeg", Buffer.from([0xff, 0xd8, 0xff, 0xe0, 1])],
      ["application/pdf", Buffer.from("%PDF-1.7\n")],
      ["application/vnd.openxmlformats-officedocument.wordprocessingml.document", Buffer.from([0x50, 0x4b, 0x03, 0x04, 9])],
    ];
    for (const [type, body] of samples) {
      const d = await createDoc(t, "alice", body, { contentType: type });
      await api(t).put(`/documents/${d.meta.docId}/content`).set(...d.auth).set("Content-Type", type).send(body).expect(200);
      const got = await raw.s3.send(new GetObjectCommand({ Bucket: r.documentsBucket, Key: `tenants/t-acme-01/docs/${d.meta.docId}` }));
      expect(got.ContentType).toBe(type);
    }
  });

  it("refuses a second upload and downloads of pending documents (409)", async () => {
    const d = await createDoc(t, "alice", "once\n");
    await api(t).get(`/documents/${d.meta.docId}/download`).set(...d.auth).expect(409);
    await api(t).patch(`/documents/${d.meta.docId}`).set(...d.auth).send({ title: "x" }).expect(409);
    await api(t).put(`/documents/${d.meta.docId}/content`).set(...d.auth).set("Content-Type", "text/plain").send(d.body).expect(200);
    await api(t).put(`/documents/${d.meta.docId}/content`).set(...d.auth).set("Content-Type", "text/plain").send(d.body).expect(409);
  });
});

describe("agreement gate", () => {
  it("blocks every document write until the tenant accepted the required agreements", async () => {
    const { auth } = await t.as("dina");
    const res = await api(t).post("/documents").set(...auth).send({ title: "x", contentType: "text/plain", sizeBytes: 1, sha256: "a".repeat(64), classification: "public" }).expect(403);
    expect(res.body.code).toBe("AGREEMENT_REQUIRED");
    await api(t).get("/documents").set(...auth).expect(200);
    const actions = await auditActions("t-nile-02");
    expect(actions).toContain("ACCESS_DENIED");
  });
});
