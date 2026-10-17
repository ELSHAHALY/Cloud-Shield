import { api, sha256Hex, type TestApp } from "./app";
import type { UserName } from "./tokens";

export async function acceptAll(t: TestApp, admin: UserName): Promise<void> {
  const { auth } = await t.as(admin);
  const list = await api(t).get("/agreements").set(...auth).expect(200);
  for (const a of list.body as { agreementId: string; version: string; sha256: string }[]) {
    const res = await api(t).post(`/agreements/${a.agreementId}/accept`).set(...auth).send({ version: a.version, sha256: a.sha256, authorityConfirmed: true });
    if (res.status !== 201 && res.status !== 200) throw new Error(`accept failed: ${res.status} ${JSON.stringify(res.body)}`);
  }
}

export async function createDoc(t: TestApp, user: UserName, content: Buffer | string = "hello world\n", extra: Record<string, unknown> = {}) {
  const body = Buffer.isBuffer(content) ? content : Buffer.from(content);
  const { auth } = await t.as(user);
  const created = await api(t)
    .post("/documents")
    .set(...auth)
    .send({ title: "Quarterly report", contentType: "text/plain", sizeBytes: body.length, sha256: sha256Hex(body), classification: "internal", ...extra });
  if (created.status !== 201) throw new Error(`create failed: ${created.status} ${JSON.stringify(created.body)}`);
  return { meta: created.body as { docId: string; version: number }, body, auth };
}

export async function uploadedDoc(t: TestApp, user: UserName, content: Buffer | string = "hello world\n") {
  const d = await createDoc(t, user, content);
  const up = await api(t).put(`/documents/${d.meta.docId}/content`).set(...d.auth).set("Content-Type", "text/plain").send(d.body);
  if (up.status !== 200) throw new Error(`upload failed: ${up.status} ${JSON.stringify(up.body)}`);
  return { ...d, meta: up.body as { docId: string; version: number } };
}
