import { createHash } from "node:crypto";
import { Readable } from "node:stream";
import { mockClient } from "aws-sdk-client-mock";
import { GetObjectCommand, GetObjectRetentionCommand, GetObjectLegalHoldCommand, GetObjectLockConfigurationCommand, S3Client } from "@aws-sdk/client-s3";
import { bucketLock, checkRecord, chainOfCustody, verifyAll, MAX_RECORDS } from "../src/soc/evidence";

// moto 5.2.4 cannot serve GetObjectRetention to the JS SDK (Step 0), so the
// retention / legal-hold / size cases run against a mocked S3 client.
describe("evidence hardening (unit, mocked S3)", () => {
  const s3 = mockClient(S3Client);
  afterEach(() => s3.reset());
  const client = new S3Client({ region: "us-east-1" });
  const rec = (o: Partial<{ bucket: string | null; key: string; versionId: string | null; sha256: string | null; sha256Base64: string | null }> = {}) => ({ bucket: "ev", key: "incidents/a/x.json", versionId: null, sha256: "a".repeat(64), sha256Base64: null, ...o });

  it("refuses a foreign bucket or a key outside incidents/ without calling S3", async () => {
    expect((await checkRecord(client, "ev", rec({ bucket: "other" }))).error).toBe("foreign-bucket");
    expect((await checkRecord(client, "ev", rec({ key: "tenants/t/docs/x" }))).error).toBe("key-outside-incidents-prefix");
    expect((await checkRecord(client, "ev", rec({ key: "incidents/../tenants/x" }))).error).toBe("key-outside-incidents-prefix");
    expect(s3.calls()).toHaveLength(0);
  });

  it("aborts objects above 5 MiB and reports retention / legal hold as found", async () => {
    s3.on(GetObjectCommand).resolves({ ContentLength: 6 * 1024 * 1024, Body: Readable.from([Buffer.alloc(1)]) as never });
    expect((await checkRecord(client, "ev", rec())).error).toBe("too-large");
    s3.reset();
    s3.on(GetObjectCommand).callsFake(() => ({ Body: Readable.from([Buffer.alloc(3 * 1024 * 1024), Buffer.alloc(3 * 1024 * 1024)]) }));
    expect((await checkRecord(client, "ev", rec())).error).toBe("too-large");
    s3.reset();
    const body = Buffer.from("x");
    const sha = createHash("sha256").update(body).digest("hex");
    s3.on(GetObjectCommand).resolves({ Body: Readable.from([body]) as never });
    s3.on(GetObjectRetentionCommand).resolves({ Retention: { Mode: "GOVERNANCE", RetainUntilDate: new Date("2027-01-01T00:00:00Z") } });
    s3.on(GetObjectLegalHoldCommand).resolves({ LegalHold: { Status: "ON" } });
    const ok = await checkRecord(client, "ev", rec({ sha256: sha }));
    expect(ok).toMatchObject({ ok: true, retention: { mode: "GOVERNANCE", retainUntil: "2027-01-01T00:00:00.000Z" }, legalHold: true });
    s3.on(GetObjectRetentionCommand).rejects(Object.assign(new Error("x"), { name: "NoSuchObjectLockConfiguration" }));
    s3.on(GetObjectLegalHoldCommand).resolves({ LegalHold: { Status: "OFF" } });
    expect(await checkRecord(client, "ev", rec({ sha256: sha }))).toMatchObject({ retention: null, legalHold: false });
  });

  it("reports Object Lock off, unknown, or a default retention", async () => {
    s3.on(GetObjectLockConfigurationCommand).rejects(Object.assign(new Error("x"), { name: "ObjectLockConfigurationNotFoundError" }));
    expect(await bucketLock(client, "ev")).toEqual({ enabled: false, mode: null, days: null });
    s3.reset();
    s3.on(GetObjectLockConfigurationCommand).rejects(Object.assign(new Error("x"), { name: "AccessDenied" }));
    expect(await bucketLock(client, "ev")).toEqual({ enabled: null, mode: null, days: null });
    s3.reset();
    s3.on(GetObjectLockConfigurationCommand).resolves({ ObjectLockConfiguration: { ObjectLockEnabled: "Enabled", Rule: { DefaultRetention: { Mode: "COMPLIANCE", Years: 1 } } } });
    expect(await bucketLock(client, "ev")).toEqual({ enabled: true, mode: "COMPLIANCE", days: 365 });
  });

  it("never claims an intact chain for a truncated check", async () => {
    s3.on(GetObjectCommand).callsFake(() => ({ Body: Readable.from([Buffer.from("x")]) }));
    const sha = createHash("sha256").update("x").digest("hex");
    const many = Array.from({ length: MAX_RECORDS + 1 }, () => rec({ sha256: sha }));
    const out = await verifyAll(client, "ev", many);
    expect(out.checks).toHaveLength(MAX_RECORDS);
    expect(out.truncated).toBe(true);
    expect(out.chainOfCustodyOk).toBeNull();
    expect(chainOfCustody([], false)).toBeNull();
  });
});

