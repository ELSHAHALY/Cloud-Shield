// Regression tests for the Phase E independent audit (E1, E3, E4, E5, E9, E10).
import { mockClient } from "aws-sdk-client-mock";
import { DescribeImageScanFindingsCommand, ECRClient } from "@aws-sdk/client-ecr";
import { api, makeApp, type TestApp } from "./helpers/app";
import { acceptAll, uploadedDoc } from "./helpers/flows";
import { createResources, testConfig } from "./helpers/moto";
import { isConditionFailure, rethrowUnlessConditionFailure } from "../src/lib/ddb-errors";
import { safeFieldError } from "../src/middleware/errors";
import { ecrScan, parseImage } from "../src/posture/posture";
import { chainOfCustody } from "../src/soc/evidence";
import { clean, wellFormed, attachmentDisposition } from "../src/lib/sanitize";

let t: TestApp;
beforeAll(async () => {
  t = await makeApp(testConfig(await createResources()));
  await acceptAll(t, "alice");
});

describe("E1: titles with emoji and surrogates", () => {
  it("downloads a document whose title has an emoji at the 120-character cut", async () => {
    const d = await uploadedDoc(t, "alice", "emoji\n");
    await api(t).patch(`/documents/${d.meta.docId}`).set(...d.auth).send({ title: `${"a".repeat(119)}😀tail` }).expect(200);
    const dl = await api(t).get(`/documents/${d.meta.docId}/download`).set(...d.auth).expect(200);
    expect(new URL(dl.body.url).searchParams.get("response-content-disposition")).toContain("%F0%9F%98%80");
  });

  it("rejects lone surrogates on create and patch", async () => {
    const { auth } = await t.as("alice");
    const res = await api(t).post("/documents").set(...auth).set("Content-Type", "application/json").send('{"title":"x\\ud800","contentType":"text/plain","sizeBytes":1,"sha256":"' + "a".repeat(64) + '","classification":"public"}');
    expect(res.status).toBe(400);
    const d = await uploadedDoc(t, "alice", "p\n");
    const p = await api(t).patch(`/documents/${d.meta.docId}`).set(...d.auth).set("Content-Type", "application/json").send('{"tags":["\\udc00"]}');
    expect(p.status).toBe(400);
  });

  it("cuts by code point", () => {
    expect(clean("a😀b", 2)).toBe("a😀");
    expect(clean("x\ud800")).toBe("x\ufffd");
    expect(wellFormed("ok", ["ok"], undefined, 5)).toBe(true);
    expect(wellFormed(["\ud800"])).toBe(false);
    expect(attachmentDisposition("\ud800.txt")).toContain("%EF%BF%BD");
  });
});

describe("E3: no shared lock-out bucket", () => {
  it("does not limit callers without a trusted viewer address", async () => {
    const fresh = await makeApp(testConfig(await createResources()));
    for (let i = 0; i < 70; i++) await api(fresh).get("/me").set("Authorization", "Bearer a.bad.tok").expect(401);
    await api(fresh).get("/me").set("Authorization", `Bearer ${await fresh.token("alice")}`).expect(200);
  });
});

describe("E4: only ConditionalCheckFailed is a business error", () => {
  const cancelled = (...codes: string[]) => Object.assign(new Error("x"), { name: "TransactionCanceledException", CancellationReasons: codes.map((Code) => ({ Code })) });
  it("classifies cancellation reasons", () => {
    expect(isConditionFailure(Object.assign(new Error(), { name: "ConditionalCheckFailedException" }))).toBe(true);
    expect(isConditionFailure(cancelled("ConditionalCheckFailed", "None"))).toBe(true);
    expect(isConditionFailure(cancelled("None", "ThrottlingError"))).toBe(false);
    expect(isConditionFailure(cancelled("ConditionalCheckFailed", "ValidationError"))).toBe(false);
    expect(isConditionFailure(Object.assign(new Error(), { name: "TransactionCanceledException" }))).toBe(false);
    expect(() => rethrowUnlessConditionFailure(cancelled("TransactionConflict"))).toThrow(expect.objectContaining({ code: "CONFLICT" }));
    expect(() => rethrowUnlessConditionFailure(cancelled("ThrottlingError"))).toThrow("x");
    expect(() => rethrowUnlessConditionFailure(cancelled("ConditionalCheckFailed"))).not.toThrow();
  });

  it("answers 500, not 409, when a create transaction is throttled", async () => {
    const { DynamoDBDocumentClient } = await import("@aws-sdk/lib-dynamodb");
    const spy = jest.spyOn(DynamoDBDocumentClient.prototype, "send").mockImplementationOnce(async () => {
      throw Object.assign(new Error("throttled"), { name: "TransactionCanceledException", CancellationReasons: [{ Code: "ThrottlingError" }, { Code: "None" }] });
    });
    const { auth } = await t.as("alice");
    const res = await api(t).post("/documents").set(...auth).send({ title: "x", contentType: "text/plain", sizeBytes: 1, sha256: "a".repeat(64), classification: "public" });
    spy.mockRestore();
    expect(res.status).toBe(500);
  });
});

describe("E5: ECR counts only for a completed scan", () => {
  const ecr = mockClient(ECRClient);
  afterAll(() => ecr.restore());
  it("reports null counts for an unsupported image", async () => {
    ecr.on(DescribeImageScanFindingsCommand).resolves({ imageScanStatus: { status: "UNSUPPORTED_IMAGE" }, imageScanFindings: {} });
    const image = parseImage(`123456789012.dkr.ecr.us-east-1.amazonaws.com/r@sha256:${"a".repeat(64)}`, "r");
    expect(await ecrScan(new ECRClient({ region: "us-east-1" }), image)).toEqual({ status: "UNSUPPORTED_IMAGE", critical: null, high: null, medium: null, low: null, completedAt: null });
  });
});

describe("E6: an object over 5 MiB is unverified, not BROKEN", () => {
  it("returns null", () => {
    const base = { key: "incidents/a", versionId: null, recordedSha256: "a", retention: null, legalHold: null };
    expect(chainOfCustody([{ ...base, actualSha256: null, ok: false, error: "too-large" }, { ...base, actualSha256: "a", ok: true, error: null }], false)).toBeNull();
    expect(chainOfCustody([{ ...base, actualSha256: null, ok: false, error: "too-large" }, { ...base, actualSha256: "b", ok: false, error: "mismatch" }], false)).toBe(false);
  });
});

describe("E9: validation errors never echo input", () => {
  it("returns fixed messages and safe paths", async () => {
    const { auth } = await t.as("alice");
    const res = await api(t).get("/documents?%3Cscript%3Ealert(1)%3C%2Fscript%3E=1").set(...auth).expect(400);
    expect(JSON.stringify(res.body)).not.toContain("script");
    const ct = await api(t).post("/documents").set(...auth).set("Content-Type", "application/x-evil<b>").send("x");
    expect(JSON.stringify(ct.body)).not.toContain("evil");
    expect(safeFieldError({ path: "/body/title", errorCode: "maxLength.openapi.validation" })).toEqual({ path: "/body/title", message: "too long" });
    expect(safeFieldError({ path: "/query/<x>", message: "Unknown query parameter '<x>'" })).toEqual({ path: "/query", message: "invalid request" });
    expect(safeFieldError({})).toEqual({ path: "/", message: "invalid request" });
  });
});

describe("E10: audit cursor must sit in the window", () => {
  it("refuses an out-of-window cursor with 400", async () => {
    const { auth } = await t.as("alice");
    const page = await api(t).get("/audit?limit=1").set(...auth).expect(200);
    await api(t).get(`/audit?limit=1&from=2020-01-01T00:00:00Z&to=2020-01-02T00:00:00Z&cursor=${page.body.nextCursor}`).set(...auth).expect(400);
  });
});
