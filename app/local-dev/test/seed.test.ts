import { randomBytes } from "node:crypto";
import { QueryCommand, DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { createHash } from "node:crypto";
import { main, seed, seedConfig, DOCS } from "../src/seed";

const MOTO = process.env.MOTO_ENDPOINT ?? "http://localhost:5000";
process.env.AWS_ACCESS_KEY_ID = "local-only";
process.env.AWS_SECRET_ACCESS_KEY = "local-only";

describe("seed", () => {
  it("refuses a non-local endpoint with exit code 2", async () => {
    const err = jest.spyOn(console, "error").mockImplementation(() => undefined);
    expect(await main({ AWS_ENDPOINT_URL: "https://dynamodb.us-east-1.amazonaws.com" })).toBe(2);
    expect(await main({})).toBe(2);
    expect(await main({ AWS_ENDPOINT_URL: "http://moto.evil:5000" })).toBe(2);
    err.mockRestore();
  });

  it("is idempotent and writes real hashes and a BROKEN chain for scenario C", async () => {
    const s = randomBytes(3).toString("hex");
    const c = {
      ...seedConfig({ AWS_ENDPOINT_URL: MOTO }),
      documentsTable: `seed-docs-${s}`,
      auditTable: `seed-audit-${s}`,
      documentsBucket: `seed-docs-${s}`,
      incidentsTable: `seed-inc-${s}`,
      evidenceBucket: `seed-ev-${s}`,
      busName: `seed-bus-${s}`,
      captureQueue: `seed-q-${s}`,
      dryRunParam: `/seed-${s}/dry_run`,
    };
    const log = jest.fn();
    await seed(c, new Date(), log);
    await seed(c, new Date(), log);
    const ddb = new DynamoDBClient({ region: "us-east-1", endpoint: MOTO });
    const inc = await ddb.send(new QueryCommand({ TableName: c.incidentsTable, IndexName: "status-eventTime", KeyConditionExpression: "#s = :s", ExpressionAttributeNames: { "#s": "status" }, ExpressionAttributeValues: { ":s": { S: "CONTAINED" } } }));
    expect(inc.Items!.length).toBe(7);
    const acme = await ddb.send(new QueryCommand({ TableName: c.documentsTable, KeyConditionExpression: "tenantId = :t", ExpressionAttributeValues: { ":t": { S: "t-acme-01" } } }));
    expect(acme.Items!.length).toBe(4); // 3 documents + the GRC profile, not duplicated by the second run
    const s3 = new S3Client({ region: "us-east-1", endpoint: MOTO, forcePathStyle: true });
    const d = DOCS[0];
    const obj = await s3.send(new GetObjectCommand({ Bucket: c.documentsBucket, Key: `tenants/${d.tenant}/docs/${d.id}` }));
    expect(createHash("sha256").update(await obj.Body!.transformToString()).digest("hex")).toBe(createHash("sha256").update(d.body).digest("hex"));
    const tampered = await s3.send(new GetObjectCommand({ Bucket: c.evidenceBucket, Key: "incidents/local-c-public-bucket/prestate.json" }));
    expect(await tampered.Body!.transformToString()).toContain("TAMPERED");
    const markers = await ddb.send(new QueryCommand({ TableName: c.auditTable, KeyConditionExpression: "tenantId = :t AND begins_with(eventKey, :m)", ExpressionAttributeValues: { ":t": { S: "t-acme-01" }, ":m": { S: "AGREEMENT#" } } }));
    expect(markers.Items!.length).toBe(2);
    const nile = await ddb.send(new QueryCommand({ TableName: c.auditTable, KeyConditionExpression: "tenantId = :t AND begins_with(eventKey, :m)", ExpressionAttributeValues: { ":t": { S: "t-nile-02" }, ":m": { S: "AGREEMENT#" } } }));
    expect(nile.Items!.length).toBe(0);
  });
});
