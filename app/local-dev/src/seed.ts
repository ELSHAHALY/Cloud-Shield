// Seeds the moto server for docker-compose.local.yml (plan §10). Idempotent
// (create-if-missing) and REFUSES any endpoint whose host is not a local
// emulator (exit 2): it can never write to real AWS.
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { CreateTableCommand, DynamoDBClient, waitUntilTableExists } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand, PutCommand } from "@aws-sdk/lib-dynamodb";
import { CreateBucketCommand, HeadBucketCommand, HeadObjectCommand, PutBucketVersioningCommand, PutObjectCommand, PutObjectLockConfigurationCommand, S3Client } from "@aws-sdk/client-s3";
import { CreateEventBusCommand, EventBridgeClient, PutRuleCommand, PutTargetsCommand } from "@aws-sdk/client-eventbridge";
import { CreateQueueCommand, GetQueueAttributesCommand, SQSClient } from "@aws-sdk/client-sqs";
import { PutParameterCommand, SSMClient } from "@aws-sdk/client-ssm";
import { isLocalEndpoint } from "./guard";

export interface SeedConfig {
  endpoint: string;
  region: string;
  documentsTable: string;
  auditTable: string;
  documentsBucket: string;
  incidentsTable: string;
  evidenceBucket: string;
  busName: string;
  captureQueue: string;
  dryRunParam: string;
  kmsKeyArn: string;
  agreementsDir: string;
}

export function seedConfig(env: NodeJS.ProcessEnv): SeedConfig {
  return {
    endpoint: env.AWS_ENDPOINT_URL ?? "",
    region: env.AWS_REGION ?? "us-east-1",
    documentsTable: env.DOCUMENTS_TABLE ?? "cloudshield-local-documents",
    auditTable: env.AUDIT_TABLE ?? "cloudshield-local-audit",
    documentsBucket: env.DOCUMENTS_BUCKET ?? "cloudshield-local-documents",
    incidentsTable: env.INCIDENTS_TABLE ?? "cloudshield-local-soar-incidents",
    evidenceBucket: env.EVIDENCE_BUCKET ?? "cloudshield-local-soar-evidence",
    busName: env.EDGE_BUS_NAME ?? "cloudshield-local-soar-edge",
    captureQueue: env.EDGE_CAPTURE_QUEUE ?? "cloudshield-local-edge-capture",
    dryRunParam: env.SOAR_DRY_RUN_PARAM ?? "/cloudshield-local/soar/dry_run",
    kmsKeyArn: env.DATA_KMS_KEY_ARN ?? "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-00000000c0de",
    agreementsDir: env.AGREEMENTS_DIR ?? path.resolve(__dirname, "..", "..", "grc", "agreements"),
  };
}

const sha = (b: Buffer | string) => createHash("sha256").update(b).digest();
const hex = (b: Buffer | string) => sha(b).toString("hex");
const b64 = (b: Buffer | string) => sha(b).toString("base64");
const ignore = (...names: string[]) => (err: unknown) => {
  if (!names.includes((err as { name?: string }).name ?? "")) throw err;
};

/** Fixed, valid UUIDv7 ids so re-runs are idempotent and demos can name them. */
export const DOCS = [
  { tenant: "t-acme-01", id: "0192b3c4-0000-7000-8000-00000000a001", owner: "local-alice", title: "Quarterly report", type: "text/plain", body: "Acme Q3 report: revenue up, incidents down.\n", cls: "confidential" },
  { tenant: "t-acme-01", id: "0192b3c4-0000-7000-8000-00000000a002", owner: "local-bob", title: "Network diagram", type: "application/pdf", body: "%PDF-1.4\n% CloudShield demo PDF\n1 0 obj << >> endobj\ntrailer << >>\n%%EOF\n", cls: "internal" },
  { tenant: "t-acme-01", id: "0192b3c4-0000-7000-8000-00000000a003", owner: "local-bob", title: "Holiday rota", type: "text/plain", body: "Alice: Mon-Wed\nBob: Thu-Fri\n", cls: "public" },
  { tenant: "t-nile-02", id: "0192b3c4-0000-7000-8000-00000000b001", owner: "local-dina", title: "Branch list", type: "text/plain", body: "Cairo, Alexandria, Aswan\n", cls: "internal" },
  { tenant: "t-nile-02", id: "0192b3c4-0000-7000-8000-00000000b002", owner: "local-mallory", title: "KYC procedure", type: "text/plain", body: "Verify ID, address and source of funds.\n", cls: "restricted" },
  { tenant: "t-riyadh-03", id: "0192b3c4-0000-7000-8000-00000000c001", owner: "local-omar", title: "Procurement memo", type: "text/plain", body: "Tender 2026-14: cloud hosting.\n", cls: "confidential" },
] as const;

export const PROFILES = {
  "t-acme-01": { jurisdictions: ["EU", "EG"], sector: "general", cbeRegulated: false, processesPersonalData: true, processesSensitiveData: false, governmentData: false, dataSubjectRegions: ["EU", "EG"] },
  "t-nile-02": { jurisdictions: ["EG"], sector: "financial", cbeRegulated: true, processesPersonalData: true, processesSensitiveData: true, governmentData: false, dataSubjectRegions: ["EG"] },
} as const;

function clients(c: SeedConfig) {
  const base = { region: c.region, endpoint: c.endpoint };
  return {
    ddb: new DynamoDBClient(base),
    s3: new S3Client({ ...base, forcePathStyle: true }),
    events: new EventBridgeClient(base),
    sqs: new SQSClient(base),
    ssm: new SSMClient(base),
  };
}

async function table(ddb: DynamoDBClient, name: string, keys: [string, string?], gsi = false) {
  await ddb
    .send(
      new CreateTableCommand({
        TableName: name,
        BillingMode: "PAY_PER_REQUEST",
        AttributeDefinitions: [
          { AttributeName: keys[0], AttributeType: "S" },
          ...(keys[1] ? [{ AttributeName: keys[1], AttributeType: "S" as const }] : []),
          ...(gsi ? [{ AttributeName: "status", AttributeType: "S" as const }, { AttributeName: "eventTime", AttributeType: "S" as const }] : []),
        ],
        KeySchema: [{ AttributeName: keys[0], KeyType: "HASH" }, ...(keys[1] ? [{ AttributeName: keys[1], KeyType: "RANGE" as const }] : [])],
        ...(gsi
          ? {
              GlobalSecondaryIndexes: [
                {
                  IndexName: "status-eventTime",
                  KeySchema: [
                    { AttributeName: "status", KeyType: "HASH" },
                    { AttributeName: "eventTime", KeyType: "RANGE" },
                  ],
                  Projection: { ProjectionType: "ALL" },
                },
              ],
            }
          : {}),
      }),
    )
    .catch(ignore("ResourceInUseException"));
  await waitUntilTableExists({ client: ddb, maxWaitTime: 30 }, { TableName: name });
}

async function putOnce(doc: DynamoDBDocumentClient, tableName: string, item: Record<string, unknown>, keyAttr: string) {
  await doc.send(new PutCommand({ TableName: tableName, Item: item, ConditionExpression: `attribute_not_exists(${keyAttr})` })).catch(ignore("ConditionalCheckFailedException"));
}

async function objectOnce(s3: S3Client, bucket: string, key: string, body: string | Buffer, extra: Record<string, unknown> = {}): Promise<string | undefined> {
  try {
    const head = await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
    return head.VersionId;
  } catch (err) {
    if ((err as { name?: string }).name !== "NotFound" && (err as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode !== 404) throw err;
  }
  const out = await s3.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: body, ...extra }));
  return out.VersionId;
}

function normalise(raw: string): string {
  return raw.replace(/^\ufeff/, "").replace(/\r\n?/g, "\n");
}

export async function seed(c: SeedConfig, now = new Date(), log: (m: string) => void = console.log): Promise<void> {
  const k = clients(c);
  const doc = DynamoDBDocumentClient.from(k.ddb, { marshallOptions: { removeUndefinedValues: true } });
  const iso = (msAgo: number) => new Date(now.getTime() - msAgo).toISOString();
  const event = (tenant: string, msAgo: number, action: string, actor: Record<string, unknown>, resource: Record<string, unknown>, details: Record<string, unknown> = {}) => {
    const at = iso(msAgo);
    const requestId = randomUUID();
    return { tenantId: tenant, eventKey: `${at}#${requestId}`, schemaVersion: "1", eventId: randomUUID(), at, action, outcome: action === "DECOY_ROUTE_HIT" ? "DENIED" : "SUCCESS", actor, resource, sourceIp: "198.51.100.10", sourceIpTrusted: true, userAgent: "cloudshield-seed", requestId, details };
  };

  // ---- resources ----
  await table(k.ddb, c.documentsTable, ["tenantId", "docId"]);
  await table(k.ddb, c.auditTable, ["tenantId", "eventKey"]);
  await table(k.ddb, c.incidentsTable, ["incidentId"], true);
  const exists = (Bucket: string) =>
    k.s3.send(new HeadBucketCommand({ Bucket })).then(
      () => true,
      () => false,
    );
  if (!(await exists(c.documentsBucket))) await k.s3.send(new CreateBucketCommand({ Bucket: c.documentsBucket }));
  await k.s3.send(new PutBucketVersioningCommand({ Bucket: c.documentsBucket, VersioningConfiguration: { Status: "Enabled" } }));
  if (!(await exists(c.evidenceBucket))) {
    await k.s3.send(new CreateBucketCommand({ Bucket: c.evidenceBucket, ObjectLockEnabledForBucket: true }));
    await k.s3.send(
      new PutObjectLockConfigurationCommand({ Bucket: c.evidenceBucket, ObjectLockConfiguration: { ObjectLockEnabled: "Enabled", Rule: { DefaultRetention: { Mode: "GOVERNANCE", Days: 1 } } } }),
    );
  }
  await k.events.send(new CreateEventBusCommand({ Name: c.busName })).catch(ignore("ResourceAlreadyExistsException"));
  const queue = await k.sqs.send(new CreateQueueCommand({ QueueName: c.captureQueue }));
  const queueArn = (await k.sqs.send(new GetQueueAttributesCommand({ QueueUrl: queue.QueueUrl, AttributeNames: ["QueueArn"] }))).Attributes?.QueueArn;
  await k.events.send(new PutRuleCommand({ Name: "cloudshield-local-edge-capture", EventBusName: c.busName, EventPattern: JSON.stringify({ source: ["cloudshield.edge"] }) }));
  await k.events.send(new PutTargetsCommand({ Rule: "cloudshield-local-edge-capture", EventBusName: c.busName, Targets: [{ Id: "capture", Arn: queueArn }] }));
  await k.ssm.send(new PutParameterCommand({ Name: c.dryRunParam, Value: "true", Type: "String", Overwrite: true }));
  log("resources ready");

  // Dataset sentinel in the reserved `_seed` partition (no tenant can match it).
  const sentinel = { tenantId: "_seed", docId: "meta#seeded-v1" };
  if ((await doc.send(new GetCommand({ TableName: c.documentsTable, Key: sentinel, ConsistentRead: true }))).Item) {
    log("data already seeded: nothing to do");
    return;
  }

  // ---- documents (real bytes, real SHA-256) ----
  for (const [i, d] of DOCS.entries()) {
    const key = `tenants/${d.tenant}/docs/${d.id}`;
    const versionId = await objectOnce(k.s3, c.documentsBucket, key, d.body, { ContentType: d.type, ServerSideEncryption: "aws:kms", SSEKMSKeyId: c.kmsKeyArn, ChecksumSHA256: b64(d.body) });
    const at = iso((10 - i) * 86_400_000);
    await putOnce(doc, c.documentsTable, { tenantId: d.tenant, docId: `doc#${d.id}`, title: d.title, contentType: d.type, sizeBytes: Buffer.byteLength(d.body), sha256: hex(d.body), classification: d.cls, tags: ["seed"], ownerSub: d.owner, status: "AVAILABLE", createdAt: at, updatedAt: at, version: 2, s3Key: key, s3VersionId: versionId ?? "null" }, "docId");
    await putOnce(doc, c.auditTable, event(d.tenant, (10 - i) * 86_400_000, "DOCUMENT_UPLOADED", { type: "user", sub: d.owner, tenantId: d.tenant, groups: ["member"] }, { type: "document", id: d.id }, { sha256: hex(d.body), sizeBytes: Buffer.byteLength(d.body), contentType: d.type }), "eventKey");
  }
  log(`documents: ${DOCS.length}`);

  // ---- agreements: acme accepted; nile and riyadh pending ----
  const index = JSON.parse(readFileSync(path.join(c.agreementsDir, "index.json"), "utf8")) as { agreements: { agreementId: string; version: string; file: string; current: boolean }[] };
  for (const a of index.agreements.filter((x) => x.current)) {
    const textSha256 = hex(normalise(readFileSync(path.join(c.agreementsDir, a.file), "utf8")));
    const accepted = event("t-acme-01", 9 * 86_400_000, "AGREEMENT_ACCEPTED", { type: "user", sub: "local-alice", tenantId: "t-acme-01", groups: ["admin"] }, { type: "agreement", id: `${a.agreementId}/${a.version}` }, { agreementId: a.agreementId, version: a.version, textSha256 });
    await putOnce(doc, c.auditTable, { tenantId: "t-acme-01", eventKey: `AGREEMENT#${a.agreementId}#${a.version}`, agreementId: a.agreementId, version: a.version, textSha256, textMediaType: "text/plain; charset=utf-8", acceptedBy: { sub: "local-alice", groups: ["admin"] }, acceptedAt: accepted.at, sourceIp: "198.51.100.10", sourceIpTrusted: true, userAgent: "cloudshield-seed", requestId: accepted.requestId, method: "click-through", authorityConfirmed: true, schemaVersion: "1" }, "eventKey");
    await putOnce(doc, c.auditTable, accepted, "eventKey");
  }

  // ---- GRC profiles: acme and nile; riyadh has none (shows onboarding) ----
  for (const [tenant, profile] of Object.entries(PROFILES)) {
    await putOnce(doc, c.documentsTable, { tenantId: tenant, docId: "meta#grc-profile", profile, version: 1, updatedAt: iso(8 * 86_400_000), updatedBy: tenant === "t-acme-01" ? "local-alice" : "local-dina" }, "docId");
  }
  log("agreements and GRC profiles");

  // ---- incidents (times relative to seed time) and evidence ----
  const evidence = async (incidentId: string, name: string, content: string, opts: { tamperAfter?: boolean; pin?: boolean } = {}) => {
    const key = `incidents/${incidentId}/${name}`;
    const versionId = await objectOnce(k.s3, c.evidenceBucket, key, content);
    if (opts.tamperAfter && versionId) {
      // Overwrite the current version: the unpinned record no longer matches (BROKEN chain).
      const head = await k.s3.send(new HeadObjectCommand({ Bucket: c.evidenceBucket, Key: key }));
      if (head.VersionId === versionId) await k.s3.send(new PutObjectCommand({ Bucket: c.evidenceBucket, Key: key, Body: content.replace("PRESTATE", "TAMPERED") }));
    }
    return { bucket: c.evidenceBucket, key, ...(opts.pin !== false && versionId ? { versionId } : {}), sha256: hex(content), sha256Base64: b64(content) };
  };
  const hour = iso(5 * 60_000).slice(0, 13).replace(/[-T]/g, "");
  const decoyId = `edge-decoy-203-0-113-66-${hour}`;
  const manifest = (id: string, kind: string) => `${JSON.stringify({ incidentId: id, kind, capturedAt: iso(3_000_000) })}\n`;

  const rows: Record<string, unknown>[] = [
    { incidentId: "local-a-cred-exfil", status: "CONTAINED", findingType: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", severity: 8, resourceType: "AccessKey", findingCreatedAt: iso(3_602_000), eventTime: iso(3_600_000), sfnStartedAt: iso(3_599_000), containedAt: iso(3_582_000), containmentVerified: true, attempts: 1, executionArn: "arn:aws:states:us-east-1:123456789012:execution:cloudshield-local-ir:a", actions: [{ at: iso(3_595_000), playbook: "PB-01", step: "revoke-sessions" }, { at: iso(3_590_000), playbook: "PB-01", step: "nacl-quarantine", subnet: "subnet-local" }, { at: iso(3_585_000), playbook: "PB-01", step: "ebs-snapshot" }], evidenceRecords: [await evidence("local-a-cred-exfil", "manifest.json", manifest("local-a-cred-exfil", "ebs-snapshot"))] },
    { incidentId: "local-a-recon", status: "CONTAINED", findingType: "Recon:EC2/Portscan", severity: 5, resourceType: "Instance", eventTime: iso(7_200_000), containedAt: iso(7_175_000), actions: [{ at: iso(7_190_000), playbook: "PB-01", step: "nacl-quarantine" }], evidenceRecords: [await evidence("local-a-recon", "manifest.json", manifest("local-a-recon", "ebs-snapshot"))] },
    { incidentId: "local-b-malicious-ip", status: "CONTAINED", findingType: "UnauthorizedAccess:IAMUser/MaliciousIPCaller", severity: 5, resourceType: "AccessKey", eventTime: iso(10_800_000), containedAt: iso(10_768_000), actions: [{ at: iso(10_790_000), playbook: "PB-02", step: "deactivate-access-key" }], evidenceRecords: [await evidence("local-b-malicious-ip", "key-state.json", manifest("local-b-malicious-ip", "PRESTATE"))] },
    { incidentId: "local-c-public-bucket", status: "CONTAINED", findingType: "Policy:S3/BucketBlockPublicAccessDisabled", severity: 8, resourceType: "S3Bucket", eventTime: iso(14_400_000), containedAt: iso(14_391_000), actions: [{ at: iso(14_395_000), playbook: "PB-03", step: "restore-public-access-block" }], evidenceRecords: [await evidence("local-c-public-bucket", "prestate.json", manifest("local-c-public-bucket", "PRESTATE"), { tamperAfter: true, pin: false }), await evidence("local-c-public-bucket", "poststate.json", manifest("local-c-public-bucket", "POSTSTATE"))] },
    { incidentId: "local-d-runtime", status: "WOULD_CONTAIN_DRY_RUN", findingType: "Execution:Runtime/NewBinaryExecuted", severity: 8, resourceType: "ECSCluster", eventTime: iso(18_000_000), wouldContainAt: iso(17_990_000), actions: [{ at: iso(17_995_000), playbook: "PB-04", step: "would-stop-task" }] },
    { incidentId: "local-e-waf-rate", status: "CONTAINED", findingType: "CloudShield:IPAddress/WafRateLimitExceeded", severity: 5, resourceType: "IPAddress", eventTime: iso(1_800_000), containedAt: iso(1_788_000), blockedCidr: "203.0.113.50/32", blockState: "active", blockExpiresAt: iso(-1_800_000), actions: [{ at: iso(1_790_000), playbook: "PB-05", step: "waf-ip-block" }] },
    { incidentId: decoyId, status: "BLOCKED_BY_GUARD", findingType: "CloudShield:IPAddress/DecoyRouteHit", severity: 5, resourceType: "IPAddress", eventTime: iso(300_000), sfnStartedAt: iso(299_000), guardReason: "notify-only edge finding (decoy route hit): analyst review" },
    { incidentId: "local-failed", status: "FAILED", findingType: "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B", severity: 5, resourceType: "AccessKey", eventTime: iso(21_600_000), failure: "AccessDenied: iam:UpdateAccessKey", attempts: 3 },
    { incidentId: "local-no-playbook", status: "NO_PLAYBOOK_ANALYST_REVIEW", findingType: "Trojan:EC2/DNSDataExfiltration", severity: 8, resourceType: "Instance", eventTime: iso(25_200_000) },
    { incidentId: "local-detected", status: "DETECTED", findingType: "Recon:IAMUser/MaliciousIPCaller", severity: 2, resourceType: "AccessKey", eventTime: iso(60_000) },
    { incidentId: "local-a-recon-2", status: "CONTAINED", findingType: "Recon:EC2/PortProbeUnprotectedPort", severity: 2, resourceType: "Instance", eventTime: iso(86_000_000), containedAt: iso(85_960_000) },
    { incidentId: "local-crypto", status: "CONTAINED", findingType: "CryptoCurrency:Runtime/BitcoinTool.B", severity: 8, resourceType: "ECSCluster", eventTime: iso(43_200_000), containedAt: iso(43_178_000) },
  ];
  for (const row of rows) await putOnce(doc, c.incidentsTable, row, "incidentId");
  await putOnce(doc, c.auditTable, event("_platform", 300_000, "DECOY_ROUTE_HIT", { type: "anonymous", tokenPresent: false }, { type: "decoy-route", id: "/admin/users" }, { method: "GET", path: "/admin/users", query: null, incidentId: decoyId, published: true, publishSkipped: null, tokenPresent: false, authenticated: false }), "eventKey");
  await putOnce(doc, c.documentsTable, { ...sentinel, seededAt: now.toISOString() }, "docId");
  log(`incidents: ${rows.length}`);
}

export async function main(env: NodeJS.ProcessEnv = process.env): Promise<number> {
  const c = seedConfig(env);
  if (!isLocalEndpoint(c.endpoint)) {
    console.error("refusing to seed: AWS_ENDPOINT_URL must point at a local emulator (moto, localhost, 127.0.0.1, ::1)");
    return 2;
  }
  await seed(c);
  console.log("seed complete");
  return 0;
}

/* istanbul ignore next */
if (require.main === module) {
  main().then(
    (code) => process.exit(code),
    (err: unknown) => {
      console.error(err);
      process.exit(1);
    },
  );
}
