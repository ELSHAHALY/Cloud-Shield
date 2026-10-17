// Per-suite resources in the moto server (MOTO_ENDPOINT, default
// http://localhost:5000). Integration suites fail loudly without it.
import { randomBytes } from "node:crypto";
import { CreateTableCommand, DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { CreateBucketCommand, PutBucketVersioningCommand, PutObjectLockConfigurationCommand, S3Client } from "@aws-sdk/client-s3";
import { CreateEventBusCommand, EventBridgeClient } from "@aws-sdk/client-eventbridge";
import { PutParameterCommand, SSMClient } from "@aws-sdk/client-ssm";
import { CreateKeyCommand, KMSClient } from "@aws-sdk/client-kms";
import path from "node:path";
import type { Config } from "../../src/config";
import { AUDIENCE, ISSUER } from "./tokens";

export const MOTO = process.env.MOTO_ENDPOINT ?? "http://localhost:5000";
const base = { region: "us-east-1", endpoint: MOTO, credentials: { accessKeyId: "local-only", secretAccessKey: "local-only" } };

export const raw = {
  ddb: new DynamoDBClient(base),
  s3: new S3Client({ ...base, forcePathStyle: true }),
  events: new EventBridgeClient(base),
  ssm: new SSMClient(base),
  kms: new KMSClient(base),
};

export interface Resources {
  suffix: string;
  documentsTable: string;
  auditTable: string;
  documentsBucket: string;
  evidenceBucket: string;
  incidentsTable: string;
  busName: string;
  dryRunParam: string;
  kmsKeyArn: string;
}

export async function createResources(opts: { objectLock?: boolean; evidenceBucket?: string } = {}): Promise<Resources> {
  const suffix = randomBytes(4).toString("hex");
  const r: Resources = {
    suffix,
    documentsTable: `cs-test-documents-${suffix}`,
    auditTable: `cs-test-audit-${suffix}`,
    documentsBucket: `cs-test-documents-${suffix}`,
    evidenceBucket: opts.evidenceBucket ?? `cs-test-evidence-${suffix}`,
    incidentsTable: `cs-test-incidents-${suffix}`,
    busName: `cs-test-edge-${suffix}`,
    dryRunParam: `/cs-test-${suffix}/soar/dry_run`,
    kmsKeyArn: "",
  };
  const key = await raw.kms.send(new CreateKeyCommand({ Description: "test data key" }));
  r.kmsKeyArn = key.KeyMetadata!.Arn!;
  await raw.ddb.send(
    new CreateTableCommand({
      TableName: r.documentsTable,
      BillingMode: "PAY_PER_REQUEST",
      AttributeDefinitions: [
        { AttributeName: "tenantId", AttributeType: "S" },
        { AttributeName: "docId", AttributeType: "S" },
      ],
      KeySchema: [
        { AttributeName: "tenantId", KeyType: "HASH" },
        { AttributeName: "docId", KeyType: "RANGE" },
      ],
    }),
  );
  await raw.ddb.send(
    new CreateTableCommand({
      TableName: r.auditTable,
      BillingMode: "PAY_PER_REQUEST",
      AttributeDefinitions: [
        { AttributeName: "tenantId", AttributeType: "S" },
        { AttributeName: "eventKey", AttributeType: "S" },
      ],
      KeySchema: [
        { AttributeName: "tenantId", KeyType: "HASH" },
        { AttributeName: "eventKey", KeyType: "RANGE" },
      ],
    }),
  );
  await raw.ddb.send(
    new CreateTableCommand({
      TableName: r.incidentsTable,
      BillingMode: "PAY_PER_REQUEST",
      AttributeDefinitions: [
        { AttributeName: "incidentId", AttributeType: "S" },
        { AttributeName: "status", AttributeType: "S" },
        { AttributeName: "eventTime", AttributeType: "S" },
      ],
      KeySchema: [{ AttributeName: "incidentId", KeyType: "HASH" }],
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
    }),
  );
  await raw.s3.send(new CreateBucketCommand({ Bucket: r.documentsBucket }));
  await raw.s3.send(new PutBucketVersioningCommand({ Bucket: r.documentsBucket, VersioningConfiguration: { Status: "Enabled" } }));
  await raw.s3.send(new CreateBucketCommand({ Bucket: r.evidenceBucket, ...(opts.objectLock ? { ObjectLockEnabledForBucket: true } : {}) }));
  await raw.s3.send(new PutBucketVersioningCommand({ Bucket: r.evidenceBucket, VersioningConfiguration: { Status: "Enabled" } }));
  if (opts.objectLock) {
    await raw.s3.send(
      new PutObjectLockConfigurationCommand({
        Bucket: r.evidenceBucket,
        ObjectLockConfiguration: { ObjectLockEnabled: "Enabled", Rule: { DefaultRetention: { Mode: "GOVERNANCE", Days: 1 } } },
      }),
    );
  }
  await raw.events.send(new CreateEventBusCommand({ Name: r.busName }));
  await raw.ssm.send(new PutParameterCommand({ Name: r.dryRunParam, Value: "true", Type: "String", Overwrite: true }));
  return r;
}

export function testConfig(r: Resources, overrides: Partial<Config> = {}): Config {
  return {
    mode: "local",
    port: 0,
    region: "us-east-1",
    contentRoot: path.resolve(__dirname, "..", "..", ".."),
    auth: { clientId: AUDIENCE, issuer: ISSUER, jwksUri: "http://local-idp:9000/.well-known/jwks.json" },
    endpoint: MOTO,
    s3PublicEndpoint: "http://localhost:5000",
    data: {
      documentsTable: r.documentsTable,
      auditTable: r.auditTable,
      documentsBucket: r.documentsBucket,
      kmsKeyArn: r.kmsKeyArn,
      presignMaxSeconds: 300,
      maxUploadBytes: 64 * 1024,
    },
    soc: { incidentsTable: r.incidentsTable, statusIndex: "status-eventTime", evidenceBucket: r.evidenceBucket, dryRunParam: r.dryRunParam, playbooksEnabled: true },
    decoy: { publishEnabled: true, busName: r.busName, source: "cloudshield.edge", accountId: "123456789012" },
    posture: {},
    logLevel: "silent",
    ...overrides,
  };
}
