// One place builds every AWS client. In local mode each client is pinned to
// the validated emulator endpoint (D22); in aws mode the config validator has
// already refused every endpoint override, so the SDK resolves real endpoints.
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { S3Client } from "@aws-sdk/client-s3";
import { EventBridgeClient } from "@aws-sdk/client-eventbridge";
import { SSMClient } from "@aws-sdk/client-ssm";
import { ECRClient } from "@aws-sdk/client-ecr";
import type { Config } from "../config";

export interface AwsClients {
  ddb: DynamoDBDocumentClient;
  s3: S3Client;
  /** Signs download URLs; in local mode its host is the browser-reachable S3_PUBLIC_ENDPOINT. */
  s3Presign: S3Client;
  events: EventBridgeClient;
  ssm: SSMClient;
  ecr: ECRClient;
}

export function createClients(config: Config): AwsClients {
  const base = {
    region: config.region,
    maxAttempts: 3,
    ...(config.mode === "local" && config.endpoint ? { endpoint: config.endpoint } : {}),
  };
  const local = config.mode === "local";
  const ddb = DynamoDBDocumentClient.from(new DynamoDBClient(base), {
    marshallOptions: { removeUndefinedValues: true, convertClassInstanceToMap: false },
  });
  const s3 = new S3Client({ ...base, forcePathStyle: local });
  const s3Presign = new S3Client({
    ...base,
    forcePathStyle: local,
    ...(local && config.s3PublicEndpoint ? { endpoint: config.s3PublicEndpoint } : {}),
  });
  return {
    ddb,
    s3,
    s3Presign,
    events: new EventBridgeClient(base),
    ssm: new SSMClient(base),
    ecr: new ECRClient(base),
  };
}
