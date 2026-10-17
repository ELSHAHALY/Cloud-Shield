// Runtime configuration (plan D22). Production (`aws`) is the default and is
// strict: any local-auth or endpoint-override variable makes startup fail, so
// a mis-set task can never accept a non-Cognito token or talk to a fake data
// plane. `local` is accepted only together with an endpoint on a local host.
import path from "node:path";

export type Mode = "aws" | "local";

export interface Config {
  mode: Mode;
  port: number;
  region: string;
  contentRoot: string;
  auth: {
    clientId: string;
    // aws mode
    userPoolId?: string;
    issuer: string;
    // local mode only
    jwksUri?: string;
  };
  endpoint?: string;
  s3PublicEndpoint?: string;
  data: {
    documentsTable: string;
    auditTable: string;
    documentsBucket: string;
    kmsKeyArn: string;
    presignMaxSeconds: number;
    maxUploadBytes: number;
  };
  soc?: {
    incidentsTable: string;
    statusIndex: string;
    evidenceBucket: string;
    dryRunParam?: string;
    playbooksEnabled: boolean;
  };
  decoy: {
    publishEnabled: boolean;
    busName?: string;
    source: string;
    accountId?: string;
  };
  posture: {
    appImage?: string;
    ecrRepositoryName?: string;
  };
  logLevel: string;
}

export class ConfigError extends Error {
  constructor(readonly problems: string[]) {
    super(`invalid configuration: ${problems.join("; ")}`);
    this.name = "ConfigError";
  }
}

export const COGNITO_ISSUER_RE =
  /^https:\/\/cognito-idp\.[a-z0-9-]+\.amazonaws\.com\/[a-z0-9-]+_[A-Za-z0-9]+$/;
// eslint-disable-next-line security/detect-unsafe-regex -- bounded and unambiguous: linear time
const POOL_ID_RE = /^([a-z]{2}(?:-[a-z]+)+-\d)_[A-Za-z0-9]+$/;
const CLIENT_ID_RE = /^[A-Za-z0-9]{1,128}$/;
const LOCAL_CLIENT_ID_RE = /^[A-Za-z0-9-]{1,128}$/;
// eslint-disable-next-line security/detect-unsafe-regex -- bounded and unambiguous: linear time
const REGION_RE = /^[a-z]{2}(?:-[a-z]+)+-\d$/;
const NAME_RE = /^[A-Za-z0-9._/-]{1,255}$/;
const KMS_ARN_RE = /^arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:key\/[A-Za-z0-9-]+$/;
const ACCOUNT_RE = /^\d{12}$/;

/** Hosts a local-mode endpoint may point at (D22). */
export const LOCAL_HOSTS: ReadonlySet<string> = new Set(["moto", "localhost", "127.0.0.1", "::1"]);
const LOCAL_IDP_HOSTS: ReadonlySet<string> = new Set(["local-idp", "localhost", "127.0.0.1", "::1"]);

/** Variables that only make sense against a fake data plane or a local IdP. */
const LOCAL_ONLY_VARS = ["AUTH_LOCAL_ISSUER", "AUTH_LOCAL_JWKS_URI", "S3_PUBLIC_ENDPOINT"];

export function isLocalUrl(value: string, hosts: ReadonlySet<string> = LOCAL_HOSTS): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  if (url.username || url.password) return false;
  const host = url.hostname.replace(/^\[|\]$/g, "");
  return hosts.has(host);
}

function int(value: string | undefined, fallback: number, min: number, max: number, name: string, problems: string[]): number {
  if (value === undefined || value === "") return fallback;
  if (!/^\d{1,10}$/.test(value)) {
    problems.push(`${name} must be an integer`);
    return fallback;
  }
  const n = Number(value);
  if (n < min || n > max) problems.push(`${name} must be between ${min} and ${max}`);
  return n;
}

function bool(value: string | undefined): boolean {
  return value === "true";
}

function required(env: NodeJS.ProcessEnv, name: string, re: RegExp, problems: string[]): string {
  const value = env[name];
  if (!value) {
    problems.push(`${name} is required`);
    return "";
  }
  if (!re.test(value)) problems.push(`${name} has an invalid format`);
  return value;
}

function optional(env: NodeJS.ProcessEnv, name: string, re: RegExp, problems: string[]): string | undefined {
  const value = env[name];
  if (value === undefined || value === "") return undefined;
  if (!re.test(value)) problems.push(`${name} has an invalid format`);
  return value;
}

export function defaultContentRoot(): string {
  // <root>/docs-api/{src,dist}/config.(ts|js) -> <root> (holds openapi.yaml and grc/)
  return path.resolve(__dirname, "..", "..");
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const problems: string[] = [];
  const rawMode = env.CLOUDSHIELD_ENV ?? "aws";
  if (rawMode !== "aws" && rawMode !== "local") {
    throw new ConfigError(["CLOUDSHIELD_ENV must be aws or local"]);
  }
  const mode: Mode = rawMode;
  // The SDK also honours AWS_ENDPOINT_URL_<SERVICE> on its own.
  const endpointVars = Object.keys(env).filter((k) => k === "AWS_ENDPOINT_URL" || k.startsWith("AWS_ENDPOINT_URL_"));

  const region = env.AWS_REGION ?? (mode === "local" ? "us-east-1" : "");
  if (!REGION_RE.test(region)) problems.push("AWS_REGION is required and must be a region name");

  let auth: Config["auth"];
  let endpoint: string | undefined;
  let s3PublicEndpoint: string | undefined;

  if (mode === "aws") {
    for (const name of [...LOCAL_ONLY_VARS, ...endpointVars]) {
      if (env[name] !== undefined) problems.push(`${name} is forbidden when CLOUDSHIELD_ENV=aws`);
    }
    const userPoolId = required(env, "COGNITO_USER_POOL_ID", POOL_ID_RE, problems);
    const clientId = required(env, "COGNITO_CLIENT_ID", CLIENT_ID_RE, problems);
    const issuer = required(env, "COGNITO_ISSUER", COGNITO_ISSUER_RE, problems);
    const poolRegion = POOL_ID_RE.exec(userPoolId)?.[1];
    if (poolRegion && issuer !== `https://cognito-idp.${poolRegion}.amazonaws.com/${userPoolId}`) {
      problems.push("COGNITO_ISSUER must equal the issuer derived from COGNITO_USER_POOL_ID");
    }
    auth = { clientId, userPoolId, issuer };
  } else {
    endpoint = env.AWS_ENDPOINT_URL;
    if (!endpoint) problems.push("CLOUDSHIELD_ENV=local requires AWS_ENDPOINT_URL");
    for (const name of endpointVars) {
      const value = env[name] ?? "";
      if (!isLocalUrl(value)) problems.push(`${name} must point at a local emulator host`);
    }
    s3PublicEndpoint = env.S3_PUBLIC_ENDPOINT || undefined;
    if (s3PublicEndpoint && !isLocalUrl(s3PublicEndpoint)) {
      problems.push("S3_PUBLIC_ENDPOINT must point at a local host");
    }
    const issuer = env.AUTH_LOCAL_ISSUER ?? "";
    const jwksUri = env.AUTH_LOCAL_JWKS_URI ?? "";
    if (!isLocalUrl(issuer, LOCAL_IDP_HOSTS)) problems.push("AUTH_LOCAL_ISSUER must be a local IdP URL");
    if (!isLocalUrl(jwksUri, LOCAL_IDP_HOSTS)) problems.push("AUTH_LOCAL_JWKS_URI must be a local IdP URL");
    if (COGNITO_ISSUER_RE.test(issuer)) problems.push("AUTH_LOCAL_ISSUER must not look like a Cognito issuer");
    const clientId = required(env, "COGNITO_CLIENT_ID", LOCAL_CLIENT_ID_RE, problems);
    auth = { clientId, issuer, jwksUri };
  }

  const data: Config["data"] = {
    documentsTable: required(env, "DOCUMENTS_TABLE", NAME_RE, problems),
    auditTable: required(env, "AUDIT_TABLE", NAME_RE, problems),
    documentsBucket: required(env, "DOCUMENTS_BUCKET", NAME_RE, problems),
    kmsKeyArn: required(env, "DATA_KMS_KEY_ARN", KMS_ARN_RE, problems),
    presignMaxSeconds: int(env.PRESIGNED_URL_MAX_SECONDS, 300, 60, 3600, "PRESIGNED_URL_MAX_SECONDS", problems),
    // API Gateway REST payloads stop at 10 MB; leave headroom.
    maxUploadBytes: int(env.MAX_UPLOAD_BYTES, 5 * 1024 * 1024, 1024, 9 * 1024 * 1024, "MAX_UPLOAD_BYTES", problems),
  };

  let soc: Config["soc"];
  const incidentsTable = optional(env, "INCIDENTS_TABLE", NAME_RE, problems);
  if (incidentsTable) {
    soc = {
      incidentsTable,
      statusIndex: optional(env, "INCIDENTS_STATUS_INDEX", NAME_RE, problems) ?? "status-eventTime",
      evidenceBucket: required(env, "EVIDENCE_BUCKET", NAME_RE, problems),
      dryRunParam: optional(env, "SOAR_DRY_RUN_PARAM", NAME_RE, problems),
      playbooksEnabled: bool(env.SOAR_PLAYBOOKS_ENABLED),
    };
  }

  const decoy: Config["decoy"] = {
    publishEnabled: bool(env.DECOY_PUBLISH_ENABLED),
    busName: optional(env, "EDGE_BUS_NAME", NAME_RE, problems),
    source: env.EDGE_EVENT_SOURCE || "cloudshield.edge",
    accountId: optional(env, "AWS_ACCOUNT_ID", ACCOUNT_RE, problems),
  };
  if (decoy.source !== "cloudshield.edge") problems.push("EDGE_EVENT_SOURCE must be cloudshield.edge");

  const posture: Config["posture"] = {
    appImage: env.APP_IMAGE || undefined,
    ecrRepositoryName: optional(env, "ECR_REPOSITORY_NAME", NAME_RE, problems),
  };

  const port = int(env.PORT, 3000, 1, 65535, "PORT", problems);
  const logLevel = env.LOG_LEVEL ?? "info";
  if (!["fatal", "error", "warn", "info", "debug", "silent"].includes(logLevel)) problems.push("LOG_LEVEL is invalid");

  if (problems.length > 0) throw new ConfigError(problems);

  return {
    mode,
    port,
    region,
    contentRoot: env.CONTENT_ROOT ? path.resolve(env.CONTENT_ROOT) : defaultContentRoot(),
    auth,
    endpoint,
    s3PublicEndpoint,
    data,
    soc,
    decoy,
    posture,
    logLevel,
  };
}
