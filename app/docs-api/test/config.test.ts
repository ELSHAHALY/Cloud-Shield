import { ConfigError, isLocalUrl, loadConfig, defaultContentRoot } from "../src/config";

const POOL = "us-east-1_AbCdEf123";
const AWS_ENV = {
  AWS_REGION: "us-east-1",
  COGNITO_USER_POOL_ID: POOL,
  COGNITO_CLIENT_ID: "4h5j6k7l8m9n0p1q2r3s4t5u6v",
  COGNITO_ISSUER: `https://cognito-idp.us-east-1.amazonaws.com/${POOL}`,
  DOCUMENTS_TABLE: "cs-dev-documents",
  AUDIT_TABLE: "cs-dev-audit",
  DOCUMENTS_BUCKET: "cs-dev-documents-123456789012",
  DATA_KMS_KEY_ARN: "arn:aws:kms:us-east-1:123456789012:key/0f0e0d0c-0b0a-0908-0706-050403020100",
};
const LOCAL_ENV = {
  CLOUDSHIELD_ENV: "local",
  AWS_ENDPOINT_URL: "http://moto:5000",
  S3_PUBLIC_ENDPOINT: "http://localhost:5000",
  AUTH_LOCAL_ISSUER: "http://local-idp:9000",
  AUTH_LOCAL_JWKS_URI: "http://local-idp:9000/.well-known/jwks.json",
  COGNITO_CLIENT_ID: "cloudshield-local-spa",
  DOCUMENTS_TABLE: "cloudshield-local-documents",
  AUDIT_TABLE: "cloudshield-local-audit",
  DOCUMENTS_BUCKET: "cloudshield-local-documents",
  DATA_KMS_KEY_ARN: "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-4000-8000-000000000001",
};

function problems(env: NodeJS.ProcessEnv): string[] {
  try {
    loadConfig(env);
  } catch (err) {
    if (err instanceof ConfigError) return err.problems;
    throw err;
  }
  return [];
}

describe("config: aws mode (default, strict)", () => {
  it("defaults to aws and accepts a consistent Cognito configuration", () => {
    const c = loadConfig({ ...AWS_ENV });
    expect(c.mode).toBe("aws");
    expect(c.auth.issuer).toBe(AWS_ENV.COGNITO_ISSUER);
    expect(c.data.presignMaxSeconds).toBe(300);
    expect(c.data.maxUploadBytes).toBe(5 * 1024 * 1024);
    expect(c.soc).toBeUndefined();
    expect(c.contentRoot).toBe(defaultContentRoot());
  });

  it.each([
    ["AUTH_LOCAL_ISSUER", "http://local-idp:9000"],
    ["AUTH_LOCAL_JWKS_URI", "http://local-idp:9000/jwks"],
    ["AWS_ENDPOINT_URL", "http://moto:5000"],
    ["AWS_ENDPOINT_URL_S3", "http://moto:5000"],
    ["AWS_ENDPOINT_URL_DYNAMODB", ""],
    ["S3_PUBLIC_ENDPOINT", "http://localhost:5000"],
  ])("refuses to start when %s is present", (name, value) => {
    expect(problems({ ...AWS_ENV, [name]: value }).join()).toContain(`${name} is forbidden`);
  });

  it("requires an https Cognito issuer that matches the pool id", () => {
    expect(problems({ ...AWS_ENV, COGNITO_ISSUER: `http://cognito-idp.us-east-1.amazonaws.com/${POOL}` }).join()).toContain("COGNITO_ISSUER has an invalid format");
    expect(problems({ ...AWS_ENV, COGNITO_ISSUER: "http://local-idp:9000" }).join()).toContain("COGNITO_ISSUER has an invalid format");
    expect(problems({ ...AWS_ENV, COGNITO_ISSUER: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Other1" }).join()).toContain("must equal the issuer derived");
    expect(problems({ ...AWS_ENV, COGNITO_ISSUER: `https://cognito-idp.eu-west-1.amazonaws.com/${POOL}` }).join()).toContain("must equal the issuer derived");
    expect(problems({ ...AWS_ENV, COGNITO_USER_POOL_ID: undefined }).join()).toContain("COGNITO_USER_POOL_ID is required");
  });

  it("validates names, ARNs, ranges and flags", () => {
    expect(problems({ ...AWS_ENV, DATA_KMS_KEY_ARN: "alias/foo" }).join()).toContain("DATA_KMS_KEY_ARN");
    expect(problems({ ...AWS_ENV, PRESIGNED_URL_MAX_SECONDS: "7200" }).join()).toContain("between 60 and 3600");
    expect(problems({ ...AWS_ENV, PRESIGNED_URL_MAX_SECONDS: "abc" }).join()).toContain("must be an integer");
    expect(problems({ ...AWS_ENV, MAX_UPLOAD_BYTES: String(20 * 1024 * 1024) }).join()).toContain("MAX_UPLOAD_BYTES");
    expect(problems({ ...AWS_ENV, AWS_REGION: undefined }).join()).toContain("AWS_REGION");
    expect(problems({ ...AWS_ENV, EDGE_EVENT_SOURCE: "evil.source" }).join()).toContain("EDGE_EVENT_SOURCE");
    expect(problems({ ...AWS_ENV, LOG_LEVEL: "trace!" }).join()).toContain("LOG_LEVEL");
    expect(problems({ ...AWS_ENV, AWS_ACCOUNT_ID: "12" }).join()).toContain("AWS_ACCOUNT_ID");
    expect(problems({ ...AWS_ENV, INCIDENTS_TABLE: "inc" }).join()).toContain("EVIDENCE_BUCKET is required");
    expect(() => loadConfig({ ...AWS_ENV, CLOUDSHIELD_ENV: "dev" })).toThrow("CLOUDSHIELD_ENV must be aws or local");
  });

  it("reads the SOC, decoy and posture settings", () => {
    const c = loadConfig({
      ...AWS_ENV,
      INCIDENTS_TABLE: "cs-dev-soar-incidents",
      EVIDENCE_BUCKET: "cs-dev-soar-evidence",
      SOAR_PLAYBOOKS_ENABLED: "true",
      SOAR_DRY_RUN_PARAM: "/cs-dev/soar/dry_run",
      DECOY_PUBLISH_ENABLED: "true",
      EDGE_BUS_NAME: "cs-dev-soar-edge",
      AWS_ACCOUNT_ID: "123456789012",
      APP_IMAGE: "123456789012.dkr.ecr.us-east-1.amazonaws.com/cs-dev/docs-api@sha256:" + "a".repeat(64),
      ECR_REPOSITORY_NAME: "cs-dev/docs-api",
      CONTENT_ROOT: "/srv/app",
      PORT: "3000",
    });
    expect(c.soc).toEqual({ incidentsTable: "cs-dev-soar-incidents", statusIndex: "status-eventTime", evidenceBucket: "cs-dev-soar-evidence", dryRunParam: "/cs-dev/soar/dry_run", playbooksEnabled: true });
    expect(c.decoy).toMatchObject({ publishEnabled: true, busName: "cs-dev-soar-edge", accountId: "123456789012" });
    expect(c.contentRoot).toBe("/srv/app");
  });
});

describe("config: local mode is coupled to a fake data plane", () => {
  it("accepts the compose configuration", () => {
    const c = loadConfig({ ...LOCAL_ENV });
    expect(c.mode).toBe("local");
    expect(c.endpoint).toBe("http://moto:5000");
    expect(c.auth.jwksUri).toBe(LOCAL_ENV.AUTH_LOCAL_JWKS_URI);
  });

  it.each([
    ["missing endpoint", { AWS_ENDPOINT_URL: undefined }, "requires AWS_ENDPOINT_URL"],
    ["real AWS endpoint", { AWS_ENDPOINT_URL: "https://dynamodb.us-east-1.amazonaws.com" }, "local emulator host"],
    ["look-alike host", { AWS_ENDPOINT_URL: "http://moto.evil" }, "local emulator host"],
    ["credentials in URL", { AWS_ENDPOINT_URL: "http://user:pw@moto:5000" }, "local emulator host"],
    ["non-http scheme", { AWS_ENDPOINT_URL: "file:///etc/passwd" }, "local emulator host"],
    ["service endpoint to AWS", { AWS_ENDPOINT_URL_S3: "https://s3.amazonaws.com" }, "AWS_ENDPOINT_URL_S3 must point"],
    ["public S3 endpoint elsewhere", { S3_PUBLIC_ENDPOINT: "https://evil.example" }, "S3_PUBLIC_ENDPOINT"],
    ["remote issuer", { AUTH_LOCAL_ISSUER: "https://idp.example" }, "AUTH_LOCAL_ISSUER must be a local IdP URL"],
    ["remote JWKS", { AUTH_LOCAL_JWKS_URI: "https://idp.example/jwks" }, "AUTH_LOCAL_JWKS_URI"],
  ])("refuses %s", (_name, override, message) => {
    expect(problems({ ...LOCAL_ENV, ...override } as NodeJS.ProcessEnv).join()).toContain(message);
  });

  it("allows only the listed local hosts", () => {
    for (const ok of ["http://moto:5000", "http://localhost:4566", "http://127.0.0.1:5000", "http://[::1]:5000"]) expect(isLocalUrl(ok)).toBe(true);
    for (const bad of ["http://moto.local", "http://10.0.0.1", "not a url", "ftp://localhost"]) expect(isLocalUrl(bad)).toBe(false);
  });
});
