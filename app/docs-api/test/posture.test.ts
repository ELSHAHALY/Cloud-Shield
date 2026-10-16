import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { mockClient } from "aws-sdk-client-mock";
import { DescribeImageScanFindingsCommand, ECRClient } from "@aws-sdk/client-ecr";
import { ecrScan, loadBuildInfo, LOCAL_BUILD, parseBuildInfo, parseImage } from "../src/posture/posture";

const DIGEST = "sha256:" + "b".repeat(64);
const IMAGE = `123456789012.dkr.ecr.us-east-1.amazonaws.com/cloudshield-dev/docs-api@${DIGEST}`;

describe("build info", () => {
  it("keeps only enum values; anything else is unknown", () => {
    const b = parseBuildInfo({ commit: "a".repeat(40), builtAt: "2026-10-16T12:00:00Z", ciRunId: "123", gates: { secrets: "success", sast: "failure", sca: "skipped", app: "pwned" }, gatesEnforced: true, extra: 1 });
    expect(b).toEqual({ commit: "a".repeat(40), builtAt: "2026-10-16T12:00:00Z", ciRunId: "123", local: false, gates: { secrets: "success", sast: "failure", sca: "skipped", app: "unknown" }, gatesEnforced: true });
    expect(parseBuildInfo({ commit: "<script>", gates: null, builtAt: "yesterday", ciRunId: "x" })).toMatchObject({ commit: "local", local: true, builtAt: null, ciRunId: null });
    expect(parseBuildInfo(null)).toBe(LOCAL_BUILD);
    expect(parseBuildInfo([])).toBe(LOCAL_BUILD);
  });

  it("falls back to a local build when the file is missing or invalid", () => {
    expect(loadBuildInfo("/nonexistent/build-info.json")).toBe(LOCAL_BUILD);
    const dir = mkdtempSync(path.join(os.tmpdir(), "bi-"));
    try {
      writeFileSync(path.join(dir, "b.json"), "{not json");
      expect(loadBuildInfo(path.join(dir, "b.json"))).toBe(LOCAL_BUILD);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("image reference", () => {
  it("accepts only a digest-pinned reference to the configured repository", () => {
    expect(parseImage(IMAGE, "cloudshield-dev/docs-api")).toEqual({ registryId: "123456789012", region: "us-east-1", repositoryName: "cloudshield-dev/docs-api", digest: DIGEST });
    expect(parseImage(IMAGE, "other/repo")).toBeNull();
    expect(parseImage(IMAGE.replace(`@${DIGEST}`, ":latest"), "cloudshield-dev/docs-api")).toBeNull();
    expect(parseImage("evil.example/x@" + DIGEST, "x")).toBeNull();
    expect(parseImage(undefined, "x")).toBeNull();
  });
});

describe("ECR scan", () => {
  const ecr = mockClient(ECRClient);
  afterEach(() => ecr.reset());
  const client = new ECRClient({ region: "us-east-1" });

  it("reports counts and completion time, or null when unavailable", async () => {
    ecr.on(DescribeImageScanFindingsCommand).resolves({ imageScanStatus: { status: "COMPLETE" }, imageScanFindings: { findingSeverityCounts: { HIGH: 2, LOW: 1 }, imageScanCompletedAt: new Date("2026-10-16T00:00:00Z") } });
    expect(await ecrScan(client, parseImage(IMAGE, "cloudshield-dev/docs-api"))).toEqual({ status: "COMPLETE", critical: 0, high: 2, medium: 0, low: 1, completedAt: "2026-10-16T00:00:00.000Z" });
    expect(ecr.commandCalls(DescribeImageScanFindingsCommand)[0]!.args[0].input).toMatchObject({ repositoryName: "cloudshield-dev/docs-api", imageId: { imageDigest: DIGEST } });
    ecr.reset();
    ecr.on(DescribeImageScanFindingsCommand).rejects(new Error("AccessDenied"));
    expect(await ecrScan(client, parseImage(IMAGE, "cloudshield-dev/docs-api"))).toBeNull();
    expect(await ecrScan(client, null)).toBeNull();
    ecr.reset();
    ecr.on(DescribeImageScanFindingsCommand).resolves({});
    expect(await ecrScan(client, parseImage(IMAGE, "cloudshield-dev/docs-api"))).toMatchObject({ status: "UNKNOWN", completedAt: null });
  });
});
