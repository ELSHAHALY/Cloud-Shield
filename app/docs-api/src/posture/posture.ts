// Security posture (plan D18 §7.5). Three sources, each worded precisely:
// build info baked at image build (the REAL gate outcomes), the static image
// policy, and a live ECR basic scan of the running digest. It never claims
// "no vulnerabilities".
import { readFileSync } from "node:fs";
import { DescribeImageScanFindingsCommand, type ECRClient } from "@aws-sdk/client-ecr";

export const IMAGE_POLICY =
  "CI pushes to ECR only when Trivy reports no fixable CRITICAL/HIGH vulnerabilities at scan time (audit A9).";

const GATES = ["secrets", "sast", "sca", "app"] as const;
type Gate = (typeof GATES)[number];
type Outcome = "success" | "failure" | "skipped" | "unknown";
const OUTCOMES: ReadonlySet<string> = new Set(["success", "failure", "skipped", "unknown"]);

export interface BuildInfo {
  commit: string;
  builtAt: string | null;
  ciRunId: string | null;
  local: boolean;
  gates: Record<Gate, Outcome>;
  gatesEnforced: boolean;
}

export const LOCAL_BUILD: BuildInfo = {
  commit: "local",
  builtAt: null,
  ciRunId: null,
  local: true,
  gates: { secrets: "unknown", sast: "unknown", sca: "unknown", app: "unknown" },
  gatesEnforced: false,
};

/** Validate build-info.json; anything off-enum becomes `unknown`. */
export function parseBuildInfo(raw: unknown): BuildInfo {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return LOCAL_BUILD;
  const r = raw as Record<string, unknown>;
  const commit = typeof r.commit === "string" && /^[0-9a-f]{40}$/.test(r.commit) ? r.commit : "local";
  const gatesRaw = (r.gates && typeof r.gates === "object" ? r.gates : {}) as Record<string, unknown>;
  const gates = Object.fromEntries(
    GATES.map((g) => [g, typeof gatesRaw[g] === "string" && OUTCOMES.has(gatesRaw[g]) ? gatesRaw[g] : "unknown"]),
  ) as Record<Gate, Outcome>;
  return {
    commit,
    builtAt: typeof r.builtAt === "string" && /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/.test(r.builtAt) ? r.builtAt : null,
    ciRunId: typeof r.ciRunId === "string" && /^\d{1,20}$/.test(r.ciRunId) ? r.ciRunId : null,
    local: commit === "local",
    gates,
    gatesEnforced: r.gatesEnforced === true,
  };
}

export function loadBuildInfo(file: string): BuildInfo {
  try {
    return parseBuildInfo(JSON.parse(readFileSync(file, "utf8")));
  } catch {
    return LOCAL_BUILD;
  }
}

const IMAGE_RE = /^(\d{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com\/([a-z0-9][a-z0-9._/-]{0,254})@(sha256:[0-9a-f]{64})$/;

/** Only a digest-pinned ECR reference for the configured repository is ever queried. */
export function parseImage(appImage: string | undefined, repositoryName: string | undefined) {
  if (!appImage || !repositoryName) return null;
  const m = IMAGE_RE.exec(appImage);
  if (!m || m[3] !== repositoryName) return null;
  return { registryId: m[1]!, region: m[2]!, repositoryName: m[3]!, digest: m[4]! };
}

export interface EcrScan {
  status: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  completedAt: string | null;
}

export async function ecrScan(ecr: ECRClient, image: ReturnType<typeof parseImage>): Promise<EcrScan | null> {
  if (!image) return null;
  try {
    const out = await ecr.send(
      new DescribeImageScanFindingsCommand({ registryId: image.registryId, repositoryName: image.repositoryName, imageId: { imageDigest: image.digest }, maxResults: 1 }),
    );
    const counts = (out.imageScanFindings?.findingSeverityCounts ?? {}) as Record<string, number | undefined>;
    const n = (k: string) => (typeof counts[k] === "number" ? counts[k] : 0);
    return {
      status: String(out.imageScanStatus?.status ?? "UNKNOWN").slice(0, 32),
      critical: n("CRITICAL"),
      high: n("HIGH"),
      medium: n("MEDIUM"),
      low: n("LOW"),
      completedAt: out.imageScanFindings?.imageScanCompletedAt?.toISOString() ?? null,
    };
  } catch {
    return null;
  }
}
