// Plan D18: three sources, each worded precisely. Never says "no
// vulnerabilities": a missing ECR scan is "unavailable", and the image policy
// is a statement about scan time only.
import type { Posture } from "../api/types";
import { Card, Chip } from "../components/ui";

const GATE_TONE = { success: "good", failure: "bad", skipped: "warn", unknown: "neutral" } as const;

export function PostureBanner({ posture }: { posture: Posture }) {
  const { build, image, containment } = posture;
  const scan = image.ecrScan;
  return (
    <Card title="Security posture">
      <div className="grid gap-3 text-sm md:grid-cols-3">
        <div>
          <h3 className="font-medium">Build</h3>
          {build.local ? (
            <p data-testid="build-local">Local build: CI gate outcomes are not available for this image.</p>
          ) : (
            <p>
              Commit <span className="font-mono">{build.commit.slice(0, 12)}</span>
              {build.builtAt ? ` built ${build.builtAt}` : ""}
              {build.ciRunId ? ` (CI run ${build.ciRunId})` : ""}.
            </p>
          )}
          <ul className="mt-1 flex flex-wrap gap-1" aria-label="CI gate outcomes at build time">
            {(Object.keys(build.gates) as (keyof typeof build.gates)[]).map((g) => (
              <li key={g}>
                <Chip tone={GATE_TONE[build.gates[g]]}>
                  {g}: {build.gates[g]}
                </Chip>
              </li>
            ))}
          </ul>
          <p className="mt-1 text-xs text-slate-600">{build.gatesEnforced ? "Gates were enforced (findings fail the build)." : "Gates were not enforced at build time (fail-open)."}</p>
        </div>
        <div>
          <h3 className="font-medium">Image</h3>
          <p data-testid="image-policy">{posture.imagePolicy}</p>
          {scan ? (
            <p data-testid="ecr-scan" className="mt-1">
              ECR basic scan of the running digest ({scan.status}): {scan.critical} critical, {scan.high} high, {scan.medium} medium, {scan.low} low
              {scan.completedAt ? `, completed ${scan.completedAt}` : ""}.
            </p>
          ) : (
            <p data-testid="ecr-scan" className="mt-1 text-slate-700">
              Live ECR scan: unavailable{image.reference ? "" : " (no digest-pinned image reference)"}.
            </p>
          )}
        </div>
        <div>
          <h3 className="font-medium">Containment</h3>
          <ul className="space-y-0.5">
            <li>Playbooks: {containment.playbooksEnabled ? "enabled" : "disabled"}</li>
            <li>Dry run: {containment.dryRun === null ? "unknown (switch not readable)" : containment.dryRun ? "on (no changes are made)" : "off"}</li>
            <li>Failed in the last 24 h: {containment.failedLast24h ?? "unknown"}</li>
            <li>Last MTTC: {containment.lastMttcSeconds === null ? "none in 24 h" : `${containment.lastMttcSeconds.toFixed(1)} s (target ${containment.targetSeconds} s)`}</li>
          </ul>
        </div>
      </div>
    </Card>
  );
}
