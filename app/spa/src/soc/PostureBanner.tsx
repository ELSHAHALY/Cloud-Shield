// Plan D18: three sources, each worded precisely. Never says "no
// vulnerabilities": a missing ECR scan is "unavailable", and the image policy
// is a statement about scan time only.
import type { ReactNode } from "react";
import type { Posture } from "../api/types";
import { Card, Chip, Icon, type IconName } from "../components/ui";

const GATE_TONE = { success: "good", failure: "bad", skipped: "warn", unknown: "neutral" } as const;

function Panel({ title, icon, children }: { title: string; icon: IconName; children: ReactNode }) {
  return (
    <div className="rounded-xl border border-slate-800/80 bg-slate-950/40 p-3.5 backdrop-blur-sm">
      <h3 className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-100">
        <span className="grid size-6 place-items-center rounded-md border border-slate-700/70 bg-slate-800/70 text-cyan-300">
          <Icon name={icon} className="size-3.5" />
        </span>
        {title}
      </h3>
      {children}
    </div>
  );
}

function Row({ k, children }: { k: string; children: ReactNode }) {
  return (
    <li className="flex flex-wrap justify-between gap-x-3 border-b border-slate-800/60 py-1 last:border-0">
      <span className="text-slate-400">{k}: </span>
      <span className="text-right text-slate-100 tabular-nums">{children}</span>
    </li>
  );
}

export function PostureBanner({ posture }: { posture: Posture }) {
  const { build, image, containment } = posture;
  const scan = image.ecrScan;
  return (
    <Card title="Security posture" icon="shield-check" subtitle="Build provenance, the running image and the containment switch, as reported by the API">
      <div className="grid gap-3 text-sm text-slate-300 md:grid-cols-3">
        <Panel title="Build" icon="server">
          {build.local ? (
            <p data-testid="build-local">Local build: CI gate outcomes are not available for this image.</p>
          ) : (
            <p>
              Commit <span className="font-mono text-cyan-200">{build.commit.slice(0, 12)}</span>
              {build.builtAt ? ` built ${build.builtAt}` : ""}
              {build.ciRunId ? ` (CI run ${build.ciRunId})` : ""}.
            </p>
          )}
          <ul className="mt-2 flex flex-wrap gap-1.5" aria-label="CI gate outcomes at build time">
            {(Object.keys(build.gates) as (keyof typeof build.gates)[]).map((g) => (
              <li key={g}>
                <Chip tone={GATE_TONE[build.gates[g]]} dot>
                  {g}: {build.gates[g]}
                </Chip>
              </li>
            ))}
          </ul>
          <p className={`mt-2 text-xs ${build.gatesEnforced ? "text-slate-400" : "text-amber-300"}`}>{build.gatesEnforced ? "Gates were enforced (findings fail the build)." : "Gates were not enforced at build time (fail-open)."}</p>
        </Panel>
        <Panel title="Image" icon="layers">
          <p data-testid="image-policy" className="text-slate-300">
            {posture.imagePolicy}
          </p>
          {scan && scan.status === "COMPLETE" && scan.critical !== null ? (
            <p data-testid="ecr-scan" className="mt-2 rounded-lg border border-slate-800 bg-slate-900/60 p-2 text-slate-200">
              ECR basic scan of the running digest (COMPLETE): {scan.critical} critical, {scan.high} high, {scan.medium} medium, {scan.low} low
              {scan.completedAt ? `, completed ${scan.completedAt}` : ""}.
            </p>
          ) : scan ? (
            <p data-testid="ecr-scan" className="mt-2 rounded-lg border border-amber-500/25 bg-amber-500/[0.06] p-2 text-amber-100">
              ECR scan of the running digest: no result ({scan.status}).
            </p>
          ) : (
            <p data-testid="ecr-scan" className="mt-2 rounded-lg border border-amber-500/25 bg-amber-500/[0.06] p-2 text-amber-100">
              Live ECR scan: unavailable{image.reference ? "" : " (no digest-pinned image reference)"}.
            </p>
          )}
        </Panel>
        <Panel title="Containment" icon="bolt">
          <ul>
            <Row k="Playbooks">{containment.playbooksEnabled ? "enabled" : "disabled"}</Row>
            <Row k="Dry run">{containment.dryRun === null ? "unknown (switch not readable)" : containment.dryRun ? "on (no changes are made)" : "off"}</Row>
            <Row k="Failed in the last 24 h">{containment.failedLast24h ?? "unknown"}</Row>
            <Row k="Last MTTC">{containment.lastMttcSeconds === null ? "none in 24 h" : `${containment.lastMttcSeconds.toFixed(1)} s (target ${containment.targetSeconds} s)`}</Row>
          </ul>
        </Panel>
      </div>
    </Card>
  );
}
