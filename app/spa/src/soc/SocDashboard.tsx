import { useCallback } from "react";
import type { Posture, SocMetrics, SocOverview } from "../api/types";
import { useSession } from "../auth/session";
import { useReportLive } from "../components/live";
import { Card, ErrorBox, Loading, PageHeader, ProgressRing, Sparkline, StatCard, type Tone } from "../components/ui";
import { usePolling } from "../hooks/usePolling";
import { IncidentsTable } from "./IncidentsTable";
import { MitreBreakdown } from "./MitreBreakdown";
import { MttcMeter, mttcVerdict } from "./MttcMeter";
import { PostureBanner } from "./PostureBanner";

const WINDOW: Record<SocMetrics["window"], string> = { "24h": "24 h", "7d": "7 d", "30d": "30 d" };
const VERDICT_TONE = { none: "neutral", within: "good", over: "warn", far: "bad" } as const satisfies Record<string, Tone>;

/** KPI tiles, computed only from what /soc/overview and /soc/posture return. */
function KpiRow({ o, posture, postureError }: { o: SocOverview; posture: Posture | null; postureError: boolean }) {
  const { byStatus, mttc } = o.metrics;
  const win = WINDOW[o.metrics.window] ?? o.metrics.window;

  const needAnalyst = byStatus.DETECTED + byStatus.NO_PLAYBOOK_ANALYST_REVIEW + byStatus.BLOCKED_BY_GUARD + byStatus.FAILED;
  const needTone: Tone = byStatus.FAILED > 0 ? "bad" : needAnalyst > 0 ? "warn" : "good";

  const verdict = mttcVerdict(mttc.p50, mttc.targetSeconds);
  const trend = o.incidents
    .filter((i) => i.status === "CONTAINED" && i.mttcSeconds !== null)
    .sort((a, b) => ((a.containedAt ?? a.eventTime ?? "") < (b.containedAt ?? b.eventTime ?? "") ? -1 : 1))
    .map((i) => i.mttcSeconds as number);

  const total = Object.values(byStatus).reduce((a, b) => a + b, 0);
  const containedShare = total > 0 ? byStatus.CONTAINED / total : 0;

  const scan = posture?.image.ecrScan ?? null;
  const cveKnown = scan !== null && scan.status === "COMPLETE" && scan.critical !== null;
  const cveTone: Tone = cveKnown ? (scan.critical === 0 ? "good" : "bad") : "neutral";
  const cveHint = !posture ? (postureError ? "posture unavailable" : "loading posture…") : cveKnown ? `ECR basic scan of the running digest${scan.high !== null ? ` · ${scan.high} high` : ""}` : scan ? `no result (${scan.status})` : "ECR scan unavailable";

  const dryRun = posture ? posture.containment.dryRun : null;
  const mode = dryRun === null ? "Unknown" : dryRun ? "Dry run" : "Live";
  const modeTone: Tone = dryRun === null ? "neutral" : dryRun ? "warn" : "info";
  const modeHint = !posture ? (postureError ? "posture unavailable" : "loading posture…") : `playbooks ${posture.containment.playbooksEnabled ? "enabled" : "disabled"}${dryRun === null ? " · switch not readable" : dryRun ? " · no changes are made" : ""}`;

  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
      <StatCard label={`Need analyst (${win})`} value={needAnalyst} tone={needTone} icon="user" hint={`detected ${byStatus.DETECTED} · no playbook ${byStatus.NO_PLAYBOOK_ANALYST_REVIEW} · guard-blocked ${byStatus.BLOCKED_BY_GUARD} · failed ${byStatus.FAILED}`} />
      <StatCard
        label={`MTTC p50 (${win})`}
        value={mttc.p50 === null ? "—" : mttc.p50.toFixed(1)}
        unit={mttc.p50 === null ? undefined : "s"}
        tone={VERDICT_TONE[verdict]}
        icon="clock"
        hint={`target ${mttc.targetSeconds} s · n=${mttc.samples}`}
        visual={<Sparkline values={trend} threshold={mttc.targetSeconds} tone={VERDICT_TONE[verdict]} />}
      />
      <StatCard
        label={`Contained (${win})`}
        value={byStatus.CONTAINED}
        tone={byStatus.CONTAINED > 0 ? "good" : "neutral"}
        icon="shield-check"
        hint={total > 0 ? `${Math.round(containedShare * 100)}% of ${total} incidents` : "no incidents in the window"}
        visual={<ProgressRing value={containedShare} size={40} stroke={5} tone="good" />}
      />
      <StatCard label="Critical CVEs (running image)" value={cveKnown ? scan.critical : "—"} tone={cveTone} icon="bug" hint={cveHint} />
      <StatCard label="Containment mode" value={mode} tone={modeTone} icon="bolt" hint={modeHint} />
    </div>
  );
}

export function SocDashboard() {
  const { api } = useSession();
  const overview = usePolling(useCallback(() => api.get<SocOverview>("/soc/overview"), [api]), 15_000);
  const posture = usePolling(useCallback(() => api.get<Posture>("/soc/posture"), [api]), 60_000);
  useReportLive({ label: "SOC overview", intervalSeconds: 15, updatedAt: overview.updatedAt, failing: !!overview.error });
  const o = overview.data;
  return (
    <div className="space-y-5">
      <PageHeader
        eyebrow="Security operations"
        title="SecOps SOC"
        subtitle="Automated containment with human-gated eradication. Figures below come from the SOC API as returned."
        actions={
          <p className="flex items-center gap-2 text-xs text-slate-400" aria-live="polite">
            {overview.updatedAt && <span className={overview.error ? "size-2 rounded-full bg-rose-400" : "live-dot"} aria-hidden="true" />}
            {overview.updatedAt ? `Updated ${overview.updatedAt.toLocaleTimeString()} · refreshes every 15 s while this tab is visible` : ""}
          </p>
        }
      />
      <ErrorBox error={overview.error} />
      {!o && !overview.error && <Loading />}
      {o && <KpiRow o={o} posture={posture.data} postureError={!!posture.error} />}
      {o?.metrics.truncated && <p className="text-xs text-amber-300">The metrics were computed on a truncated result set: counts may be incomplete.</p>}
      {posture.data && <PostureBanner posture={posture.data} />}
      {o && (
        <>
          <div className="grid gap-5 lg:grid-cols-2">
            <Card title="Time to contain (24 h)" icon="clock" subtitle={`Last, p50, p90 and max as reported · ${o.metrics.mttc.targetSeconds} s is the target`}>
              <MttcMeter mttc={o.metrics.mttc} />
            </Card>
            <Card title="ATT&CK tactics (24 h)" icon="target" subtitle="Incidents by tactic, with technique ids">
              <MitreBreakdown byTactic={o.metrics.byTactic} />
            </Card>
          </div>
          <Card title="Latest incidents" icon="activity">
            <IncidentsTable incidents={o.incidents} targetSeconds={o.metrics.mttc.targetSeconds} />
          </Card>
        </>
      )}
    </div>
  );
}
