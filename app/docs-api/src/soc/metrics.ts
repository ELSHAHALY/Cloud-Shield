// SOC metrics (plan §7.1 / §3.3): MTTC distribution, status counts, ATT&CK.
import { STATUSES, type IncidentRepository, type IncidentStatus, type Row } from "./repository";
import { MTTC_TARGET_SECONDS, mttcOf, parseTime } from "./time";
import { triage } from "./triage";

export type Window = "24h" | "7d" | "30d";
const WINDOW_MS: Record<Window, number> = { "24h": 86_400_000, "7d": 7 * 86_400_000, "30d": 30 * 86_400_000 };

export function percentile(sortedAsc: number[], p: number): number | null {
  if (sortedAsc.length === 0) return null;
  const idx = Math.max(0, Math.ceil((p / 100) * sortedAsc.length) - 1);
  return sortedAsc[idx]!;
}

export function computeMetrics(rows: Row[], window: Window, since: string, truncated: boolean) {
  const byStatus = Object.fromEntries(STATUSES.map((s) => [s, 0])) as Record<IncidentStatus, number>;
  const tactics = new Map<string, { count: number; techniques: Set<string> }>();
  const samples: { mttc: number; at: number }[] = [];
  for (const row of rows) {
    const status = row.status as IncidentStatus;
    if (Object.prototype.hasOwnProperty.call(byStatus, status)) byStatus[status] += 1;
    const t = triage(row.findingType);
    const entry = tactics.get(t.tactic) ?? { count: 0, techniques: new Set<string>() };
    entry.count += 1;
    for (const tech of t.attack_techniques) entry.techniques.add(tech);
    tactics.set(t.tactic, entry);
    const m = mttcOf(row);
    if (m !== null) samples.push({ mttc: m, at: parseTime(row.containedAt) ?? 0 });
  }
  const sorted = samples.map((s) => s.mttc).sort((a, b) => a - b);
  const last = samples.length ? samples.reduce((a, b) => (b.at > a.at ? b : a)).mttc : null;
  return {
    window,
    since,
    mttc: {
      targetSeconds: MTTC_TARGET_SECONDS,
      samples: sorted.length,
      last,
      p50: percentile(sorted, 50),
      p90: percentile(sorted, 90),
      max: sorted.length ? sorted[sorted.length - 1]! : null,
    },
    byStatus,
    byTactic: [...tactics.entries()]
      .map(([tactic, v]) => ({ tactic, count: v.count, techniques: [...v.techniques].sort() }))
      .sort((a, b) => b.count - a.count || a.tactic.localeCompare(b.tactic))
      .slice(0, 20),
    truncated,
  };
}

export async function metrics(repo: IncidentRepository, window: Window, now: Date) {
  const since = new Date(now.getTime() - WINDOW_MS[window]).toISOString();
  const results = await Promise.all(STATUSES.map((s) => repo.since(s, since)));
  return computeMetrics(
    results.flatMap((r) => r.items),
    window,
    since,
    results.some((r) => r.truncated),
  );
}
