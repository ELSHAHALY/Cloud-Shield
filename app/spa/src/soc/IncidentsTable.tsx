import { useMemo, useState } from "react";
import { Link } from "react-router";
import type { IncidentSummary } from "../api/types";
import { Icon } from "../components/ui";
import { STATUSES, StatusChip } from "./status";

type SortKey = "eventTime" | "severity";

// GuardDuty-style severity bands (0–10): the number is always written next to the bar.
function sevColor(s: number): string {
  if (s >= 7) return "#fb7185";
  if (s >= 4) return "#fbbf24";
  return "#22d3ee";
}

function Severity({ value }: { value: number | null }) {
  if (value === null) return <span className="text-slate-400">—</span>;
  const w = Math.max(2, (Math.min(10, Math.max(0, value)) / 10) * 40);
  return (
    <span className="inline-flex items-center gap-2">
      <svg viewBox="0 0 40 6" width="40" height="6" aria-hidden="true" focusable="false" className="shrink-0">
        <rect x="0" y="0" width="40" height="6" rx="3" fill="#1e293b" />
        <rect x="0" y="0" width={w.toFixed(1)} height="6" rx="3" fill={sevColor(value)} />
      </svg>
      <span className="tabular-nums text-slate-200">{value}</span>
    </span>
  );
}

function Mttc({ seconds, target }: { seconds: number | null; target: number }) {
  if (seconds === null) return <span className="text-slate-400">—</span>;
  const within = seconds <= target;
  return (
    <span className="inline-flex items-center gap-1.5 tabular-nums" title={within ? `Within the ${target} s target` : `Over the ${target} s target`}>
      <span className={`size-1.5 rounded-full ${within ? "bg-emerald-400" : "bg-amber-400"}`} aria-hidden="true" />
      <span className={within ? "text-emerald-200" : "text-amber-200"}>{`${seconds.toFixed(1)} s`}</span>
      <span className="sr-only">{within ? " (within target)" : " (over target)"}</span>
    </span>
  );
}

export function IncidentsTable({ incidents, targetSeconds = 60 }: { incidents: IncidentSummary[]; targetSeconds?: number }) {
  const [filter, setFilter] = useState<string>("ALL");
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({ key: "eventTime", desc: true });

  const rows = useMemo(() => {
    const list = incidents.filter((i) => filter === "ALL" || i.status === filter);
    const val = (i: IncidentSummary) => (sort.key === "severity" ? (i.severity ?? -1) : (i.eventTime ?? ""));
    return [...list].sort((a, b) => {
      const [x, y] = [val(a), val(b)];
      const c = x < y ? -1 : x > y ? 1 : 0;
      return sort.desc ? -c : c;
    });
  }, [incidents, filter, sort]);

  const toggle = (key: SortKey) => setSort((s) => (s.key === key ? { key, desc: !s.desc } : { key, desc: true }));
  const arrow = (key: SortKey) => (sort.key === key ? (sort.desc ? " ↓" : " ↑") : "");
  const ariaSort = (key: SortKey) => (sort.key === key ? (sort.desc ? "descending" : "ascending") : "none");
  const sortBtn = (key: SortKey) => `inline-flex items-center gap-1 rounded px-1 -mx-1 uppercase tracking-wide transition-colors hover:text-slate-100 ${sort.key === key ? "text-cyan-300" : ""}`;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <label className="flex items-center gap-2 text-sm text-slate-300">
          Status
          <select value={filter} onChange={(e) => setFilter(e.target.value)} className="px-2.5 py-1.5 text-sm">
            <option value="ALL">All</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </label>
        <p className="text-xs tabular-nums text-slate-400">
          {rows.length} of {incidents.length} shown · MTTC mark: <span className="text-emerald-300">≤ {targetSeconds} s target</span> / <span className="text-amber-300">over</span>
        </p>
      </div>
      <div className="overflow-x-auto rounded-lg border border-slate-800">
        <table className="data-table">
          <thead className="bg-slate-900/80">
            <tr>
              <th scope="col" className="px-3 py-2.5" aria-sort={ariaSort("eventTime")}>
                <button type="button" className={sortBtn("eventTime")} onClick={() => toggle("eventTime")}>
                  Event time{arrow("eventTime")}
                </button>
              </th>
              <th scope="col" className="px-3 py-2.5">
                Status
              </th>
              <th scope="col" className="px-3 py-2.5">
                Finding type
              </th>
              <th scope="col" className="px-3 py-2.5" aria-sort={ariaSort("severity")}>
                <button type="button" className={sortBtn("severity")} onClick={() => toggle("severity")}>
                  Severity{arrow("severity")}
                </button>
              </th>
              <th scope="col" className="px-3 py-2.5">
                Tactic
              </th>
              <th scope="col" className="px-3 py-2.5">
                MTTC
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-6 text-center text-slate-400">
                  No incidents.
                </td>
              </tr>
            )}
            {rows.map((i) => (
              <tr key={i.incidentId} className="group">
                <td className="px-3 py-2.5 font-mono text-xs whitespace-nowrap">
                  <Link className="link-inline inline-flex items-center gap-1" to={`/soc/incidents/${encodeURIComponent(i.incidentId)}`} title={i.incidentId}>
                    {i.eventTime ?? "—"}
                    <Icon name="chevron" className="size-3 opacity-0 transition-opacity group-hover:opacity-100" />
                  </Link>
                </td>
                <td className="px-3 py-2.5">
                  <StatusChip incident={i} />
                </td>
                <td className="px-3 py-2.5 font-mono text-xs text-slate-300">{i.findingType ?? "—"}</td>
                <td className="px-3 py-2.5">
                  <Severity value={i.severity} />
                </td>
                <td className="px-3 py-2.5 text-slate-300">{i.tactic}</td>
                <td className="px-3 py-2.5">
                  <Mttc seconds={i.mttcSeconds} target={targetSeconds} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
