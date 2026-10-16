import { useMemo, useState } from "react";
import { Link } from "react-router";
import type { IncidentSummary } from "../api/types";
import { STATUSES, StatusChip } from "./status";

type SortKey = "eventTime" | "severity";

export function IncidentsTable({ incidents }: { incidents: IncidentSummary[] }) {
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

  return (
    <div className="space-y-2">
      <label className="flex items-center gap-2 text-sm">
        Status
        <select value={filter} onChange={(e) => setFilter(e.target.value)} className="rounded border border-slate-300 px-2 py-1">
          <option value="ALL">All</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </label>
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="border-b border-slate-200 text-xs uppercase text-slate-600">
            <tr>
              <th scope="col" className="py-2 pr-3" aria-sort={ariaSort("eventTime")}>
                <button type="button" onClick={() => toggle("eventTime")}>
                  Event time{arrow("eventTime")}
                </button>
              </th>
              <th scope="col" className="py-2 pr-3">
                Status
              </th>
              <th scope="col" className="py-2 pr-3">
                Finding type
              </th>
              <th scope="col" className="py-2 pr-3" aria-sort={ariaSort("severity")}>
                <button type="button" onClick={() => toggle("severity")}>
                  Severity{arrow("severity")}
                </button>
              </th>
              <th scope="col" className="py-2 pr-3">
                Tactic
              </th>
              <th scope="col" className="py-2 pr-3">
                MTTC
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={6} className="py-4 text-slate-600">
                  No incidents.
                </td>
              </tr>
            )}
            {rows.map((i) => (
              <tr key={i.incidentId} className="border-b border-slate-100">
                <td className="py-2 pr-3 font-mono text-xs">
                  <Link className="text-indigo-700 underline" to={`/soc/incidents/${encodeURIComponent(i.incidentId)}`}>
                    {i.eventTime ?? "—"}
                  </Link>
                </td>
                <td className="py-2 pr-3">
                  <StatusChip incident={i} />
                </td>
                <td className="py-2 pr-3 font-mono text-xs">{i.findingType ?? "—"}</td>
                <td className="py-2 pr-3">{i.severity ?? "—"}</td>
                <td className="py-2 pr-3">{i.tactic}</td>
                <td className="py-2 pr-3">{i.mttcSeconds === null ? "—" : `${i.mttcSeconds.toFixed(1)} s`}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
