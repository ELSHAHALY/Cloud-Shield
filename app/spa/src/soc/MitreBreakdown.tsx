import type { SocMetrics } from "../api/types";

export function MitreBreakdown({ byTactic }: { byTactic: SocMetrics["byTactic"] }) {
  if (byTactic.length === 0) return <p className="text-sm text-slate-600">No incidents in the window.</p>;
  const max = Math.max(...byTactic.map((t) => t.count));
  const rowH = 22;
  return (
    <svg role="img" aria-label={`Incidents by ATT&CK tactic: ${byTactic.map((t) => `${t.tactic} ${t.count}`).join(", ")}`} viewBox={`0 0 420 ${byTactic.length * rowH + 4}`} className="w-full max-w-xl">
      {byTactic.map((t, i) => {
        const w = Math.max(2, (t.count / max) * 180);
        const y = i * rowH + 4;
        return (
          <g key={t.tactic}>
            <text x="0" y={y + 12} fontSize="10" fill="#0f172a">
              {t.tactic}
            </text>
            <rect x="130" y={y + 2} width={w} height="12" rx="3" fill="#4f46e5" />
            <text x={136 + w} y={y + 12} fontSize="10" fill="#334155">
              {t.count} {t.techniques.length ? `(${t.techniques.join(", ")})` : ""}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
