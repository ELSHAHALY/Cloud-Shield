import type { SocMetrics } from "../api/types";

const BAR_MAX = 160;

export function MitreBreakdown({ byTactic }: { byTactic: SocMetrics["byTactic"] }) {
  if (byTactic.length === 0) return <p className="text-sm text-slate-400">No incidents in the window.</p>;
  const max = Math.max(...byTactic.map((t) => t.count));
  const rowH = 26;
  return (
    <svg role="img" aria-label={`Incidents by ATT&CK tactic: ${byTactic.map((t) => `${t.tactic} ${t.count}`).join(", ")}`} viewBox={`0 0 560 ${byTactic.length * rowH + 4}`} className="w-full">
      {byTactic.map((t, i) => {
        const w = Math.max(2, (t.count / max) * BAR_MAX);
        const y = i * rowH + 4;
        return (
          <g key={t.tactic}>
            <text x="0" y={y + 13} fontSize="11" fill="#cbd5e1">
              {t.tactic.length > 36 ? `${t.tactic.slice(0, 35)}…` : t.tactic}
              <title>{t.tactic}</title>
            </text>
            <rect x="230" y={y + 3} width={BAR_MAX} height="12" rx="3" fill="#1e293b" />
            <rect x="230" y={y + 3} width={w} height="12" rx="3" fill="#22d3ee" fillOpacity="0.85" className="animate-gauge" />
            <text x={238 + BAR_MAX} y={y + 13} fontSize="11" fill="#e2e8f0" fontWeight="600">
              {t.count}
            </text>
            <text x={256 + BAR_MAX} y={y + 13} fontSize="10" fill="#94a3b8" fontFamily="ui-monospace, monospace">
              {t.techniques.length ? `(${t.techniques.join(", ")})` : ""}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
