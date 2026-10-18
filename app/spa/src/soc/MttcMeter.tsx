import type { SocMetrics } from "../api/types";

const MAX = 120;

export function mttcVerdict(value: number | null, target: number): "none" | "within" | "over" | "far" {
  if (value === null) return "none";
  if (value <= target) return "within";
  return value <= MAX ? "over" : "far";
}

const LABEL = { none: "no contained incidents in the window", within: "within target", over: "over target", far: "far over target" };
const COLOR = { none: "#64748b", within: "#34d399", over: "#fbbf24", far: "#fb7185" };
const TEXT = { none: "text-slate-300", within: "text-emerald-300", over: "text-amber-300", far: "text-rose-300" };

// Radial gauge geometry (viewBox units): a semicircle over 0–MAX seconds.
const CX = 120;
const CY = 122;
const R = 90;
const ARC = Math.PI * R;

function polar(seconds: number, radius: number): [number, number] {
  const theta = Math.PI * (1 - Math.min(MAX, Math.max(0, seconds)) / MAX);
  return [CX + radius * Math.cos(theta), CY - radius * Math.sin(theta)];
}

/** Decorative radial gauge; the accessible reading is the linear scale below it. */
function RadialGauge({ value, target, verdict }: { value: number | null; target: number; verdict: keyof typeof LABEL }) {
  const fraction = value === null ? 0 : Math.min(MAX, Math.max(0, value)) / MAX;
  const [tx1, ty1] = polar(target, R - 12);
  const [tx2, ty2] = polar(target, R + 11);
  const [lx, ly] = polar(target, R + 19);
  const path = `M ${CX - R} ${CY} A ${R} ${R} 0 0 1 ${CX + R} ${CY}`;
  return (
    <svg viewBox="0 0 240 142" aria-hidden="true" focusable="false" className="mx-auto w-full max-w-[18rem]">
      <path d={path} fill="none" stroke="#1e293b" strokeWidth="14" strokeLinecap="round" />
      {value !== null && (
        <path d={path} fill="none" stroke={COLOR[verdict]} strokeWidth="14" strokeLinecap="round" strokeDasharray={`${(fraction * ARC).toFixed(2)} ${ARC.toFixed(2)}`} className="animate-gauge" />
      )}
      <line x1={tx1.toFixed(2)} y1={ty1.toFixed(2)} x2={tx2.toFixed(2)} y2={ty2.toFixed(2)} stroke="#e2e8f0" strokeWidth="2" strokeLinecap="round" />
      <text x={lx.toFixed(2)} y={(ly + 2).toFixed(2)} fontSize="9" textAnchor="middle" fill="#cbd5e1">
        target {target} s
      </text>
      <text x={CX} y={CY - 24} fontSize="34" fontWeight="600" textAnchor="middle" fill={COLOR[verdict]}>
        {value === null ? "—" : value.toFixed(1)}
        {value !== null && (
          <tspan fontSize="14" fill="#94a3b8" dx="3">
            s
          </tspan>
        )}
      </text>
      <text x={CX} y={CY - 6} fontSize="10" textAnchor="middle" fill="#94a3b8" letterSpacing="1.2">
        LAST MTTC
      </text>
      <text x={CX - R} y={CY + 16} fontSize="9" textAnchor="middle" fill="#94a3b8">
        0
      </text>
      <text x={CX + R} y={CY + 16} fontSize="9" textAnchor="middle" fill="#94a3b8">
        {MAX} s+
      </text>
    </svg>
  );
}

/** Hand-written SVG gauge (no chart library, CSP-safe: attributes only, no inline style). */
export function MttcMeter({ mttc }: { mttc: SocMetrics["mttc"] }) {
  const value = mttc.last;
  const verdict = mttcVerdict(value, mttc.targetSeconds);
  const clamp = value === null ? 0 : Math.min(MAX, Math.max(0, value));
  const x = (v: number) => 10 + (v / MAX) * 280;
  const fmt = (v: number | null) => (v === null ? "—" : `${v.toFixed(1)} s`);
  const sentence = `Last MTTC ${fmt(value)}, target ${mttc.targetSeconds} s: ${LABEL[verdict]}. Median ${fmt(mttc.p50)}, 90th percentile ${fmt(mttc.p90)}, ${mttc.samples} samples.`;
  return (
    <figure className="space-y-3">
      <RadialGauge value={value} target={mttc.targetSeconds} verdict={verdict} />
      <div>
        <p className="label-caps mb-1">Scale (0–{MAX} s)</p>
        <svg role="img" aria-label={sentence} viewBox="0 0 300 48" className="w-full">
          <rect x="10" y="16" width="280" height="12" rx="6" fill="#1e293b" />
          <rect x="10" y="16" width={x(clamp) - 10} height="12" rx="6" fill={COLOR[verdict]} data-testid="mttc-bar" />
          <line x1={x(mttc.targetSeconds)} x2={x(mttc.targetSeconds)} y1="10" y2="34" stroke="#e2e8f0" strokeWidth="2" data-testid="mttc-target" />
          <text x={x(mttc.targetSeconds)} y="44" fontSize="8" textAnchor="middle" fill="#cbd5e1">
            target {mttc.targetSeconds} s
          </text>
          <text x="10" y="44" fontSize="8" fill="#94a3b8">
            0
          </text>
          <text x="290" y="44" fontSize="8" textAnchor="end" fill="#94a3b8">
            {MAX} s+
          </text>
        </svg>
      </div>
      <figcaption className="text-sm tabular-nums text-slate-400">
        <span className={`font-medium ${TEXT[verdict]}`}>Last MTTC {fmt(value)}</span> ({LABEL[verdict]}) · p50 {fmt(mttc.p50)} · p90 {fmt(mttc.p90)} · max {fmt(mttc.max)} · {mttc.samples} samples
      </figcaption>
    </figure>
  );
}
