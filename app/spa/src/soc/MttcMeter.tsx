import type { SocMetrics } from "../api/types";

const MAX = 120;

export function mttcVerdict(value: number | null, target: number): "none" | "within" | "over" | "far" {
  if (value === null) return "none";
  if (value <= target) return "within";
  return value <= MAX ? "over" : "far";
}

const LABEL = { none: "no contained incidents in the window", within: "within target", over: "over target", far: "far over target" };
const COLOR = { none: "#94a3b8", within: "#047857", over: "#b45309", far: "#b91c1c" };

/** Hand-written SVG gauge (no chart library, CSP-safe: attributes only, no inline style). */
export function MttcMeter({ mttc }: { mttc: SocMetrics["mttc"] }) {
  const value = mttc.last;
  const verdict = mttcVerdict(value, mttc.targetSeconds);
  const clamp = value === null ? 0 : Math.min(MAX, Math.max(0, value));
  const x = (v: number) => 10 + (v / MAX) * 280;
  const fmt = (v: number | null) => (v === null ? "—" : `${v.toFixed(1)} s`);
  const sentence = `Last MTTC ${fmt(value)}, target ${mttc.targetSeconds} s: ${LABEL[verdict]}. Median ${fmt(mttc.p50)}, 90th percentile ${fmt(mttc.p90)}, ${mttc.samples} samples.`;
  return (
    <figure className="space-y-2">
      <svg role="img" aria-label={sentence} viewBox="0 0 300 48" className="w-full max-w-md">
        <rect x="10" y="16" width="280" height="12" rx="6" fill="#e2e8f0" />
        <rect x="10" y="16" width={x(clamp) - 10} height="12" rx="6" fill={COLOR[verdict]} data-testid="mttc-bar" />
        <line x1={x(mttc.targetSeconds)} x2={x(mttc.targetSeconds)} y1="10" y2="34" stroke="#0f172a" strokeWidth="2" data-testid="mttc-target" />
        <text x={x(mttc.targetSeconds)} y="44" fontSize="8" textAnchor="middle" fill="#0f172a">
          target {mttc.targetSeconds} s
        </text>
        <text x="10" y="44" fontSize="8" fill="#475569">
          0
        </text>
        <text x="290" y="44" fontSize="8" textAnchor="end" fill="#475569">
          {MAX} s+
        </text>
      </svg>
      <figcaption className="text-sm">
        <span className="font-medium">Last MTTC {fmt(value)}</span> ({LABEL[verdict]}) · p50 {fmt(mttc.p50)} · p90 {fmt(mttc.p90)} · max {fmt(mttc.max)} · {mttc.samples} samples
      </figcaption>
    </figure>
  );
}
