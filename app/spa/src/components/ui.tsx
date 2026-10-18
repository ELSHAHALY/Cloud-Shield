import type { ReactNode } from "react";
import { messageFor } from "../api/client";

// Design primitives (feat/ui-cyber-redesign). Every visual is a compiled
// Tailwind class or an SVG presentation attribute: no inline style (CSP).

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <p role="alert" className="flex items-start gap-2 rounded-xl border border-rose-500/40 bg-rose-500/10 p-3 text-sm text-rose-100">
      <Icon name="alert" className="mt-0.5 size-4 shrink-0 text-rose-300" />
      <span>{messageFor(error)}</span>
    </p>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <p role="status" className="flex items-center gap-2 text-sm text-slate-400">
      <span className="size-3 animate-spin rounded-full border-2 border-slate-600 border-t-cyan-400" aria-hidden="true" />
      {label}
    </p>
  );
}

export type Accent = "cyan" | "emerald" | "rose" | "amber" | "none";
const RIM: Record<Accent, string> = { cyan: "accent-rim", emerald: "accent-rim accent-rim-emerald", rose: "accent-rim accent-rim-rose", amber: "accent-rim accent-rim-amber", none: "" };

export function Card({ title, children, actions, icon, subtitle, accent = "none", className = "" }: { title: string; children: ReactNode; actions?: ReactNode; icon?: IconName; subtitle?: ReactNode; accent?: Accent; className?: string }) {
  return (
    <section className={`glass animate-fade-in p-4 md:p-5 ${RIM[accent]} ${className}`} aria-label={title}>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-2.5">
          {icon && (
            <span className="mt-0.5 grid size-7 shrink-0 place-items-center rounded-lg border border-slate-700/70 bg-slate-800/70 text-cyan-300">
              <Icon name={icon} className="size-4" />
            </span>
          )}
          <div className="min-w-0">
            <h2 className="text-sm font-semibold tracking-wide text-slate-100">{title}</h2>
            {subtitle && <p className="mt-0.5 text-xs text-slate-400">{subtitle}</p>}
          </div>
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}

export type Tone = "good" | "warn" | "bad" | "info" | "neutral";
const TONE: Record<Tone, string> = {
  good: "border-emerald-500/35 bg-emerald-500/10 text-emerald-200",
  warn: "border-amber-500/35 bg-amber-500/10 text-amber-200",
  bad: "border-rose-500/40 bg-rose-500/10 text-rose-200",
  info: "border-cyan-500/35 bg-cyan-500/10 text-cyan-200",
  neutral: "border-slate-600/60 bg-slate-800/60 text-slate-300",
};
const DOT: Record<Tone, string> = { good: "bg-emerald-400", warn: "bg-amber-400", bad: "bg-rose-400", info: "bg-cyan-400", neutral: "bg-slate-400" };

/** Status text is always written out: colour is never the only signal. */
export function Chip({ tone, children, title, dot = false }: { tone: Tone; children: ReactNode; title?: string; dot?: boolean }) {
  return (
    <span title={title} className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium ${TONE[tone]}`}>
      {dot && <span className={`size-1.5 rounded-full ${DOT[tone]}`} aria-hidden="true" />}
      {children}
    </span>
  );
}

export function VerifyBadge() {
  return (
    <Chip tone="warn" title="This legal reference has not been checked against the official text.">
      ⚠ Verify against the official text
    </Chip>
  );
}

export function Disclaimer({ text }: { text: string }) {
  return (
    <aside role="note" aria-label="Disclaimer" className="flex items-start gap-2.5 rounded-xl border border-amber-500/30 bg-amber-500/[0.07] p-3 text-sm text-amber-100">
      <Icon name="scale" className="mt-0.5 size-4 shrink-0 text-amber-300" />
      <span>
        <strong className="text-amber-200">Not legal advice.</strong> {text}
      </span>
    </aside>
  );
}

export function PageHeader({ eyebrow, title, subtitle, actions }: { eyebrow?: string; title: ReactNode; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-3">
      <div>
        {eyebrow && <p className="label-caps text-cyan-300/80">{eyebrow}</p>}
        <h1 className="mt-1 text-2xl font-semibold tracking-tight text-white">{title}</h1>
        {subtitle && <p className="mt-1 max-w-3xl text-sm text-slate-400">{subtitle}</p>}
      </div>
      {actions}
    </header>
  );
}

const STAT_TONE: Record<Tone, { text: string; glow: string }> = {
  good: { text: "text-emerald-300", glow: "bg-emerald-500/15" },
  warn: { text: "text-amber-300", glow: "bg-amber-500/15" },
  bad: { text: "text-rose-300", glow: "bg-rose-500/15" },
  info: { text: "text-cyan-300", glow: "bg-cyan-500/15" },
  neutral: { text: "text-slate-200", glow: "bg-slate-500/10" },
};

/** A bento KPI tile. `value` is shown as given: callers pass "—" when the source has no data. */
export function StatCard({ label, value, unit, tone = "neutral", icon, hint, visual }: { label: string; value: ReactNode; unit?: string; tone?: Tone; icon: IconName; hint: ReactNode; visual?: ReactNode }) {
  const t = STAT_TONE[tone];
  return (
    <div className="glass group relative overflow-hidden p-4 animate-fade-in" role="group" aria-label={label}>
      <span className={`pointer-events-none absolute -top-10 -right-10 size-28 rounded-full blur-2xl animate-glow ${t.glow}`} aria-hidden="true" />
      <div className="flex items-center justify-between gap-2">
        <p className="label-caps">{label}</p>
        <Icon name={icon} className={`size-4 ${t.text}`} />
      </div>
      <div className="mt-3 flex items-end justify-between gap-2">
        <p className={`text-3xl font-semibold tabular-nums tracking-tight ${t.text}`}>
          {value}
          {unit && <span className="ml-1 text-sm font-medium text-slate-400">{unit}</span>}
        </p>
        {visual}
      </div>
      <p className="mt-2 text-xs text-slate-400">{hint}</p>
    </div>
  );
}

/** Pure-SVG progress ring (stroke-dasharray attribute). Decorative: callers render the number as text. */
export function ProgressRing({ value, size = 56, stroke = 6, tone = "info" }: { value: number; size?: number; stroke?: number; tone?: Tone }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const v = Math.min(1, Math.max(0, Number.isFinite(value) ? value : 0));
  const color = { good: "#34d399", warn: "#fbbf24", bad: "#fb7185", info: "#22d3ee", neutral: "#94a3b8" }[tone];
  return (
    <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size} aria-hidden="true" focusable="false" className="shrink-0 -rotate-90">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1e293b" strokeWidth={stroke} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke} strokeLinecap="round" strokeDasharray={`${(v * c).toFixed(2)} ${c.toFixed(2)}`} className="animate-gauge" />
    </svg>
  );
}

/** Decorative sparkline of real values (oldest first); an optional threshold line. */
export function Sparkline({ values, threshold, tone = "info", width = 96, height = 32 }: { values: number[]; threshold?: number; tone?: Tone; width?: number; height?: number }) {
  if (values.length < 2) return null;
  const max = Math.max(...values, threshold ?? 0) || 1;
  const pts = values.map((v, i) => `${((i / (values.length - 1)) * (width - 4) + 2).toFixed(1)},${(height - 2 - (v / max) * (height - 4)).toFixed(1)}`);
  const color = { good: "#34d399", warn: "#fbbf24", bad: "#fb7185", info: "#22d3ee", neutral: "#94a3b8" }[tone];
  const ty = threshold === undefined ? null : height - 2 - (threshold / max) * (height - 4);
  return (
    <svg viewBox={`0 0 ${width} ${height}`} width={width} height={height} aria-hidden="true" focusable="false" className="shrink-0 overflow-visible">
      {ty !== null && <line x1="0" x2={width} y1={ty} y2={ty} stroke="#f59e0b" strokeOpacity="0.55" strokeDasharray="3 3" strokeWidth="1" />}
      <polyline points={pts.join(" ")} fill="none" stroke={color} strokeWidth="1.75" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={pts[pts.length - 1]!.split(",")[0]} cy={pts[pts.length - 1]!.split(",")[1]} r="2.5" fill={color} />
    </svg>
  );
}

// ---- Icons: hand-drawn 24×24 stroke paths, decorative (aria-hidden) ----
const PATHS = {
  home: "M3 10.5 12 3l9 7.5M5.25 9v11.25h13.5V9M9.75 20.25v-6h4.5v6",
  documents: "M7 3.75h6.75L18.75 8.7V20.25H7zM13.5 3.75V9h5.25M9.75 13.5h5.25M9.75 16.5h3.75",
  "file-lock": "M14.25 3.75H7a1.5 1.5 0 0 0-1.5 1.5v13.5a1.5 1.5 0 0 0 1.5 1.5h4.5M14.25 3.75 18.75 8.25M14.25 3.75v4.5h4.5M18.75 8.25v3M14.25 16.5h6v4.5h-6zM15.75 16.5V15a1.5 1.5 0 0 1 3 0v1.5",
  audit: "M9 4.5h6M8.25 3h7.5v3h-7.5zM6 4.5H4.5v16.5h15V4.5H18M8.25 11.25l1.5 1.5 3-3M8.25 16.5h7.5",
  agreement: "M4.5 4.5h11.25l3.75 3.75V19.5h-15zM8.25 12l2.25 2.25 4.5-4.5M8.25 17.25h7.5",
  scale: "M12 3.75v16.5M6.75 20.25h10.5M4.5 7.5h15M4.5 7.5 2.25 13.5a2.25 2.25 0 0 0 4.5 0zM19.5 7.5l-2.25 6a2.25 2.25 0 0 0 4.5 0z",
  radar: "M12 21a9 9 0 1 1 9-9M12 16.5a4.5 4.5 0 1 1 4.5-4.5M12 12l6.36-6.36M12 12h.01",
  shield: "M12 3 4.5 6v5.25c0 4.66 3.2 8.6 7.5 9.75 4.3-1.15 7.5-5.09 7.5-9.75V6z",
  "shield-check": "M12 3 4.5 6v5.25c0 4.66 3.2 8.6 7.5 9.75 4.3-1.15 7.5-5.09 7.5-9.75V6zM9 12l2.25 2.25L15 10.5",
  logout: "M15.75 8.25 19.5 12l-3.75 3.75M19.5 12H9M12.75 20.25H5.25a1.5 1.5 0 0 1-1.5-1.5V5.25a1.5 1.5 0 0 1 1.5-1.5h7.5",
  switch: "M7.5 7.5h12l-3-3M16.5 16.5h-12l3 3",
  lock: "M6.75 10.5h10.5v9.75H6.75zM9 10.5V7.5a3 3 0 0 1 6 0v3M12 14.25v2.25",
  key: "M15.75 5.25a3 3 0 1 1 0 6 3 3 0 0 1 0-6M13.5 10.5 4.5 19.5M7.5 16.5l2.25 2.25M9.75 14.25 12 16.5",
  hash: "M9 3.75 7.5 20.25M16.5 3.75 15 20.25M4.5 9h15.75M3.75 15h15.75",
  check: "M4.5 12.75 9.75 18 19.5 6",
  x: "M6 6l12 12M18 6 6 18",
  alert: "M12 3.75 2.25 20.25h19.5zM12 9.75v4.5M12 17.25h.01",
  activity: "M3 12h4.5l2.25-6 4.5 12 2.25-6H21",
  clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18M12 7.5V12l3 1.5",
  bug: "M8.25 8.25a3.75 3.75 0 0 1 7.5 0v1.5h-7.5zM6.75 11.25h10.5v3a5.25 5.25 0 0 1-10.5 0zM3.75 12.75h3M17.25 12.75h3M4.5 7.5l2.25 2.25M19.5 7.5l-2.25 2.25M4.5 19.5l2.25-2.25M19.5 19.5l-2.25-2.25M12 11.25v8.25",
  bolt: "M13.5 3 5.25 13.5h6L10.5 21l8.25-10.5h-6z",
  download: "M12 3.75v11.25M7.5 10.5 12 15l4.5-4.5M4.5 15.75v3.75h15v-3.75",
  upload: "M12 15V3.75M7.5 8.25 12 3.75l4.5 4.5M4.5 15.75v3.75h15v-3.75",
  globe: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18M3.75 9h16.5M3.75 15h16.5M12 3a13.5 13.5 0 0 1 0 18M12 3a13.5 13.5 0 0 0 0 18",
  server: "M4.5 4.5h15v6h-15zM4.5 13.5h15v6h-15zM7.5 7.5h.01M7.5 16.5h.01",
  user: "M12 12a3.75 3.75 0 1 0 0-7.5 3.75 3.75 0 0 0 0 7.5M4.5 20.25a7.5 7.5 0 0 1 15 0",
  users: "M9 11.25a3.38 3.38 0 1 0 0-6.75 3.38 3.38 0 0 0 0 6.75M2.25 19.5a6.75 6.75 0 0 1 13.5 0M15.75 4.65a3.38 3.38 0 0 1 0 6.45M18 13.6a6.75 6.75 0 0 1 3.75 5.9",
  eye: "M2.25 12S5.25 5.25 12 5.25 21.75 12 21.75 12 18.75 18.75 12 18.75 2.25 12 2.25 12M12 14.62a2.62 2.62 0 1 0 0-5.25 2.62 2.62 0 0 0 0 5.25",
  layers: "M12 3 2.25 8.25 12 13.5l9.75-5.25zM2.25 12.75 12 18l9.75-5.25M2.25 16.5 12 21.75l9.75-5.25",
  flow: "M3.75 6h4.5v4.5h-4.5zM15.75 13.5h4.5V18h-4.5zM8.25 8.25H12a2.25 2.25 0 0 1 2.25 2.25v3a2.25 2.25 0 0 0 2.25 2.25h-.75",
  fingerprint: "M7.5 5.25A7.5 7.5 0 0 1 19.5 11.25v1.5M4.5 9.75a7.5 7.5 0 0 0-.75 3M12 8.25a3.75 3.75 0 0 1 3.75 3.75v1.5a10.5 10.5 0 0 1-1.5 5.25M8.25 12a3.75 3.75 0 0 1 .75-2.25M12 12v1.5a6.75 6.75 0 0 1-2.25 5.25M8.25 15a7.5 7.5 0 0 1-1.5 3.75",
  chevron: "M9 6l6 6-6 6",
  target: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18M12 16.5a4.5 4.5 0 1 0 0-9 4.5 4.5 0 0 0 0 9M12 12h.01",
  grid: "M3.75 3.75h6.75v6.75H3.75zM13.5 3.75h6.75v6.75H13.5zM3.75 13.5h6.75v6.75H3.75zM13.5 13.5h6.75v6.75H13.5z",
} as const;
export type IconName = keyof typeof PATHS;

export function Icon({ name, className = "size-4" }: { name: IconName; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false" className={className}>
      <path d={PATHS[name]} />
    </svg>
  );
}
