import type { TimelineEntry } from "../api/types";
import { Icon, type IconName } from "../components/ui";

const KIND: Record<TimelineEntry["kind"], string> = {
  DETECTED: "Detected",
  GUARD: "Safety guard",
  ACTION: "Playbook action",
  CONTAINED: "Contained",
  WOULD_CONTAIN: "Would contain (dry run)",
  FAILED: "Failed",
  EVIDENCE: "Evidence",
  ANALYST: "Analyst",
};

// Node style per step kind. The kind is always written as text next to the node.
const NODE: Record<TimelineEntry["kind"], { icon: IconName; node: string; label: string; line: string }> = {
  DETECTED: { icon: "radar", node: "border-cyan-400/60 bg-cyan-500/15 text-cyan-300", label: "text-cyan-300", line: "bg-cyan-500/40" },
  GUARD: { icon: "shield", node: "border-amber-400/50 bg-slate-800 text-amber-300", label: "text-amber-300", line: "bg-slate-700" },
  ACTION: { icon: "bolt", node: "border-sky-400/60 bg-sky-500/15 text-sky-300", label: "text-sky-300", line: "bg-sky-500/40" },
  CONTAINED: { icon: "check", node: "border-emerald-400/70 bg-emerald-500/20 text-emerald-300 shadow-[0_0_14px_-4px_rgb(52_211_153/0.8)]", label: "text-emerald-300", line: "bg-emerald-500/40" },
  WOULD_CONTAIN: { icon: "shield-check", node: "border-2 border-dashed border-amber-400/80 bg-amber-500/10 text-amber-300", label: "text-amber-300", line: "bg-amber-500/40" },
  FAILED: { icon: "x", node: "border-rose-400/70 bg-rose-500/15 text-rose-300", label: "text-rose-300", line: "bg-rose-500/40" },
  EVIDENCE: { icon: "lock", node: "border-violet-400/60 bg-violet-500/15 text-violet-300", label: "text-violet-300", line: "bg-violet-500/40" },
  ANALYST: { icon: "user", node: "border-slate-500/70 bg-slate-800 text-slate-300", label: "text-slate-300", line: "bg-slate-700" },
};

/**
 * The SOAR run as a connected pipeline: vertical on small screens, a wrapping
 * horizontal node graph from `md`. `active` marks the last step as still in
 * progress (the incident has not reached a terminal status yet).
 */
export function SoarTimeline({ entries, active = false }: { entries: TimelineEntry[]; active?: boolean }) {
  return (
    <ol className="flex flex-col md:flex-row md:flex-wrap md:gap-y-6" aria-label="SOAR timeline">
      {entries.map((e, i) => {
        const s = NODE[e.kind];
        const last = i === entries.length - 1;
        const pulsing = active && last;
        return (
          <li key={i} className="flex min-w-0 gap-3 md:min-w-[11rem] md:flex-1 md:basis-44 md:flex-col md:gap-2.5">
            <div className="flex flex-col items-center md:flex-row" aria-hidden="true">
              <span className={`grid size-8 shrink-0 place-items-center rounded-full border ${s.node} ${pulsing ? "animate-pulse-dot" : ""}`}>
                <Icon name={s.icon} className="size-4" />
              </span>
              {!last && <span className={`min-h-6 w-px flex-1 md:ml-2 md:h-px md:min-h-0 md:w-auto ${s.line}`} />}
            </div>
            <div className="min-w-0 pb-5 text-sm md:pr-4 md:pb-0">
              <p className="flex flex-wrap items-baseline gap-x-2">
                <span className={`text-[11px] font-semibold tracking-[0.1em] uppercase ${s.label}`}>{KIND[e.kind]}</span>
                {pulsing && <span className="text-[11px] font-medium text-cyan-300">· in progress</span>}
              </p>
              {e.at ? <p className="mt-0.5 font-mono text-[11px] break-all text-slate-400">{e.at}</p> : null}
              <span className="mt-0.5 block text-slate-200">{e.label}</span>
              {e.detail && <span className="mt-1 block break-all font-mono text-xs text-slate-400">{e.detail}</span>}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
