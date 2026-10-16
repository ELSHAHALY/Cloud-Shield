import type { TimelineEntry } from "../api/types";

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

export function SoarTimeline({ entries }: { entries: TimelineEntry[] }) {
  return (
    <ol className="relative space-y-3 border-l border-slate-300 pl-4" aria-label="SOAR timeline">
      {entries.map((e, i) => (
        <li key={i} className="text-sm">
          <span className="block text-xs font-semibold uppercase tracking-wide text-slate-600">
            {KIND[e.kind]} {e.at ? <span className="font-mono normal-case">· {e.at}</span> : null}
          </span>
          <span>{e.label}</span>
          {e.detail && <span className="block break-all font-mono text-xs text-slate-600">{e.detail}</span>}
        </li>
      ))}
    </ol>
  );
}
