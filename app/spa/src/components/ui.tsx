import type { ReactNode } from "react";
import { messageFor } from "../api/client";

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <p role="alert" className="rounded border border-red-300 bg-red-50 p-3 text-sm text-red-800">
      {messageFor(error)}
    </p>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <p role="status" className="text-sm text-slate-600">
      {label}
    </p>
  );
}

export function Card({ title, children, actions }: { title: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm" aria-label={title}>
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="text-base font-semibold">{title}</h2>
        {actions}
      </div>
      {children}
    </section>
  );
}

const TONE: Record<string, string> = {
  good: "border-emerald-300 bg-emerald-50 text-emerald-900",
  warn: "border-amber-300 bg-amber-50 text-amber-900",
  bad: "border-red-300 bg-red-50 text-red-900",
  info: "border-sky-300 bg-sky-50 text-sky-900",
  neutral: "border-slate-300 bg-slate-50 text-slate-800",
};

/** Status text is always written out: colour is never the only signal. */
export function Chip({ tone, children, title }: { tone: keyof typeof TONE; children: ReactNode; title?: string }) {
  return (
    <span title={title} className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium ${TONE[tone]}`}>
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
    <aside role="note" aria-label="Disclaimer" className="rounded border border-amber-300 bg-amber-50 p-3 text-sm text-amber-950">
      <strong>Not legal advice.</strong> {text}
    </aside>
  );
}
