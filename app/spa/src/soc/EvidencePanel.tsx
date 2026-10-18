// Chain of custody (plan §12): recorded vs recomputed SHA-256, Object Lock as
// found, and the IR report download (fetch with bearer → Blob → <a download>).
// Markdown is never rendered.
import { useState } from "react";
import type { ApiClient } from "../api/client";
import type { EvidenceVerification } from "../api/types";
import { Card, Chip, ErrorBox, Icon, type IconName } from "../components/ui";

const BANNER: Record<"good" | "bad" | "warn" | "neutral", { box: string; iconBox: string; text: string; icon: IconName }> = {
  good: { box: "border-emerald-500/35 bg-emerald-500/[0.07]", iconBox: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300", text: "text-emerald-200", icon: "shield-check" },
  bad: { box: "border-rose-500/45 bg-rose-500/10", iconBox: "border-rose-500/50 bg-rose-500/15 text-rose-300", text: "text-rose-200", icon: "alert" },
  warn: { box: "border-amber-500/35 bg-amber-500/[0.07]", iconBox: "border-amber-500/40 bg-amber-500/15 text-amber-300", text: "text-amber-200", icon: "alert" },
  neutral: { box: "border-slate-700 bg-slate-900/50", iconBox: "border-slate-700 bg-slate-800 text-slate-300", text: "text-slate-200", icon: "file-lock" },
};

// Object Lock as found: true / false / null (could not be read).
const LOCK_TONE: Record<string, string> = {
  true: "border-emerald-500/35 bg-emerald-500/10 text-emerald-200",
  false: "border-amber-500/35 bg-amber-500/10 text-amber-200",
  null: "border-slate-600/60 bg-slate-800/60 text-slate-300",
};

function Hash({ value, label }: { value: string | null; label: string }) {
  const [full, setFull] = useState(false);
  return (
    <div className="min-w-0 rounded-lg border border-slate-800 bg-slate-950/70 p-2.5">
      <p className="label-caps mb-1 flex items-center gap-1.5">
        <Icon name="hash" className="size-3 text-slate-400" />
        {label === "recorded" ? "Recorded SHA-256" : "Recomputed SHA-256"}
      </p>
      {!value ? (
        <span className="font-mono text-xs text-slate-400">—</span>
      ) : (
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <code className="min-w-0 break-all font-mono text-xs text-slate-100" aria-label={`${label} ${value}`}>
            {full ? value : `${value.slice(0, 12)}…`}
          </code>
          <span className="flex gap-1">
            <button type="button" className="rounded px-1 text-xs link-inline" onClick={() => setFull((f) => !f)}>
              {full ? "Shorten" : "Full hash"}
            </button>
            <button type="button" className="rounded px-1 text-xs link-inline" onClick={() => void navigator.clipboard?.writeText(value)}>
              Copy
            </button>
          </span>
        </div>
      )}
    </div>
  );
}

export function chainLabel(v: EvidenceVerification): { tone: "good" | "bad" | "warn" | "neutral"; text: string } {
  if (v.chainOfCustodyOk === true) return { tone: "good", text: "Chain of custody: intact" };
  if (v.chainOfCustodyOk === false) return { tone: "bad", text: "Chain of custody: BROKEN" };
  if (v.truncated) return { tone: "warn", text: "Chain of custody: not fully verified (more than 20 objects)" };
  if (v.checks.some((c) => c.error === "too-large")) return { tone: "warn", text: "Chain of custody: not fully verified (an object over 5 MiB was not hashed)" };
  return { tone: "neutral", text: "No evidence recorded" };
}

export function lockLabel(lock: EvidenceVerification["objectLock"]): string {
  if (lock.enabled === null) return "Object Lock status could not be read";
  if (!lock.enabled) return "Object Lock not enabled on the evidence bucket";
  return `Object Lock enabled${lock.mode ? `: ${lock.mode}` : ""}${lock.days ? `, default ${lock.days} day(s)` : ""}`;
}

export async function downloadReport(api: ApiClient, incidentId: string, format: "md" | "json"): Promise<void> {
  const blob = await api.get<Blob>(`/soc/incidents/${encodeURIComponent(incidentId)}/report?format=${format}`, "blob");
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `ir-${incidentId.replace(/[^A-Za-z0-9._-]/g, "_")}.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function EvidencePanel({ api, incidentId }: { api: ApiClient; incidentId: string }) {
  const [result, setResult] = useState<EvidenceVerification | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function verify() {
    setBusy(true);
    setError(null);
    try {
      setResult(await api.get<EvidenceVerification>(`/soc/incidents/${encodeURIComponent(incidentId)}/evidence`));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  async function download(format: "md" | "json") {
    setError(null);
    try {
      await downloadReport(api, incidentId, format);
    } catch (e) {
      setError(e);
    }
  }

  const chain = result ? chainLabel(result) : null;
  const banner = chain ? BANNER[chain.tone] : null;
  return (
    <Card
      title="Chain-of-custody vault"
      icon="lock"
      accent={chain?.tone === "bad" ? "rose" : chain?.tone === "good" ? "emerald" : chain?.tone === "warn" ? "amber" : "none"}
      subtitle="Evidence and IR report · recorded vs recomputed SHA-256, Object Lock as found"
      actions={
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => void download("md")} className="btn-primary">
            <Icon name="download" className="size-4" />
            Download report (Markdown)
          </button>
          <button type="button" onClick={() => void verify()} disabled={busy} className="btn-secondary">
            <Icon name="fingerprint" className="size-4" />
            {busy ? "Verifying…" : "Verify evidence"}
          </button>
          <button type="button" onClick={() => void download("json")} className="btn-secondary">
            JSON
          </button>
        </div>
      }
    >
      <div className="space-y-3">
        <ErrorBox error={error} />
        {!result && (
          <p className="flex items-start gap-2 rounded-lg border border-dashed border-slate-700 p-3 text-sm text-slate-400">
            <Icon name="file-lock" className="mt-0.5 size-4 shrink-0 text-slate-400" />
            <span>Not verified in this view yet. Verify evidence recomputes the SHA-256 of each recorded object and compares it with the recorded hash.</span>
          </p>
        )}
        {result && chain && banner && (
          <div className="space-y-3 text-sm">
            <div className={`flex flex-wrap items-start justify-between gap-3 rounded-xl border p-3.5 ${banner.box}`}>
              <div className="flex min-w-0 items-start gap-3">
                <span className={`grid size-9 shrink-0 place-items-center rounded-lg border ${banner.iconBox}`}>
                  <Icon name={banner.icon} className="size-5" />
                </span>
                <div className="min-w-0">
                  <p className={`text-base font-semibold ${banner.text}`}>{chain.text}</p>
                  <p className="mt-0.5 text-xs text-slate-400">
                    {result.label}. Verified {result.verifiedAt}. The authoritative report is <code className="text-slate-200">make ir-report INCIDENT={incidentId}</code>.
                  </p>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium ${LOCK_TONE[String(result.objectLock.enabled)]}`}>
                  <Icon name="lock" className="size-3" />
                  <span>{lockLabel(result.objectLock)}</span>
                </span>
                {result.objectLock.enabled === true && result.objectLock.mode === "COMPLIANCE" && (
                  <Chip tone="good" title="Write once, read many: COMPLIANCE-mode Object Lock, as reported by the bucket">
                    WORM (compliance)
                  </Chip>
                )}
                {result.objectLock.enabled === true && result.objectLock.mode !== "COMPLIANCE" && (
                  <Chip tone="info" title="GOVERNANCE mode can be bypassed by a principal holding s3:BypassGovernanceRetention">
                    WORM (governance, bypassable)
                  </Chip>
                )}
              </div>
            </div>
            {result.checks.length > 0 && (
              <ul className="space-y-2" aria-label="Evidence objects">
                {result.checks.map((c) => (
                  <li key={`${c.key}@${c.versionId ?? ""}`} className={`rounded-xl border p-3 ${c.ok ? "border-slate-800 bg-slate-900/40" : "border-rose-500/30 bg-rose-500/[0.05]"}`}>
                    <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                      <p className="flex min-w-0 items-center gap-2">
                        <Icon name="file-lock" className="size-4 shrink-0 text-violet-300" />
                        <span className="break-all font-mono text-xs text-slate-200">{c.key}</span>
                        {c.versionId && <span className="font-mono text-[11px] text-slate-400">v {c.versionId}</span>}
                      </p>
                      {c.ok ? (
                        <Chip tone="good" dot>
                          ✓ match
                        </Chip>
                      ) : (
                        <Chip tone="bad" dot>
                          ✗ {c.error ?? "mismatch"}
                        </Chip>
                      )}
                    </div>
                    <div className="grid gap-2 md:grid-cols-2">
                      <Hash value={c.recordedSha256} label="recorded" />
                      <Hash value={c.actualSha256} label="recomputed" />
                    </div>
                    <p className="mt-2 flex items-center gap-1.5 text-xs text-slate-400">
                      <Icon name="clock" className="size-3.5 shrink-0" />
                      <span>Retention:</span>
                      <span className="text-slate-200">
                        {c.retention ? `${c.retention.mode ?? "?"} until ${c.retention.retainUntil ?? "?"}` : "not reported"}
                        {c.legalHold === true ? " · legal hold" : ""}
                      </span>
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>
    </Card>
  );
}
