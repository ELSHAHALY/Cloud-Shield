// Chain of custody (plan §12): recorded vs recomputed SHA-256, Object Lock as
// found, and the IR report download (fetch with bearer → Blob → <a download>).
// Markdown is never rendered.
import { useState } from "react";
import type { ApiClient } from "../api/client";
import type { EvidenceVerification } from "../api/types";
import { Card, Chip, ErrorBox } from "../components/ui";

function Hash({ value, label }: { value: string | null; label: string }) {
  const [full, setFull] = useState(false);
  if (!value) return <span className="font-mono text-xs">—</span>;
  return (
    <span className="inline-flex items-center gap-1">
      <code className="break-all font-mono text-xs" aria-label={`${label} ${value}`}>
        {full ? value : `${value.slice(0, 12)}…`}
      </code>
      <button type="button" className="text-xs text-indigo-700 underline" onClick={() => setFull((f) => !f)}>
        {full ? "Shorten" : "Full hash"}
      </button>
      <button type="button" className="text-xs text-indigo-700 underline" onClick={() => void navigator.clipboard?.writeText(value)}>
        Copy
      </button>
    </span>
  );
}

export function chainLabel(v: EvidenceVerification): { tone: "good" | "bad" | "warn" | "neutral"; text: string } {
  if (v.chainOfCustodyOk === true) return { tone: "good", text: "Chain of custody: intact" };
  if (v.chainOfCustodyOk === false) return { tone: "bad", text: "Chain of custody: BROKEN" };
  if (v.truncated) return { tone: "warn", text: "Chain of custody: not fully verified (more than 20 objects)" };
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
  return (
    <Card
      title="Evidence and IR report"
      actions={
        <div className="flex gap-2">
          <button type="button" onClick={() => void verify()} disabled={busy} className="rounded bg-indigo-700 px-3 py-1 text-sm text-white disabled:opacity-50">
            {busy ? "Verifying…" : "Verify evidence"}
          </button>
          <button type="button" onClick={() => void download("md")} className="rounded border border-slate-300 px-3 py-1 text-sm">
            Download report (Markdown)
          </button>
          <button type="button" onClick={() => void download("json")} className="rounded border border-slate-300 px-3 py-1 text-sm">
            JSON
          </button>
        </div>
      }
    >
      <ErrorBox error={error} />
      {result && chain && (
        <div className="space-y-2 text-sm">
          <p className="flex flex-wrap items-center gap-2">
            <Chip tone={chain.tone}>{chain.text}</Chip>
            <span>{lockLabel(result.objectLock)}</span>
          </p>
          <p className="text-xs text-slate-600">
            {result.label}. Verified {result.verifiedAt}. The authoritative report is <code>make ir-report INCIDENT={incidentId}</code>.
          </p>
          {result.checks.length > 0 && (
            <div className="overflow-x-auto">
              <table className="min-w-full text-left text-sm">
                <thead className="text-xs uppercase text-slate-600">
                  <tr>
                    <th className="py-1 pr-3">Object</th>
                    <th className="py-1 pr-3">Recorded</th>
                    <th className="py-1 pr-3">Recomputed</th>
                    <th className="py-1 pr-3">Match</th>
                    <th className="py-1 pr-3">Retention</th>
                  </tr>
                </thead>
                <tbody>
                  {result.checks.map((c) => (
                    <tr key={`${c.key}@${c.versionId ?? ""}`} className="border-t border-slate-100 align-top">
                      <td className="py-1 pr-3 font-mono text-xs break-all">{c.key}</td>
                      <td className="py-1 pr-3">
                        <Hash value={c.recordedSha256} label="recorded" />
                      </td>
                      <td className="py-1 pr-3">
                        <Hash value={c.actualSha256} label="recomputed" />
                      </td>
                      <td className="py-1 pr-3">{c.ok ? <Chip tone="good">✓ match</Chip> : <Chip tone="bad">✗ {c.error ?? "mismatch"}</Chip>}</td>
                      <td className="py-1 pr-3 text-xs">
                        {c.retention ? `${c.retention.mode ?? "?"} until ${c.retention.retainUntil ?? "?"}` : "not reported"}
                        {c.legalHold === true ? " · legal hold" : ""}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}
