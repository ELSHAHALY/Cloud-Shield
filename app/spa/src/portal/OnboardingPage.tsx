// Plan D25/D26: the admin reads each agreement as PLAIN TEXT, confirms
// authority and accepts; the request carries the version and the text hash
// the server must match. Members and auditors only see the status.
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router";
import type { Agreement, AgreementStatus } from "../api/types";
import { useSession } from "../auth/session";
import { Card, Chip, ErrorBox, Icon, Loading, PageHeader } from "../components/ui";

export const ACCEPTANCE_NOTE =
  "Recorded as click-through acceptance by an MFA-authenticated user. This is evidence of acceptance, not a qualified or advanced electronic signature. Templates are not legal advice.";

function AgreementCard({ agreement, canAccept, tenantId, onAccepted }: { agreement: Agreement; canAccept: boolean; tenantId: string; onAccepted(): void }) {
  const { api } = useSession();
  const [text, setText] = useState<string | null>(null);
  const [authority, setAuthority] = useState(false);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    api.get<string>(`/agreements/${agreement.agreementId}/${agreement.version}/text`, "text").then(setText).catch(setError);
  }, [api, agreement]);

  async function accept() {
    setError(null);
    try {
      await api.post(`/agreements/${agreement.agreementId}/accept`, { version: agreement.version, sha256: agreement.sha256, authorityConfirmed: true });
      onAccepted();
    } catch (e) {
      setError(e);
    }
  }

  return (
    <Card title={`${agreement.title} (version ${agreement.version})`} icon="agreement" accent="amber" subtitle={`Effective ${agreement.effectiveDate}${agreement.required ? " · required" : ""}`}>
      <ErrorBox error={error} />
      {/* Rendered as text, never as HTML (plan D20). */}
      {text === null ? <Loading /> : <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-lg border border-slate-800 bg-slate-950/70 p-4 font-mono text-xs leading-relaxed text-slate-200" data-testid={`agreement-text-${agreement.agreementId}`}>{text}</pre>}
      <p className="mt-2 flex items-start gap-1.5 break-all font-mono text-xs text-slate-400">
        <Icon name="hash" className="mt-px size-3.5 shrink-0 text-slate-500" />
        <span>SHA-256 {agreement.sha256}</span>
      </p>
      {canAccept ? (
        <div className="mt-4 space-y-3 rounded-lg border border-slate-800 bg-slate-950/40 p-3">
          <label className="flex items-start gap-2 text-sm text-slate-200">
            <input type="checkbox" checked={authority} onChange={(e) => setAuthority(e.target.checked)} className="mt-1" />
            <span>
              I confirm I have authority to bind <span className="font-mono">{tenantId}</span> to this agreement.
            </span>
          </label>
          <button type="button" disabled={!authority || text === null} onClick={() => void accept()} className="btn-primary px-4">
            Accept
          </button>
        </div>
      ) : (
        <p className="mt-3 text-sm text-slate-400">Waiting for your tenant administrator to accept this agreement.</p>
      )}
    </Card>
  );
}

export function OnboardingPage() {
  const { api, can, me } = useSession();
  const [status, setStatus] = useState<AgreementStatus | null>(null);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(() => {
    api.get<AgreementStatus>("/agreements/status").then(setStatus).catch(setError);
  }, [api]);

  useEffect(() => {
    load();
  }, [load]);

  if (error) return <ErrorBox error={error} />;
  if (!status) return <Loading />;
  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Tenant portal" title="Agreements" subtitle="Each agreement is shown as plain text with its SHA-256; acceptance sends the version and hash the server must match." />
      <div className="flex items-start gap-2.5 rounded-xl border border-slate-800/80 bg-slate-900/60 p-3 text-sm text-slate-300">
        <Icon name="scale" className="mt-0.5 size-4 shrink-0 text-slate-400" />
        <p>{ACCEPTANCE_NOTE}</p>
      </div>
      {status.complete ? (
        <p role="status" className="glass flex flex-wrap items-center gap-3 p-3 text-sm accent-rim accent-rim-emerald">
          <Chip tone="good">All required agreements accepted</Chip>
          {can("grc:profile:write") && (
            <Link to="/grc" className="link-inline">
              Next: set your GRC profile
            </Link>
          )}
        </p>
      ) : (
        <p role="status" className="glass accent-rim accent-rim-amber p-3 text-sm text-slate-300">
          <Chip tone="warn" dot>Action needed</Chip> Document uploads and changes are blocked until every required agreement is accepted.
        </p>
      )}
      {status.pending.map((a) => (
        <AgreementCard key={`${a.agreementId}@${a.version}`} agreement={a} canAccept={can("agreement:accept")} tenantId={me.tenantId} onAccepted={load} />
      ))}
      {status.accepted.length > 0 && (
        <Card title="Accepted" icon="check" accent="emerald">
          <ul className="divide-y divide-slate-800/70 text-sm">
            {status.accepted.map((a) => (
              <li key={`${a.agreementId}@${a.version}`} className="flex flex-wrap items-center gap-x-2 gap-y-1 py-2 text-slate-300">
                <Icon name="check" className="size-4 text-emerald-300" />
                <span className="font-medium text-slate-100">{a.agreementId}</span> <span className="font-mono text-xs">{a.version}</span> by <span className="font-mono text-xs text-slate-200">{a.acceptedBy.sub}</span> at <span className="font-mono text-xs">{a.acceptedAt}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}
