// Plan D25/D26: the admin reads each agreement as PLAIN TEXT, confirms
// authority and accepts; the request carries the version and the text hash
// the server must match. Members and auditors only see the status.
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router";
import type { Agreement, AgreementStatus } from "../api/types";
import { useSession } from "../auth/session";
import { Card, Chip, ErrorBox, Loading } from "../components/ui";

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
    <Card title={`${agreement.title} (version ${agreement.version})`}>
      <ErrorBox error={error} />
      {text === null ? <Loading /> : <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded bg-slate-50 p-3 font-mono text-xs" data-testid={`agreement-text-${agreement.agreementId}`}>{text}</pre>}
      <p className="mt-2 break-all font-mono text-xs text-slate-500">SHA-256 {agreement.sha256}</p>
      {canAccept ? (
        <div className="mt-3 space-y-2">
          <label className="flex items-start gap-2 text-sm">
            <input type="checkbox" checked={authority} onChange={(e) => setAuthority(e.target.checked)} className="mt-1" />
            <span>
              I confirm I have authority to bind <span className="font-mono">{tenantId}</span> to this agreement.
            </span>
          </label>
          <button type="button" disabled={!authority || text === null} onClick={() => void accept()} className="rounded bg-indigo-700 px-4 py-2 text-sm text-white disabled:opacity-50">
            Accept
          </button>
        </div>
      ) : (
        <p className="mt-3 text-sm text-slate-700">Waiting for your tenant administrator to accept this agreement.</p>
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
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Agreements</h1>
      <p className="rounded border border-slate-300 bg-white p-3 text-sm">{ACCEPTANCE_NOTE}</p>
      {status.complete ? (
        <p role="status" className="flex items-center gap-2 text-sm">
          <Chip tone="good">All required agreements accepted</Chip>
          {can("grc:profile:write") && (
            <Link to="/grc" className="underline">
              Next: set your GRC profile
            </Link>
          )}
        </p>
      ) : (
        <p role="status" className="text-sm">
          <Chip tone="warn">Action needed</Chip> Document uploads and changes are blocked until every required agreement is accepted.
        </p>
      )}
      {status.pending.map((a) => (
        <AgreementCard key={`${a.agreementId}@${a.version}`} agreement={a} canAccept={can("agreement:accept")} tenantId={me.tenantId} onAccepted={load} />
      ))}
      {status.accepted.length > 0 && (
        <Card title="Accepted">
          <ul className="text-sm">
            {status.accepted.map((a) => (
              <li key={`${a.agreementId}@${a.version}`}>
                <span className="font-medium">{a.agreementId}</span> {a.version} by <span className="font-mono text-xs">{a.acceptedBy.sub}</span> at {a.acceptedAt}
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}
