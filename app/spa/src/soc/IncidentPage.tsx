import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";
import type { IncidentDetail } from "../api/types";
import { useSession } from "../auth/session";
import { Card, Chip, ErrorBox, Loading } from "../components/ui";
import { EvidencePanel } from "./EvidencePanel";
import { SoarTimeline } from "./SoarTimeline";
import { StatusChip } from "./status";

export function IncidentPage() {
  const { incidentId = "" } = useParams();
  const { api } = useSession();
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    let live = true;
    api
      .get<IncidentDetail>(`/soc/incidents/${encodeURIComponent(incidentId)}`)
      .then((d) => live && setIncident(d))
      .catch((e: unknown) => live && setError(e));
    return () => {
      live = false;
    };
  }, [api, incidentId]);

  if (error) return <ErrorBox error={error} />;
  if (!incident) return <Loading />;
  return (
    <div className="space-y-4">
      <Link to="/soc" className="text-sm text-indigo-700 underline">
        ← SOC dashboard
      </Link>
      <h1 className="flex flex-wrap items-center gap-2 text-xl font-semibold">
        <span className="font-mono text-base">{incident.incidentId}</span> <StatusChip incident={incident} />
        {incident.notifyOnly && <Chip tone="info">Notify only: SOAR never blocks decoy hits; any block is an analyst decision</Chip>}
      </h1>
      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Incident">
          <dl className="grid grid-cols-3 gap-1 text-sm">
            <dt className="text-slate-600">Finding type</dt>
            <dd className="col-span-2 font-mono text-xs">{incident.findingType ?? "—"}</dd>
            <dt className="text-slate-600">Severity</dt>
            <dd className="col-span-2">{incident.severity ?? "—"}</dd>
            <dt className="text-slate-600">MTTC</dt>
            <dd className="col-span-2">{incident.mttcSeconds === null ? "— (not contained)" : `${incident.mttcSeconds.toFixed(3)} s`}</dd>
            <dt className="text-slate-600">ATT&CK</dt>
            <dd className="col-span-2">
              {incident.triage.techniques.join(", ") || "analyst review"} ({incident.triage.tactic})
            </dd>
            <dt className="text-slate-600">Impact</dt>
            <dd className="col-span-2">{incident.triage.impact}</dd>
            {incident.guardReason && (
              <>
                <dt className="text-slate-600">Guard</dt>
                <dd className="col-span-2 font-mono text-xs">{incident.guardReason}</dd>
              </>
            )}
            {incident.block && (
              <>
                <dt className="text-slate-600">PB-05 block</dt>
                <dd className="col-span-2 font-mono text-xs">
                  {incident.block.blockedCidr} · {incident.block.blockState} · expires {incident.block.blockExpiresAt}
                </dd>
              </>
            )}
            <dt className="text-slate-600">Execution</dt>
            <dd className="col-span-2 break-all font-mono text-xs">{incident.executionArn ?? "—"}</dd>
          </dl>
        </Card>
        <Card title="SOAR timeline">
          <SoarTimeline entries={incident.timeline} />
        </Card>
      </div>
      <Card title="Response checklist (human)">
        <div className="grid gap-4 text-sm md:grid-cols-2">
          <div>
            <h3 className="font-medium">Eradication</h3>
            <ul className="list-disc pl-5">{incident.triage.eradication.map((x) => <li key={x}>{x}</li>)}</ul>
          </div>
          <div>
            <h3 className="font-medium">Recovery</h3>
            <ul className="list-disc pl-5">{incident.triage.recovery.map((x) => <li key={x}>{x}</li>)}</ul>
          </div>
        </div>
      </Card>
      {incident.relatedAudit.length > 0 && (
        <Card title="Decoy route audit (this hour)">
          <ul className="text-sm">
            {incident.relatedAudit.map((e) => (
              <li key={e.eventId} className="font-mono text-xs">
                {e.at} · {String(e.details.method ?? "")} {String(e.details.path ?? "")} · {e.sourceIp ?? "unknown IP"}
                {e.sourceIpTrusted ? "" : " (untrusted)"} · {e.actor.type === "user" ? `user ${e.actor.sub ?? ""}` : "anonymous"}
              </li>
            ))}
          </ul>
        </Card>
      )}
      <EvidencePanel api={api} incidentId={incident.incidentId} />
    </div>
  );
}
