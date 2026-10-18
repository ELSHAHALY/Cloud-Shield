import { type ReactNode, useEffect, useState } from "react";
import { Link, useParams } from "react-router";
import type { IncidentDetail } from "../api/types";
import { useSession } from "../auth/session";
import { Card, Chip, ErrorBox, Icon, Loading } from "../components/ui";
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
  const inProgress = incident.status === "DETECTED";
  return (
    <div className="space-y-5">
      <Link to="/soc" className="btn-ghost -ml-3 text-sm no-underline">
        ← SOC dashboard
      </Link>
      <header className="space-y-2">
        <p className="label-caps text-cyan-300/80">Incident</p>
        <h1 className="break-all font-mono text-xl font-semibold tracking-tight text-white">{incident.incidentId}</h1>
        <div className="flex flex-wrap items-center gap-2">
          <StatusChip incident={incident} />
          {incident.notifyOnly && <Chip tone="info">Notify only: SOAR never blocks decoy hits; any block is an analyst decision</Chip>}
          {incident.findingType && (
            <span className="rounded-full border border-slate-700 bg-slate-800/60 px-2 py-0.5 font-mono text-xs text-slate-300">{incident.findingType}</span>
          )}
        </div>
      </header>
      <Card title="SOAR timeline" icon="flow" subtitle={inProgress ? "Playbook run in progress: the last step is still live" : `${incident.timeline.length} step(s) recorded`}>
        <SoarTimeline entries={incident.timeline} active={inProgress} />
      </Card>
      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="Incident" icon="target">
          <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
            <Fact term="Finding type" mono>
              {incident.findingType ?? "—"}
            </Fact>
            <Fact term="Severity">{incident.severity ?? "—"}</Fact>
            <Fact term="MTTC">{incident.mttcSeconds === null ? "— (not contained)" : `${incident.mttcSeconds.toFixed(3)} s`}</Fact>
            <Fact term="ATT&CK">
              {incident.triage.techniques.join(", ") || "analyst review"} ({incident.triage.tactic})
            </Fact>
            <Fact term="Impact" wide>
              {incident.triage.impact}
            </Fact>
            {incident.guardReason && (
              <Fact term="Guard" mono wide>
                {incident.guardReason}
              </Fact>
            )}
            {incident.block && (
              <Fact term="PB-05 block" mono wide>
                {incident.block.blockedCidr} · {incident.block.blockState} · expires {incident.block.blockExpiresAt}
              </Fact>
            )}
            <Fact term="Execution" mono wide>
              {incident.executionArn ?? "—"}
            </Fact>
          </dl>
        </Card>
        <Card title="Response checklist (human)" icon="audit" subtitle="Automated containment only; eradication and recovery are analyst actions">
          <div className="grid gap-5 text-sm sm:grid-cols-2">
            <Checklist title="Eradication" items={incident.triage.eradication} />
            <Checklist title="Recovery" items={incident.triage.recovery} />
          </div>
        </Card>
      </div>
      {incident.relatedAudit.length > 0 && (
        <Card title="Decoy route audit (this hour)" icon="eye" accent="amber">
          <ul className="divide-y divide-slate-800/70 overflow-hidden rounded-lg border border-slate-800 bg-slate-950/60">
            {incident.relatedAudit.map((e) => (
              <li key={e.eventId} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 font-mono text-xs text-slate-300">
                <span className="text-slate-400">{e.at}</span>
                <span className="text-slate-100">
                  {String(e.details.method ?? "")} {String(e.details.path ?? "")} · {e.sourceIp ?? "unknown IP"}
                  {e.sourceIpTrusted ? "" : " (untrusted)"}
                </span>
                <span className="text-slate-400">{e.actor.type === "user" ? `user ${e.actor.sub ?? ""}` : "anonymous"}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}
      <EvidencePanel api={api} incidentId={incident.incidentId} />
    </div>
  );
}

function Fact({ term, children, mono = false, wide = false }: { term: string; children: ReactNode; mono?: boolean; wide?: boolean }) {
  return (
    <div className={`min-w-0 ${wide ? "sm:col-span-2" : ""}`}>
      <dt className="label-caps">{term}</dt>
      <dd className={`mt-1 break-words text-slate-100 ${mono ? "break-all font-mono text-xs" : "tabular-nums"}`}>{children}</dd>
    </div>
  );
}

function Checklist({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <h3 className="label-caps mb-2">{title}</h3>
      {items.length === 0 ? (
        <p className="text-slate-400">—</p>
      ) : (
        <ul className="space-y-2">
          {items.map((x) => (
            <li key={x} className="flex items-start gap-2 text-slate-200">
              <span className="mt-0.5 grid size-4 shrink-0 place-items-center rounded border border-slate-600 text-slate-400" aria-hidden="true">
                <Icon name="check" className="size-3" />
              </span>
              <span>{x}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
