import { useEffect, useState } from "react";
import { Link } from "react-router";
import type { ResponsibilityMatrix } from "../api/types";
import { useSession } from "../auth/session";
import { Card, Chip, Disclaimer, ErrorBox, Icon, Loading, PageHeader, VerifyBadge, type Tone } from "../components/ui";

type Cell = ResponsibilityMatrix["controls"][number]["cells"]["aws"];

const RESPONSIBILITY_TONE: Record<Cell["responsibility"], Tone> = { provider: "info", shared: "neutral", customer: "warn" };

function MatrixCell({ cell }: { cell: Cell }) {
  const built = cell.status === "built";
  return (
    <div className={`h-full space-y-1.5 rounded-lg border p-2.5 ${built ? "border-emerald-500/30 bg-emerald-500/[0.05]" : "border-dashed border-slate-700 bg-slate-950/30"}`}>
      <span className="block font-medium text-slate-100">{cell.service}</span>
      <span className="flex flex-wrap items-center gap-1.5">
        <Chip tone={RESPONSIBILITY_TONE[cell.responsibility]}>{cell.responsibility}</Chip>
        <span className={`inline-flex items-center gap-1 text-xs ${built ? "text-emerald-200" : "text-slate-400"}`}>
          <Icon name={built ? "check" : "layers"} className="size-3.5" />
          {built ? "built" : "mapped, not built"}
        </span>
      </span>
      {cell.verify && <VerifyBadge />}
    </div>
  );
}

export function MatrixPage() {
  const { api } = useSession();
  const [m, setM] = useState<ResponsibilityMatrix | null>(null);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    api.get<ResponsibilityMatrix>("/grc/responsibility-matrix").then(setM).catch(setError);
  }, [api]);
  if (error) return <ErrorBox error={error} />;
  if (!m) return <Loading />;
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Governance"
        title="Shared-responsibility matrix"
        subtitle="Who owns each control on each cloud, and whether this project built it or only mapped it."
        actions={
          <Link to="/grc" className="btn-secondary no-underline">
            <Icon name="scale" className="size-4" />
            GRC hub
          </Link>
        }
      />
      <Disclaimer text={m.disclaimer} />
      <Card title={`Controls (version ${m.version}, reviewed ${m.lastReviewed})`} icon="grid" accent="cyan" subtitle="Solid green border: built. Dashed border: a mapping only. Each cell says which in words.">
        <div className="-mx-4 overflow-x-auto md:-mx-5">
          <table className="data-table">
            <thead>
              <tr>
                <th className="px-4 py-2 md:pl-5">Control</th>
                {m.providers.map((p) => (
                  <th key={p} className="min-w-48 px-3 py-2">
                    <span className="inline-flex items-center gap-1.5">
                      <Icon name="server" className="size-3.5 text-slate-500" />
                      {p.toUpperCase()}
                    </span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {m.controls.map((c) => (
                <tr key={c.id} className="align-top">
                  <td className="px-4 py-3 md:pl-5">
                    <span className="block font-medium text-slate-100">{c.control}</span>
                    <span className="mt-0.5 block font-mono text-[11px] text-slate-400">{c.layer}</span>
                  </td>
                  {m.providers.map((p) => (
                    <td key={p} className="px-3 py-3">
                      <MatrixCell cell={c.cells[p]} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <Card title="Layers" icon="layers">
        <ul className="divide-y divide-slate-800/70 text-sm">
          {m.layers.map((l) => (
            <li key={l.layer} className="flex flex-wrap items-baseline gap-x-2 gap-y-1 py-2">
              <span className="font-medium text-slate-100">{l.layer}:</span> <span className="text-slate-300">{l.owner}.</span> <span className="text-slate-400">{l.notes}</span>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
