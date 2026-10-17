import { useEffect, useState } from "react";
import type { ResponsibilityMatrix } from "../api/types";
import { useSession } from "../auth/session";
import { Card, Disclaimer, ErrorBox, Loading, VerifyBadge } from "../components/ui";

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
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Shared-responsibility matrix</h1>
      <Disclaimer text={m.disclaimer} />
      <Card title={`Controls (version ${m.version}, reviewed ${m.lastReviewed})`}>
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-xs uppercase text-slate-600">
              <tr>
                <th className="py-1 pr-3">Control</th>
                {m.providers.map((p) => (
                  <th key={p} className="py-1 pr-3">
                    {p.toUpperCase()}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {m.controls.map((c) => (
                <tr key={c.id} className="border-t border-slate-100 align-top">
                  <td className="py-2 pr-3 font-medium">{c.control}</td>
                  {m.providers.map((p) => {
                    const cell = c.cells[p];
                    return (
                      <td key={p} className="py-2 pr-3">
                        <span className="block">{cell.service}</span>
                        <span className="block text-xs text-slate-600">
                          {cell.responsibility} · {cell.status === "built" ? "built" : "mapped, not built"}
                        </span>
                        {cell.verify && <VerifyBadge />}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <Card title="Layers">
        <ul className="text-sm">
          {m.layers.map((l) => (
            <li key={l.layer} className="py-1">
              <span className="font-medium">{l.layer}:</span> {l.owner}. <span className="text-slate-600">{l.notes}</span>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
