import { useCallback, useEffect, useState } from "react";
import type { AuditEvent, AuditPage as Page } from "../api/types";
import { useSession } from "../auth/session";
import { Card, Chip, ErrorBox, Loading } from "../components/ui";

export function AuditTable({ items }: { items: AuditEvent[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full text-left text-sm">
        <thead className="text-xs uppercase text-slate-600">
          <tr>
            <th className="py-1 pr-3">Time (UTC)</th>
            <th className="py-1 pr-3">Action</th>
            <th className="py-1 pr-3">Actor</th>
            <th className="py-1 pr-3">Resource</th>
            <th className="py-1 pr-3">Source IP</th>
          </tr>
        </thead>
        <tbody>
          {items.map((e) => (
            <tr key={e.eventKey} className="border-t border-slate-100">
              <td className="py-1 pr-3 font-mono text-xs">{e.at}</td>
              <td className="py-1 pr-3">
                <Chip tone={e.outcome === "DENIED" ? "bad" : "neutral"}>{e.action}</Chip>
              </td>
              <td className="py-1 pr-3 font-mono text-xs">{e.actor.type === "user" ? e.actor.sub : "anonymous"}</td>
              <td className="py-1 pr-3 font-mono text-xs">
                {e.resource.type}
                {e.resource.id ? `/${e.resource.id}` : ""}
              </td>
              <td className="py-1 pr-3 font-mono text-xs">
                {e.sourceIp ?? "—"}
                {e.sourceIp && !e.sourceIpTrusted ? " (untrusted)" : ""}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function AuditPage({ path = "/audit", title = "Audit trail" }: { path?: string; title?: string }) {
  const { api } = useSession();
  const [items, setItems] = useState<AuditEvent[] | null>(null);
  const [next, setNext] = useState<string | undefined>();
  const [error, setError] = useState<unknown>(null);

  const fetchPage = useCallback((cursor?: string) => api.get<Page>(`${path}?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`), [api, path]);

  useEffect(() => {
    let live = true;
    fetchPage()
      .then((page) => {
        if (!live) return;
        setItems(page.items);
        setNext(page.nextCursor);
      })
      .catch((e: unknown) => live && setError(e));
    return () => {
      live = false;
    };
  }, [fetchPage]);

  function loadMore(cursor: string) {
    fetchPage(cursor)
      .then((page) => {
        setItems((prev) => [...(prev ?? []), ...page.items]);
        setNext(page.nextCursor);
      })
      .catch(setError);
  }

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">{title}</h1>
      <p className="text-sm text-slate-600">Insert-only audit table: conditional writes, no update or delete permission, a stream and point-in-time recovery. It is not WORM storage.</p>
      <ErrorBox error={error} />
      <Card title="Events (last 30 days, newest first)">
        {!items ? <Loading /> : <AuditTable items={items} />}
        {next && (
          <button type="button" className="mt-2 text-sm underline" onClick={() => loadMore(next)}>
            Load more
          </button>
        )}
      </Card>
    </div>
  );
}
