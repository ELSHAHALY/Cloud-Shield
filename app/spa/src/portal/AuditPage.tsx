import { useCallback, useEffect, useState } from "react";
import type { AuditEvent, AuditPage as Page } from "../api/types";
import { useSession } from "../auth/session";
import { Card, Chip, ErrorBox, Icon, Loading, PageHeader } from "../components/ui";

export function AuditTable({ items }: { items: AuditEvent[] }) {
  return (
    <div className="-mx-4 overflow-x-auto md:-mx-5">
      <table className="data-table">
        <thead>
          <tr>
            <th className="px-4 py-2 md:pl-5">Time (UTC)</th>
            <th className="px-3 py-2">Action</th>
            <th className="px-3 py-2">Actor</th>
            <th className="px-3 py-2">Resource</th>
            <th className="px-4 py-2 md:pr-5">Source IP</th>
          </tr>
        </thead>
        <tbody>
          {items.map((e) => (
            <tr key={e.eventKey} className="align-top">
              <td className="px-4 py-2 font-mono text-xs whitespace-nowrap text-slate-400 md:pl-5">{e.at}</td>
              <td className="px-3 py-2">
                <Chip tone={e.outcome === "DENIED" ? "bad" : "neutral"} dot={e.outcome === "DENIED"} title={`Outcome: ${e.outcome}`}>
                  {e.action}
                </Chip>
              </td>
              <td className={`px-3 py-2 font-mono text-xs ${e.actor.type === "user" ? "text-slate-200" : "text-slate-400 italic"}`}>{e.actor.type === "user" ? e.actor.sub : "anonymous"}</td>
              <td className="px-3 py-2 font-mono text-xs text-slate-300">
                {e.resource.type}
                {e.resource.id ? `/${e.resource.id}` : ""}
              </td>
              <td className={`px-4 py-2 font-mono text-xs whitespace-nowrap md:pr-5 ${e.sourceIp && !e.sourceIpTrusted ? "text-amber-200" : "text-slate-300"}`}>
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
    <div className="space-y-6">
      <PageHeader
        eyebrow={path === "/audit" ? "Tenant portal" : "Security operations"}
        title={title}
        subtitle={
          <span className="flex items-start gap-2">
            <Icon name="fingerprint" className="mt-0.5 size-4 shrink-0 text-slate-400" />
            <span>Insert-only audit table: conditional writes, no update or delete permission, a stream and point-in-time recovery. It is not WORM storage.</span>
          </span>
        }
      />
      <ErrorBox error={error} />
      <Card title="Events (last 30 days, newest first)" icon="audit" accent="cyan" subtitle={items ? `${items.length} loaded${next ? ", more available" : ""} · DENIED outcomes in rose` : undefined}>
        {!items ? <Loading /> : <AuditTable items={items} />}
        {next && (
          <button type="button" className="btn-secondary mt-3" onClick={() => loadMore(next)}>
            Load more
          </button>
        )}
      </Card>
    </div>
  );
}
