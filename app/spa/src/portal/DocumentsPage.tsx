import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router";
import type { DocumentCreate, DocumentMeta, DocumentPage } from "../api/types";
import { useSession } from "../auth/session";
import { Card, Chip, ErrorBox, Loading } from "../components/ui";
import { ACCEPTED, downloadDocument, uploadDocument } from "./upload";

const CLASSES: DocumentCreate["classification"][] = ["public", "internal", "confidential", "restricted"];

export function DocumentsPage() {
  const { api, can } = useSession();
  const [items, setItems] = useState<DocumentMeta[] | null>(null);
  const [next, setNext] = useState<string | undefined>();
  const [error, setError] = useState<unknown>(null);
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState("");
  const [classification, setClassification] = useState<DocumentCreate["classification"]>("internal");
  const [tags, setTags] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const [reload, setReload] = useState(0);

  const fetchPage = useCallback((cursor?: string) => api.get<DocumentPage>(`/documents?limit=25${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`), [api]);

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
  }, [fetchPage, reload]);

  function loadMore(cursor: string) {
    fetchPage(cursor)
      .then((page) => {
        setItems((prev) => [...(prev ?? []), ...page.items]);
        setNext(page.nextCursor);
      })
      .catch(setError);
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!file) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const tagList = tags.split(",").map((t) => t.trim()).filter(Boolean);
      const meta = await uploadDocument(api, { file, title: title || file.name, classification, tags: [...new Set(tagList)] });
      setNotice(`Uploaded "${meta.title}" (SHA-256 verified by the server).`);
      setFile(null);
      setTitle("");
      setTags("");
      setReload((n) => n + 1);
    } catch (err) {
      if (err instanceof Error && err.message === "UNSUPPORTED_TYPE") setNotice("Only PDF, text, PNG, JPEG and DOCX files are accepted.");
      else setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Documents</h1>
      <ErrorBox error={error} />
      {notice && (
        <p role="status" className="rounded border border-sky-300 bg-sky-50 p-2 text-sm">
          {notice}
        </p>
      )}
      {can("doc:write") && (
        <Card title="Upload">
          <form onSubmit={submit} className="grid gap-3 md:grid-cols-2" aria-label="Upload a document">
            <label className="text-sm">
              File
              <input type="file" accept={Object.keys(ACCEPTED).join(",")} className="mt-1 block w-full text-sm" onChange={(e) => setFile(e.target.files?.[0] ?? null)} required />
            </label>
            <label className="text-sm">
              Title
              <input className="mt-1 w-full rounded border border-slate-300 px-2 py-1" maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} />
            </label>
            <label className="text-sm">
              Classification
              <select className="mt-1 w-full rounded border border-slate-300 px-2 py-1" value={classification} onChange={(e) => setClassification(e.target.value as DocumentCreate["classification"])}>
                {CLASSES.map((c) => (
                  <option key={c}>{c}</option>
                ))}
              </select>
            </label>
            <label className="text-sm">
              Tags (comma separated)
              <input className="mt-1 w-full rounded border border-slate-300 px-2 py-1" value={tags} onChange={(e) => setTags(e.target.value)} />
            </label>
            <div>
              <button type="submit" disabled={busy || !file} className="rounded bg-indigo-700 px-4 py-2 text-sm text-white disabled:opacity-50">
                {busy ? "Uploading…" : "Upload"}
              </button>
            </div>
          </form>
        </Card>
      )}
      <Card title="Your tenant's documents">
        {!items ? (
          <Loading />
        ) : items.length === 0 ? (
          <p className="text-sm text-slate-600">No documents yet.</p>
        ) : (
          <ul className="divide-y divide-slate-100">
            {items.map((d) => (
              <li key={d.docId} className="flex flex-wrap items-center gap-2 py-2 text-sm">
                <Link to={`/documents/${d.docId}`} className="font-medium text-indigo-700 underline">
                  {d.title}
                </Link>
                <Chip tone={d.classification === "restricted" || d.classification === "confidential" ? "warn" : "neutral"}>{d.classification}</Chip>
                {d.status === "PENDING_UPLOAD" && <Chip tone="info">pending upload</Chip>}
                <span className="text-xs text-slate-500">{d.updatedAt}</span>
                {d.status === "AVAILABLE" && (
                  <button type="button" className="ml-auto text-xs underline" onClick={() => void downloadDocument(api, d.docId).catch(setError)}>
                    Download
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
        {next && (
          <button type="button" className="mt-2 text-sm underline" onClick={() => loadMore(next)}>
            Load more
          </button>
        )}
      </Card>
    </div>
  );
}
