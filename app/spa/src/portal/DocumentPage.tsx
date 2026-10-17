import { useEffect, useState, type FormEvent } from "react";
import { useNavigate, useParams } from "react-router";
import type { DocumentCreate, DocumentMeta } from "../api/types";
import { useSession } from "../auth/session";
import { Card, ErrorBox, Loading } from "../components/ui";
import { downloadDocument } from "./upload";

export function DocumentPage() {
  const { docId = "" } = useParams();
  const { api, can, me } = useSession();
  const navigate = useNavigate();
  const [doc, setDoc] = useState<DocumentMeta | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [title, setTitle] = useState("");
  const [classification, setClassification] = useState<DocumentCreate["classification"]>("internal");

  useEffect(() => {
    api
      .get<DocumentMeta>(`/documents/${encodeURIComponent(docId)}`)
      .then((d) => {
        setDoc(d);
        setTitle(d.title);
        setClassification(d.classification);
      })
      .catch(setError);
  }, [api, docId]);

  // UX only: the server enforces ownership (ABAC) and the agreement gate.
  const mayWrite = doc !== null && can("doc:write") && (me.groups.includes("admin") || doc.ownerSub === me.sub);

  async function save(e: FormEvent) {
    e.preventDefault();
    if (!doc) return;
    setError(null);
    try {
      setDoc(await api.patch<DocumentMeta>(`/documents/${doc.docId}`, { title, classification }, { "If-Match": `"${doc.version}"` }));
    } catch (err) {
      setError(err);
    }
  }

  async function remove() {
    if (!doc || !window.confirm(`Delete "${doc.title}"? Its content is erased within 30 days.`)) return;
    try {
      await api.del(`/documents/${doc.docId}`);
      navigate("/documents");
    } catch (err) {
      setError(err);
    }
  }

  if (!doc) return error ? <ErrorBox error={error} /> : <Loading />;
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">{doc.title}</h1>
      <ErrorBox error={error} />
      <Card title="Metadata">
        <dl className="grid grid-cols-3 gap-1 text-sm">
          <dt className="text-slate-600">Status</dt>
          <dd className="col-span-2">{doc.status}</dd>
          <dt className="text-slate-600">Type / size</dt>
          <dd className="col-span-2">
            {doc.contentType} · {doc.sizeBytes} bytes
          </dd>
          <dt className="text-slate-600">SHA-256</dt>
          <dd className="col-span-2 break-all font-mono text-xs">{doc.sha256}</dd>
          <dt className="text-slate-600">Owner</dt>
          <dd className="col-span-2 font-mono text-xs">{doc.ownerSub}</dd>
          <dt className="text-slate-600">Version</dt>
          <dd className="col-span-2">{doc.version}</dd>
        </dl>
        {doc.status === "AVAILABLE" && (
          <button type="button" className="mt-3 rounded border border-slate-300 px-3 py-1 text-sm" onClick={() => void downloadDocument(api, doc.docId).catch(setError)}>
            Download
          </button>
        )}
      </Card>
      {mayWrite && doc.status === "AVAILABLE" && (
        <Card title="Edit">
          <form onSubmit={save} className="flex flex-wrap items-end gap-3" aria-label="Edit document">
            <label className="text-sm">
              Title
              <input className="mt-1 block rounded border border-slate-300 px-2 py-1" maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} required />
            </label>
            <label className="text-sm">
              Classification
              <select className="mt-1 block rounded border border-slate-300 px-2 py-1" value={classification} onChange={(e) => setClassification(e.target.value as DocumentCreate["classification"])}>
                {(["public", "internal", "confidential", "restricted"] as const).map((c) => (
                  <option key={c}>{c}</option>
                ))}
              </select>
            </label>
            <button type="submit" className="rounded bg-indigo-700 px-3 py-1 text-sm text-white">
              Save
            </button>
            <button type="button" onClick={() => void remove()} className="rounded border border-red-300 px-3 py-1 text-sm text-red-800">
              Delete
            </button>
          </form>
        </Card>
      )}
    </div>
  );
}
