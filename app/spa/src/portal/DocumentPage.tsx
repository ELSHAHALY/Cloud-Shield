import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router";
import type { DocumentCreate, DocumentMeta } from "../api/types";
import { useSession } from "../auth/session";
import { Card, Chip, ErrorBox, Icon, Loading, PageHeader } from "../components/ui";
import { ClassificationPill } from "./DocumentsPage";
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
  const rows: [string, ReactNode][] = [
    ["Status", doc.status === "AVAILABLE" ? <Chip tone="good" dot>{doc.status}</Chip> : <Chip tone="neutral" dot>{doc.status}</Chip>],
    ["Classification", <ClassificationPill value={doc.classification} />],
    [
      "Type / size",
      <span className="tabular-nums">
        <span className="font-mono text-xs">{doc.contentType}</span> · {doc.sizeBytes} bytes
      </span>,
    ],
    ["SHA-256", <span className="break-all font-mono text-xs text-slate-300">{doc.sha256}</span>],
    ["Owner", <span className="break-all font-mono text-xs text-slate-300">{doc.ownerSub}</span>],
    ["Version", <span className="tabular-nums">{doc.version}</span>],
    ["Updated (UTC)", <span className="font-mono text-xs text-slate-300">{doc.updatedAt}</span>],
  ];
  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Document"
        title={doc.title}
        subtitle={
          <>
            <Link to="/documents" className="link-inline">
              Documents
            </Link>{" "}
            / <span className="font-mono text-xs text-slate-400">{doc.docId}</span>
          </>
        }
      />
      <ErrorBox error={error} />
      <Card
        title="Metadata"
        icon="file-lock"
        accent="cyan"
        subtitle="Stored with SSE-KMS (data CMK) on AWS; the SHA-256 was re-computed by the server on upload."
        actions={
          doc.status === "AVAILABLE" && (
            <button type="button" className="btn-primary" onClick={() => void downloadDocument(api, doc.docId).catch(setError)}>
              <Icon name="download" className="size-4" />
              Download
            </button>
          )
        }
      >
        <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-[10rem_1fr]">
          {rows.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="label-caps sm:pt-0.5">{k}</dt>
              <dd className="text-slate-200">{v}</dd>
            </div>
          ))}
        </dl>
      </Card>
      {mayWrite && doc.status === "AVAILABLE" && (
        <Card title="Edit" icon="key" subtitle="Changes are sent with If-Match on the current version and written to the audit trail.">
          <form onSubmit={save} className="flex flex-wrap items-end gap-3" aria-label="Edit document">
            <label className="block text-sm text-slate-300">
              Title
              <input className="mt-1.5 block w-64 max-w-full px-3 py-1.5" maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} required />
            </label>
            <label className="block text-sm text-slate-300">
              Classification
              <select className="mt-1.5 block px-3 py-1.5" value={classification} onChange={(e) => setClassification(e.target.value as DocumentCreate["classification"])}>
                {(["public", "internal", "confidential", "restricted"] as const).map((c) => (
                  <option key={c}>{c}</option>
                ))}
              </select>
            </label>
            <button type="submit" className="btn-primary">
              Save
            </button>
            <button type="button" onClick={() => void remove()} className="btn-danger ml-auto">
              Delete
            </button>
          </form>
        </Card>
      )}
    </div>
  );
}
