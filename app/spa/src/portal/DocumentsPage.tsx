import { useCallback, useEffect, useRef, useState, type DragEvent, type FormEvent } from "react";
import { Link } from "react-router";
import type { DocumentCreate, DocumentMeta, DocumentPage } from "../api/types";
import { useSession } from "../auth/session";
import { Card, Chip, ErrorBox, Icon, Loading, PageHeader, type Tone } from "../components/ui";
import { ACCEPTED, downloadDocument, uploadDocument } from "./upload";

const CLASSES: DocumentCreate["classification"][] = ["public", "internal", "confidential", "restricted"];

// restricted rose, confidential amber, internal cyan, public slate. The text is always written.
const CLASS_TONE: Record<DocumentCreate["classification"], Tone> = { restricted: "bad", confidential: "warn", internal: "info", public: "neutral" };

export function ClassificationPill({ value }: { value: DocumentCreate["classification"] }) {
  return <Chip tone={CLASS_TONE[value]}>{value}</Chip>;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}

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
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

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

  function onDragOver(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    e.dataTransfer.dropEffect = "copy";
    setDragging(true);
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    const dropped = e.dataTransfer.files[0];
    if (!dropped) return;
    setFile(dropped);
    // Keep the required native input in sync so form validation still sees the file.
    if (inputRef.current) inputRef.current.files = e.dataTransfer.files;
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
      if (inputRef.current) inputRef.current.value = "";
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
    <div className="space-y-6">
      <PageHeader
        eyebrow="Tenant portal"
        title="Documents"
        subtitle={
          <span className="mt-1 flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/35 bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-200">
              <Icon name="lock" className="size-3.5" />
              SSE-KMS (data CMK) at rest on AWS
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-cyan-500/35 bg-cyan-500/10 px-2 py-0.5 text-xs font-medium text-cyan-200" title="PRESIGNED_URL_MAX_SECONDS, default 300 s; the bucket policy caps signature age independently.">
              <Icon name="clock" className="size-3.5" />
              pre-signed downloads ≤ 300 s (default cap)
            </span>
          </span>
        }
      />
      <ErrorBox error={error} />
      {notice && (
        <p role="status" className="flex items-start gap-2 rounded-xl border border-cyan-500/35 bg-cyan-500/[0.08] p-3 text-sm text-cyan-100">
          <Icon name="check" className="mt-0.5 size-4 shrink-0 text-cyan-300" />
          <span>{notice}</span>
        </p>
      )}
      {can("doc:write") && (
        <Card title="Upload" icon="upload" accent="cyan" subtitle="The browser hashes the file (SHA-256); the server re-hashes it and checks the type before storing it.">
          <form onSubmit={submit} className="grid gap-4 lg:grid-cols-2" aria-label="Upload a document">
            <div className="lg:row-span-2">
              <label htmlFor="document-file" className="label-caps">
                File
              </label>
              <div
                onDragOver={onDragOver}
                onDragEnter={onDragOver}
                onDragLeave={() => setDragging(false)}
                onDrop={onDrop}
                className={`mt-1.5 flex min-h-36 flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed p-5 text-center transition-colors duration-150 has-[input:focus-visible]:border-cyan-400 ${
                  dragging ? "border-cyan-400 bg-cyan-500/10 shadow-[0_0_24px_-8px_rgb(34_211_238/0.7)]" : file ? "border-emerald-500/50 bg-emerald-500/[0.06]" : "border-slate-700 bg-slate-950/40 hover:border-slate-600"
                }`}
              >
                <input
                  ref={inputRef}
                  id="document-file"
                  type="file"
                  accept={Object.keys(ACCEPTED).join(",")}
                  className="sr-only"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                  required
                />
                <span className={`grid size-10 place-items-center rounded-full border ${dragging ? "border-cyan-400/60 text-cyan-200" : "border-slate-700 text-cyan-300"}`}>
                  <Icon name={file ? "check" : "upload"} className="size-5" />
                </span>
                {file ? (
                  <p className="text-sm">
                    <span className="block max-w-full truncate font-medium text-slate-100">{file.name}</span>
                    <span className="block text-xs tabular-nums text-slate-400">{formatBytes(file.size)}</span>
                  </p>
                ) : (
                  <p className="text-sm text-slate-300">Drop a file here</p>
                )}
                {/* Mouse shortcut only: the (visually hidden) file input above is the one keyboard/AT control. */}
                <button type="button" tabIndex={-1} aria-hidden="true" className="btn-secondary" onClick={() => inputRef.current?.click()}>
                  {file ? "Choose another file" : "Browse files"}
                </button>
                <p className="text-xs text-slate-400">PDF, text, PNG, JPEG or DOCX</p>
              </div>
            </div>
            <label className="block text-sm text-slate-300">
              Title
              <input className="mt-1.5 w-full px-3 py-1.5" maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} />
            </label>
            <div className="grid gap-4 sm:grid-cols-2">
              <label className="block text-sm text-slate-300">
                Classification
                <select className="mt-1.5 w-full px-3 py-1.5" value={classification} onChange={(e) => setClassification(e.target.value as DocumentCreate["classification"])}>
                  {CLASSES.map((c) => (
                    <option key={c}>{c}</option>
                  ))}
                </select>
              </label>
              <label className="block text-sm text-slate-300">
                Tags (comma separated)
                <input className="mt-1.5 w-full px-3 py-1.5" value={tags} onChange={(e) => setTags(e.target.value)} />
              </label>
            </div>
            <div className="flex flex-wrap items-center gap-3 lg:col-start-2">
              <button type="submit" disabled={busy || !file} className="btn-primary px-4">
                <Icon name="upload" className="size-4" />
                {busy ? "Uploading…" : "Upload"}
              </button>
              <span className="flex items-center gap-1.5 text-xs text-slate-400">
                Stored as <ClassificationPill value={classification} />
              </span>
            </div>
          </form>
        </Card>
      )}
      <Card title="Your tenant's documents" icon="file-lock" subtitle={items ? `${items.length} loaded${next ? ", more available" : ""}` : undefined}>
        {!items ? (
          <Loading />
        ) : items.length === 0 ? (
          <p className="text-sm text-slate-400">No documents yet.</p>
        ) : (
          <div className="-mx-4 overflow-x-auto md:-mx-5">
            <table className="data-table">
              <thead>
                <tr>
                  <th className="px-4 py-2 md:pl-5">Title</th>
                  <th className="px-3 py-2">Classification</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Updated (UTC)</th>
                  <th className="px-4 py-2 text-right md:pr-5">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {items.map((d) => (
                  <tr key={d.docId}>
                    <td className="px-4 py-2.5 md:pl-5">
                      <span className="flex items-center gap-2">
                        <Icon name="documents" className="size-4 shrink-0 text-slate-500" />
                        <Link to={`/documents/${d.docId}`} className="link-inline font-medium">
                          {d.title}
                        </Link>
                      </span>
                    </td>
                    <td className="px-3 py-2.5">
                      <ClassificationPill value={d.classification} />
                    </td>
                    <td className="px-3 py-2.5">
                      {d.status === "PENDING_UPLOAD" ? (
                        <Chip tone="neutral" dot>
                          pending upload
                        </Chip>
                      ) : (
                        <Chip tone="good" dot>
                          available
                        </Chip>
                      )}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-xs whitespace-nowrap text-slate-400">{d.updatedAt}</td>
                    <td className="px-4 py-2.5 text-right md:pr-5">
                      {d.status === "AVAILABLE" && (
                        <button type="button" className="btn-ghost px-2 py-1 text-xs" onClick={() => void downloadDocument(api, d.docId).catch(setError)}>
                          <Icon name="download" className="size-3.5" />
                          Download
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {next && (
          <button type="button" className="btn-secondary mt-3" onClick={() => loadMore(next)}>
            Load more
          </button>
        )}
      </Card>
    </div>
  );
}
