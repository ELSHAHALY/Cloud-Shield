import type { ApiClient } from "../api/client";
import type { DocumentCreate, DocumentMeta } from "../api/types";

export const ACCEPTED: Record<string, DocumentCreate["contentType"]> = {
  "application/pdf": "application/pdf",
  "text/plain": "text/plain",
  "image/png": "image/png",
  "image/jpeg": "image/jpeg",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
};

export async function sha256Hex(data: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export interface UploadInput {
  file: File;
  title: string;
  classification: DocumentCreate["classification"];
  description?: string;
  tags?: string[];
}

/** Two steps (plan D9): metadata with the declared SHA-256, then the raw bytes through the API. */
export async function uploadDocument(api: ApiClient, input: UploadInput): Promise<DocumentMeta> {
  const contentType = ACCEPTED[input.file.type];
  if (!contentType) throw new Error("UNSUPPORTED_TYPE");
  const bytes = await input.file.arrayBuffer();
  const body: DocumentCreate = {
    title: input.title,
    contentType,
    sizeBytes: bytes.byteLength,
    sha256: await sha256Hex(bytes),
    classification: input.classification,
    ...(input.description ? { description: input.description } : {}),
    ...(input.tags && input.tags.length ? { tags: input.tags } : {}),
  };
  const created = await api.post<DocumentMeta>("/documents", body);
  return api.request<DocumentMeta>("PUT", `/documents/${created.docId}/content`, { raw: new Uint8Array(bytes), contentType });
}

/** Download = navigation to a short-lived pre-signed URL (no fetch: CSP connect-src and S3 CORS stay closed). */
export async function downloadDocument(api: ApiClient, docId: string, navigate: (url: string) => void = (u) => window.location.assign(u)) {
  const { url } = await api.get<{ url: string }>(`/documents/${docId}/download`);
  navigate(url);
}
