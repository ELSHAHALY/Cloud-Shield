// Small, dependency-free text hygiene used for audit fields and headers.

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;

/** Strip control characters and cap length (audit user agent, decoy path). */
export function clean(value: unknown, max = 256): string | null {
  if (typeof value !== "string" || value.length === 0) return null;
  return value.replace(CONTROL, "").slice(0, max);
}

/**
 * RFC 6266 / RFC 5987 Content-Disposition for a download. The ASCII fallback
 * keeps only [A-Za-z0-9._ -]; the UTF-8 form is percent-encoded, so neither
 * can carry a quote, CR/LF or ';' into the header.
 */
export function attachmentDisposition(name: string): string {
  const base = (clean(name, 120) ?? "download").trim() || "download";
  const ascii = base.replace(/[^A-Za-z0-9._ -]/g, "_").replace(/^[.\s]+/, "") || "download";
  const encoded = encodeURIComponent(base).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encoded}`;
}

/** File extension for a declared content type (never from the client). */
export const EXTENSION: Readonly<Record<string, string>> = {
  "application/pdf": ".pdf",
  "text/plain": ".txt",
  "image/png": ".png",
  "image/jpeg": ".jpg",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
};
