// Magic-byte sniffing for the five accepted types (plan §5.3). The declared
// type must match the bytes; the client's file name never matters.
export const CONTENT_TYPES = [
  "application/pdf",
  "text/plain",
  "image/png",
  "image/jpeg",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
] as const;
export type ContentType = (typeof CONTENT_TYPES)[number];

const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const JPEG = Buffer.from([0xff, 0xd8, 0xff]);
const ZIP = Buffer.from([0x50, 0x4b, 0x03, 0x04]);
const PDF = Buffer.from("%PDF-", "ascii");

function startsWith(body: Buffer, prefix: Buffer): boolean {
  return body.length >= prefix.length && body.subarray(0, prefix.length).equals(prefix);
}

function isUtf8Text(body: Buffer): boolean {
  if (body.includes(0)) return false;
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(body);
    return true;
  } catch {
    return false;
  }
}

export function matchesType(contentType: ContentType, body: Buffer): boolean {
  switch (contentType) {
    case "application/pdf":
      return startsWith(body, PDF);
    case "image/png":
      return startsWith(body, PNG);
    case "image/jpeg":
      return startsWith(body, JPEG);
    case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
      return startsWith(body, ZIP);
    case "text/plain":
      return isUtf8Text(body);
  }
}

/** The bare media type of a Content-Type header ("text/plain; charset=utf-8" -> "text/plain"). */
export function mediaType(header: unknown): string {
  return typeof header === "string" ? (header.split(";")[0] ?? "").trim().toLowerCase() : "";
}
