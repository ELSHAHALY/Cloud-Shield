// Opaque pagination cursors (plan §3.1): base64url JSON holding ONLY the sort
// key value(s), each re-validated by regex. The partition key is always
// rebuilt from the token, never taken from the cursor.
import { AppError } from "./errors";

export function encodeCursor(value: Record<string, string>): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

export function decodeCursor(raw: unknown, fields: Readonly<Record<string, RegExp>>): Record<string, string> | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== "string" || raw.length > 512 || !/^[A-Za-z0-9_-]+$/.test(raw)) {
    throw new AppError("VALIDATION_FAILED", "invalid cursor", [{ path: "/query/cursor", message: "invalid cursor" }]);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
  } catch {
    parsed = undefined;
  }
  const out: Record<string, string> = {};
  const ok =
    parsed !== null &&
    typeof parsed === "object" &&
    !Array.isArray(parsed) &&
    Object.keys(parsed).length === Object.keys(fields).length &&
    Object.entries(fields).every(([name, re]) => {
      const v = (parsed as Record<string, unknown>)[name];
      if (typeof v !== "string" || !re.test(v)) return false;
      out[name] = v;
      return true;
    });
  if (!ok) throw new AppError("VALIDATION_FAILED", "invalid cursor", [{ path: "/query/cursor", message: "invalid cursor" }]);
  return out;
}

export function parseLimit(raw: unknown, fallback = 25, max = 100): number {
  if (raw === undefined) return fallback;
  const n = typeof raw === "number" ? raw : typeof raw === "string" && /^\d{1,3}$/.test(raw) ? Number(raw) : NaN;
  if (!Number.isInteger(n) || n < 1 || n > max) {
    throw new AppError("VALIDATION_FAILED", "invalid limit", [{ path: "/query/limit", message: `must be 1..${max}` }]);
  }
  return n;
}
