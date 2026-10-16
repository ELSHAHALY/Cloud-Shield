// Time helpers with the same semantics as soar/tools/generate_ir_report.py:
// only timezone-aware ISO-8601 strings parse; differences are rounded to ms.
// eslint-disable-next-line security/detect-unsafe-regex -- bounded and unambiguous: linear time
const ISO_TZ_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2})$/;

export function parseTime(value: unknown): number | null {
  if (typeof value !== "string" || !ISO_TZ_RE.test(value)) return null;
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : t;
}

export function secondsBetween(start: number | null, end: number | null): number | null {
  if (start === null || end === null) return null;
  return Math.round(end - start) / 1000;
}

export const MTTC_TARGET_SECONDS = 60;

/** MTTC exactly as build_report: containedAt − eventTime, CONTAINED rows only. */
export function mttcOf(row: Record<string, unknown>): number | null {
  if (row.status !== "CONTAINED") return null;
  return secondsBetween(parseTime(row.eventTime), parseTime(row.containedAt));
}
