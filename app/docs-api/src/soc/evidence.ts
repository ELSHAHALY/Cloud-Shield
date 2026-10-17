// Chain-of-custody verification (plan D17 §7.3): the same primitive as
// soar/tools/generate_ir_report.py::_check_evidence (version-pinned GetObject,
// SHA-256 hex compare, base64 cross-check), hardened: the record's bucket must
// be EVIDENCE_BUCKET and the key must sit under incidents/, else no GetObject
// is issued. Object Lock status is read and reported as found, never assumed.
import { createHash } from "node:crypto";
import type { Readable } from "node:stream";
import {
  GetObjectCommand,
  GetObjectLegalHoldCommand,
  GetObjectLockConfigurationCommand,
  GetObjectRetentionCommand,
  type S3Client,
} from "@aws-sdk/client-s3";
import type { EvidenceRecord } from "./projection";

export const MAX_RECORDS = 20;
export const MAX_OBJECT_BYTES = 5 * 1024 * 1024;

export interface EvidenceCheck {
  key: string;
  versionId: string | null;
  recordedSha256: string | null;
  actualSha256: string | null;
  ok: boolean;
  error: string | null;
  retention: { mode: string | null; retainUntil: string | null } | null;
  legalHold: boolean | null;
}

export interface BucketLock {
  enabled: boolean | null;
  mode: string | null;
  days: number | null;
}

function errorCode(err: unknown): string {
  const name = (err as { name?: unknown } | null)?.name;
  return typeof name === "string" && /^[A-Za-z0-9]{1,64}$/.test(name) ? name : "Error";
}

class TooLarge extends Error {}

async function readCapped(body: unknown, cap: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of body as Readable) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    total += buf.length;
    if (total > cap) {
      (body as Readable).destroy?.();
      throw new TooLarge();
    }
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

export function keyAllowed(key: string): boolean {
  return key.startsWith("incidents/") && key.length <= 1024 && !key.split("/").includes("..");
}

export async function checkRecord(s3: S3Client, evidenceBucket: string, record: EvidenceRecord): Promise<EvidenceCheck> {
  const base = { key: record.key, versionId: record.versionId, recordedSha256: record.sha256, retention: null, legalHold: null };
  if (record.bucket !== evidenceBucket) return { ...base, actualSha256: null, ok: false, error: "foreign-bucket" };
  if (!keyAllowed(record.key)) return { ...base, actualSha256: null, ok: false, error: "key-outside-incidents-prefix" };
  const target = { Bucket: evidenceBucket, Key: record.key, ...(record.versionId ? { VersionId: record.versionId } : {}) };

  let actual: string | null = null;
  let error: string | null = null;
  try {
    const out = await s3.send(new GetObjectCommand(target));
    if ((out.ContentLength ?? 0) > MAX_OBJECT_BYTES) {
      (out.Body as Readable | undefined)?.destroy?.();
      throw new TooLarge();
    }
    actual = createHash("sha256").update(await readCapped(out.Body, MAX_OBJECT_BYTES)).digest("hex");
  } catch (err) {
    error = err instanceof TooLarge ? "too-large" : errorCode(err);
  }
  let ok = false;
  if (actual !== null) {
    ok = actual === record.sha256;
    if (ok && record.sha256Base64) ok = Buffer.from(actual, "hex").toString("base64") === record.sha256Base64;
    if (!ok) error = "mismatch";
  }

  let retention: EvidenceCheck["retention"] = null;
  let legalHold: boolean | null = null;
  if (actual !== null) {
    try {
      const r = await s3.send(new GetObjectRetentionCommand(target));
      if (r.Retention) retention = { mode: r.Retention.Mode ?? null, retainUntil: r.Retention.RetainUntilDate?.toISOString() ?? null };
    } catch {
      retention = null; // not locked, Object Lock off, or not readable: never reported as locked
    }
    try {
      const h = await s3.send(new GetObjectLegalHoldCommand(target));
      legalHold = h.LegalHold?.Status === "ON" ? true : h.LegalHold?.Status === "OFF" ? false : null;
    } catch {
      legalHold = null;
    }
  }
  return { ...base, actualSha256: actual, ok, error, retention, legalHold };
}

export async function bucketLock(s3: S3Client, evidenceBucket: string): Promise<BucketLock> {
  try {
    const out = await s3.send(new GetObjectLockConfigurationCommand({ Bucket: evidenceBucket }));
    const cfg = out.ObjectLockConfiguration;
    const enabled = cfg?.ObjectLockEnabled === "Enabled";
    const def = cfg?.Rule?.DefaultRetention;
    return { enabled, mode: enabled ? (def?.Mode ?? null) : null, days: enabled ? (def?.Days ?? (def?.Years ? def.Years * 365 : null)) : null };
  } catch (err) {
    if (errorCode(err) === "ObjectLockConfigurationNotFoundError") return { enabled: false, mode: null, days: null };
    return { enabled: null, mode: null, days: null };
  }
}

/**
 * Same semantics as IrReport.chain_of_custody_ok, plus: a check that could not
 * verify everything (truncated at 20 objects, or an object over 5 MiB that
 * was not hashed) never claims "intact" and never claims "BROKEN" either
 * (audit E6): it is null, "not fully verified".
 */
export function chainOfCustody(checks: EvidenceCheck[], truncated: boolean): boolean | null {
  if (checks.length === 0) return null;
  if (checks.some((c) => !c.ok && c.error !== "too-large")) return false;
  return truncated || checks.some((c) => c.error === "too-large") ? null : true;
}

export async function verifyAll(s3: S3Client, evidenceBucket: string, records: EvidenceRecord[]) {
  const truncated = records.length > MAX_RECORDS;
  const checks: EvidenceCheck[] = [];
  for (const r of records.slice(0, MAX_RECORDS)) checks.push(await checkRecord(s3, evidenceBucket, r));
  return { checks, truncated, chainOfCustodyOk: chainOfCustody(checks, truncated) };
}
