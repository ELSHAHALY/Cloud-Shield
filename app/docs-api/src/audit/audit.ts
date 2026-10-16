// Insert-only audit trail (plan D4, §5.4): conditional writes
// (attribute_not_exists(eventKey)), no Update/Delete IAM, a stream and PITR.
// Never called "immutable": the guarantee is by convention, not WORM.
import { randomUUID } from "node:crypto";
import { PutCommand, QueryCommand, type DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import type { Request } from "express";
import { PLATFORM_PARTITION, type TenantId } from "../auth/principal";
import { clean } from "../lib/sanitize";
import { decodeCursor, encodeCursor } from "../lib/cursor";
import { AppError } from "../lib/errors";

export type AuditAction =
  | "DOCUMENT_CREATED"
  | "DOCUMENT_UPLOADED"
  | "DOCUMENT_UPDATED"
  | "DOCUMENT_DELETED"
  | "DOCUMENT_DOWNLOAD_URL_ISSUED"
  | "AGREEMENT_ACCEPTED"
  | "GRC_PROFILE_UPDATED"
  | "ACCESS_DENIED"
  | "DECOY_ROUTE_HIT"
  | "SOC_EVIDENCE_VERIFIED"
  | "SOC_REPORT_EXPORTED";

/** `details` keys allowed per action; anything else is dropped. */
const DETAIL_KEYS: Readonly<Record<AuditAction, readonly string[]>> = {
  DOCUMENT_CREATED: ["sizeBytes", "contentType", "classification", "sha256"],
  DOCUMENT_UPLOADED: ["sha256", "sizeBytes", "contentType"],
  DOCUMENT_UPDATED: ["fields", "version"],
  DOCUMENT_DELETED: ["previousStatus"],
  DOCUMENT_DOWNLOAD_URL_ISSUED: ["expiresInSeconds"],
  AGREEMENT_ACCEPTED: ["agreementId", "version", "textSha256"],
  GRC_PROFILE_UPDATED: ["version", "jurisdictions"],
  ACCESS_DENIED: ["code", "method", "route"],
  DECOY_ROUTE_HIT: ["method", "path", "query", "incidentId", "published", "publishSkipped", "tokenPresent", "authenticated"],
  SOC_EVIDENCE_VERIFIED: ["incidentId", "objects", "chainOfCustodyOk"],
  SOC_REPORT_EXPORTED: ["incidentId", "format", "chainOfCustodyOk"],
};

export type DetailValue = string | number | boolean | null;

export interface AuditActor {
  type: "user" | "anonymous";
  sub?: string;
  tenantId?: string;
  groups?: string[];
  tokenPresent?: boolean;
}

export interface AuditEvent {
  tenantId: string;
  eventKey: string;
  schemaVersion: "1";
  eventId: string;
  at: string;
  action: AuditAction;
  outcome: "SUCCESS" | "DENIED";
  actor: AuditActor;
  resource: { type: string; id?: string };
  sourceIp: string | null;
  sourceIpTrusted: boolean;
  userAgent: string | null;
  requestId: string;
  details: Record<string, DetailValue>;
}

export const EVENT_KEY_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z#[0-9a-f-]{36}$/;

export interface EventInput {
  partition: TenantId;
  action: AuditAction;
  outcome?: "SUCCESS" | "DENIED";
  resource: { type: string; id?: string };
  details?: Record<string, DetailValue>;
  actor?: AuditActor;
}

export function actorOf(req: Request): AuditActor {
  const p = req.principal;
  if (!p) return { type: "anonymous" };
  return { type: "user", sub: p.sub, tenantId: p.tenantId, groups: [...p.groups] };
}

function allowDetails(action: AuditAction, details: Record<string, DetailValue> = {}): Record<string, DetailValue> {
  const out: Record<string, DetailValue> = {};
  for (const key of DETAIL_KEYS[action]) {
    if (!Object.prototype.hasOwnProperty.call(details, key)) continue;
    const v = details[key];
    out[key] = typeof v === "string" ? v.slice(0, 512) : (v ?? null);
  }
  return out;
}

export class AuditLog {
  constructor(
    private readonly ddb: DynamoDBDocumentClient,
    private readonly table: string,
    private readonly now: () => Date = () => new Date(),
  ) {}

  build(req: Request, input: EventInput): AuditEvent {
    const at = this.now().toISOString();
    return {
      tenantId: input.partition,
      eventKey: `${at}#${req.requestId}`,
      schemaVersion: "1",
      eventId: randomUUID(),
      at,
      action: input.action,
      outcome: input.outcome ?? "SUCCESS",
      actor: input.actor ?? actorOf(req),
      resource: input.resource,
      sourceIp: req.source.ip,
      sourceIpTrusted: req.source.trusted,
      userAgent: clean(req.get("user-agent")),
      requestId: req.requestId,
      details: allowDetails(input.action, input.details),
    };
  }

  /** A transaction item: written atomically with the state change it records (F25). */
  transactPut(event: AuditEvent) {
    return {
      Put: {
        TableName: this.table,
        Item: event,
        ConditionExpression: "attribute_not_exists(eventKey)",
      },
    };
  }

  /** A standalone write. A ConditionalCheckFailed is surfaced, never swallowed. */
  async put(event: AuditEvent): Promise<void> {
    await this.ddb.send(
      new PutCommand({
        TableName: this.table,
        Item: event,
        ConditionExpression: "attribute_not_exists(eventKey)",
      }),
    );
  }

  /**
   * Newest first between two instants. The upper bound "<to>~" sorts after any
   * "<to>#<id>" key, and both bounds start with a digit, so AGREEMENT#… markers
   * are never returned.
   */
  async query(partition: TenantId, from: string, to: string, limit: number, cursor?: string) {
    const start = decodeCursor(cursor, { k: EVENT_KEY_RE });
    const out = await this.ddb.send(
      new QueryCommand({
        TableName: this.table,
        KeyConditionExpression: "tenantId = :t AND eventKey BETWEEN :from AND :to",
        ExpressionAttributeValues: { ":t": partition, ":from": from, ":to": `${to}~` },
        ScanIndexForward: false,
        Limit: limit,
        ...(start ? { ExclusiveStartKey: { tenantId: partition, eventKey: start.k } } : {}),
      }),
    );
    const items = (out.Items ?? []).map(toPublicEvent);
    const last = out.LastEvaluatedKey?.eventKey;
    return { items, ...(typeof last === "string" ? { nextCursor: encodeCursor({ k: last }) } : {}) };
  }

  /** Decoy correlation: `_platform` events in one hour naming this incident id. */
  async relatedToIncident(incidentId: string, hourStart: string, hourEnd: string) {
    const out = await this.ddb.send(
      new QueryCommand({
        TableName: this.table,
        KeyConditionExpression: "tenantId = :t AND eventKey BETWEEN :from AND :to",
        FilterExpression: "#d.#i = :id",
        ExpressionAttributeNames: { "#d": "details", "#i": "incidentId" },
        ExpressionAttributeValues: { ":t": PLATFORM_PARTITION, ":from": hourStart, ":to": `${hourEnd}~`, ":id": incidentId },
        ScanIndexForward: false,
        Limit: 100,
      }),
    );
    return (out.Items ?? []).slice(0, 20).map(toPublicEvent);
  }
}

/** Only the schema fields, whatever else a row might hold. */
export function toPublicEvent(item: Record<string, unknown>) {
  const actor = (item.actor ?? {}) as Record<string, unknown>;
  const resource = (item.resource ?? {}) as Record<string, unknown>;
  const details = (item.details ?? {}) as Record<string, unknown>;
  const action = item.action as AuditAction;
  return {
    eventKey: String(item.eventKey),
    schemaVersion: "1" as const,
    eventId: String(item.eventId),
    at: String(item.at),
    action,
    outcome: item.outcome === "DENIED" ? ("DENIED" as const) : ("SUCCESS" as const),
    actor: {
      type: actor.type === "user" ? ("user" as const) : ("anonymous" as const),
      ...(typeof actor.sub === "string" ? { sub: actor.sub } : {}),
      ...(typeof actor.tenantId === "string" ? { tenantId: actor.tenantId } : {}),
      ...(Array.isArray(actor.groups) ? { groups: actor.groups.filter((g): g is string => typeof g === "string").slice(0, 4) } : {}),
      ...(typeof actor.tokenPresent === "boolean" ? { tokenPresent: actor.tokenPresent } : {}),
    },
    resource: {
      type: String(resource.type ?? "unknown"),
      ...(typeof resource.id === "string" ? { id: resource.id } : {}),
    },
    sourceIp: typeof item.sourceIp === "string" ? item.sourceIp : null,
    sourceIpTrusted: item.sourceIpTrusted === true,
    userAgent: typeof item.userAgent === "string" ? item.userAgent : null,
    requestId: String(item.requestId),
    details: DETAIL_KEYS[action] ? allowDetails(action, details as Record<string, DetailValue>) : {},
  };
}

/** Parse ISO bounds (default: last 30 days). */
export function auditWindow(fromRaw: unknown, toRaw: unknown, now: Date): { from: string; to: string } {
  const parse = (v: unknown, name: string): Date | undefined => {
    if (v === undefined) return undefined;
    const d = typeof v === "string" && v.length <= 40 ? new Date(v) : new Date(NaN);
    if (Number.isNaN(d.getTime())) {
      throw new AppError("VALIDATION_FAILED", "invalid time bound", [{ path: `/query/${name}`, message: "must be date-time" }]);
    }
    return d;
  };
  const to = parse(toRaw, "to") ?? now;
  const from = parse(fromRaw, "from") ?? new Date(to.getTime() - 30 * 86_400_000);
  if (from > to) throw new AppError("VALIDATION_FAILED", "from is after to", [{ path: "/query/from", message: "must be <= to" }]);
  return { from: from.toISOString(), to: to.toISOString() };
}
