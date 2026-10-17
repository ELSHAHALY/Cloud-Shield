// Read-only access to the SOAR incidents table (TB5, plan D16 §7.1): one
// Query per status on the status-eventTime GSI, or GetItem. Never a Scan.
import { GetCommand, QueryCommand, type DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { decodeCursor, encodeCursor } from "../lib/cursor";

export const STATUSES = ["DETECTED", "CONTAINED", "WOULD_CONTAIN_DRY_RUN", "BLOCKED_BY_GUARD", "NO_PLAYBOOK_ANALYST_REVIEW", "FAILED"] as const;
export type IncidentStatus = (typeof STATUSES)[number];

export const INCIDENT_ID_RE = /^[\w.:-]{1,128}$/;
const EVENT_TIME_RE = /^[0-9T:.+Z-]{10,40}$/;
const STATUS_RE = /^(?:DETECTED|CONTAINED|WOULD_CONTAIN_DRY_RUN|BLOCKED_BY_GUARD|NO_PLAYBOOK_ANALYST_REVIEW|FAILED)$/;

export type Row = Record<string, unknown>;

export class IncidentRepository {
  constructor(
    private readonly ddb: DynamoDBDocumentClient,
    private readonly table: string,
    private readonly index: string,
  ) {}

  async get(incidentId: string): Promise<Row | undefined> {
    if (!INCIDENT_ID_RE.test(incidentId)) return undefined;
    const out = await this.ddb.send(new GetCommand({ TableName: this.table, Key: { incidentId }, ConsistentRead: true }));
    return out.Item;
  }

  async page(status: IncidentStatus, limit: number, cursor?: string) {
    const start = decodeCursor(cursor, { i: INCIDENT_ID_RE, s: STATUS_RE, e: EVENT_TIME_RE });
    if (start && start.s !== status) return { items: [] as Row[] };
    const out = await this.ddb.send(
      new QueryCommand({
        TableName: this.table,
        IndexName: this.index,
        KeyConditionExpression: "#status = :s",
        ExpressionAttributeNames: { "#status": "status" },
        ExpressionAttributeValues: { ":s": status },
        ScanIndexForward: false,
        Limit: limit,
        ...(start ? { ExclusiveStartKey: { incidentId: start.i, status: start.s, eventTime: start.e } } : {}),
      }),
    );
    const last = out.LastEvaluatedKey;
    const next =
      last && typeof last.incidentId === "string" && typeof last.eventTime === "string"
        ? encodeCursor({ i: last.incidentId, s: status, e: last.eventTime })
        : undefined;
    return { items: out.Items ?? [], ...(next ? { nextCursor: next } : {}) };
  }

  /** Every row of one status since an instant (key condition, bounded pages). */
  async since(status: IncidentStatus, sinceIso: string, maxPages = 5): Promise<{ items: Row[]; truncated: boolean }> {
    const items: Row[] = [];
    let start: Record<string, unknown> | undefined;
    for (let page = 0; page < maxPages; page++) {
      const out = await this.ddb.send(
        new QueryCommand({
          TableName: this.table,
          IndexName: this.index,
          KeyConditionExpression: "#status = :s AND eventTime >= :since",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: { ":s": status, ":since": sinceIso },
          ProjectionExpression: "incidentId, #status, eventTime, containedAt, findingType",
          ScanIndexForward: false,
          Limit: 1000,
          ...(start ? { ExclusiveStartKey: start } : {}),
        }),
      );
      items.push(...(out.Items ?? []));
      start = out.LastEvaluatedKey;
      if (!start) return { items, truncated: false };
    }
    return { items, truncated: true };
  }
}
