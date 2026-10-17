// Click-through acceptance logging (plan D25, §8.4). What is recorded is
// evidence of acceptance by an MFA-authenticated Cognito identity; it is not
// a qualified or advanced electronic signature.
import { GetCommand, TransactWriteCommand, type DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import type { Request } from "express";
import type { Principal, TenantId } from "../auth/principal";
import type { AuditLog } from "../audit/audit";
import { AppError } from "../lib/errors";
import { clean } from "../lib/sanitize";
import { rethrowUnlessConditionFailure } from "../lib/ddb-errors";
import { publicAgreement, type AgreementEntry, type Catalogue } from "./catalogue";

export interface Acceptance {
  agreementId: string;
  version: string;
  textSha256: string;
  textMediaType: "text/plain; charset=utf-8";
  acceptedBy: { sub: string; groups: string[] };
  tenantId: string;
  acceptedAt: string;
  sourceIp: string | null;
  sourceIpTrusted: boolean;
  userAgent: string | null;
  requestId: string;
  method: "click-through";
  authorityConfirmed: true;
  schemaVersion: "1";
}

const markerKey = (e: { agreementId: string; version: string }) => `AGREEMENT#${e.agreementId}#${e.version}`;

function toAcceptance(item: Record<string, unknown>): Acceptance {
  const by = (item.acceptedBy ?? {}) as { sub?: unknown; groups?: unknown };
  return {
    agreementId: String(item.agreementId),
    version: String(item.version),
    textSha256: String(item.textSha256),
    textMediaType: "text/plain; charset=utf-8",
    acceptedBy: { sub: String(by.sub), groups: Array.isArray(by.groups) ? by.groups.map(String).slice(0, 4) : [] },
    tenantId: String(item.tenantId),
    acceptedAt: String(item.acceptedAt),
    sourceIp: typeof item.sourceIp === "string" ? item.sourceIp : null,
    sourceIpTrusted: item.sourceIpTrusted === true,
    userAgent: typeof item.userAgent === "string" ? item.userAgent : null,
    requestId: String(item.requestId),
    method: "click-through",
    authorityConfirmed: true,
    schemaVersion: "1",
  };
}

export class AgreementService {
  private readonly cache = new Map<string, { at: number; complete: boolean }>();

  constructor(
    private readonly ddb: DynamoDBDocumentClient,
    private readonly auditTable: string,
    private readonly audit: AuditLog,
    private readonly catalogue: Catalogue | undefined,
    private readonly now: () => Date = () => new Date(),
    private readonly ttlMs = 60_000,
  ) {}

  private requireCatalogue(): Catalogue {
    if (!this.catalogue) throw new AppError("SERVICE_UNAVAILABLE", "agreement catalogue unavailable");
    return this.catalogue;
  }

  list() {
    return this.requireCatalogue().current().map(publicAgreement);
  }

  text(agreementId: string, version: string): string {
    const entry = this.requireCatalogue().find(agreementId, version);
    if (!entry) throw new AppError("NOT_FOUND");
    return entry.text;
  }

  /** One GetItem per agreement (the task role has GetItem, not BatchGetItem, on the audit table). */
  private async markers(tenantId: TenantId, entries: AgreementEntry[]): Promise<Map<string, Acceptance>> {
    const found = new Map<string, Acceptance>();
    const items = await Promise.all(
      entries.map((e) =>
        this.ddb.send(new GetCommand({ TableName: this.auditTable, Key: { tenantId, eventKey: markerKey(e) }, ConsistentRead: true })),
      ),
    );
    for (const out of items) {
      if (out.Item) found.set(String(out.Item.eventKey), toAcceptance(out.Item));
    }
    return found;
  }

  async status(p: Principal) {
    const catalogue = this.requireCatalogue();
    const current = catalogue.current();
    const markers = await this.markers(p.tenantId, current);
    const accepted = current.filter((e) => markers.has(markerKey(e))).map((e) => markers.get(markerKey(e))!);
    const pending = current.filter((e) => !markers.has(markerKey(e)));
    const complete = pending.every((e) => !e.required);
    this.cache.set(p.tenantId, { at: Date.now(), complete });
    return { complete, accepted, pending: pending.map(publicAgreement) };
  }

  /** Agreement gate for document writes: fail closed (503) if the catalogue is unavailable. */
  async assertComplete(p: Principal): Promise<void> {
    const cached = this.cache.get(p.tenantId);
    const complete = cached && Date.now() - cached.at < this.ttlMs ? cached.complete : (await this.status(p)).complete;
    if (!complete) throw new AppError("AGREEMENT_REQUIRED", "the tenant administrator must accept the required agreements");
  }

  async accept(req: Request, p: Principal, agreementId: string, body: { version: string; sha256: string; authorityConfirmed: boolean }) {
    const catalogue = this.requireCatalogue();
    const entry = catalogue.find(agreementId, body.version);
    if (!entry) throw new AppError("NOT_FOUND");
    if (!entry.current) throw new AppError("CONFLICT", "not the current version");
    if (body.authorityConfirmed !== true) throw new AppError("VALIDATION_FAILED", "authority not confirmed");
    if (body.sha256 !== entry.sha256) throw new AppError("CONFLICT", "agreement text changed: reload and review it");

    const existing = (await this.markers(p.tenantId, [entry])).get(markerKey(entry));
    if (existing) return { created: false, acceptance: existing };

    const acceptance: Acceptance = {
      agreementId: entry.agreementId,
      version: entry.version,
      textSha256: entry.sha256,
      textMediaType: "text/plain; charset=utf-8",
      acceptedBy: { sub: p.sub, groups: [...p.groups] },
      tenantId: p.tenantId,
      acceptedAt: this.now().toISOString(),
      sourceIp: req.source.ip,
      sourceIpTrusted: req.source.trusted,
      userAgent: clean(req.get("user-agent")),
      requestId: req.requestId,
      method: "click-through",
      authorityConfirmed: true,
      schemaVersion: "1",
    };
    const event = this.audit.build(req, {
      partition: p.tenantId,
      action: "AGREEMENT_ACCEPTED",
      resource: { type: "agreement", id: `${entry.agreementId}/${entry.version}` },
      details: { agreementId: entry.agreementId, version: entry.version, textSha256: entry.sha256 },
    });
    try {
      await this.ddb.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Put: {
                TableName: this.auditTable,
                Item: { eventKey: markerKey(entry), ...acceptance },
                ConditionExpression: "attribute_not_exists(eventKey)",
              },
            },
            this.audit.transactPut(event),
          ],
        }),
      );
    } catch (err) {
      rethrowUnlessConditionFailure(err);
      // A concurrent acceptance won: first acceptance wins, return it.
      const winner = (await this.markers(p.tenantId, [entry])).get(markerKey(entry));
      if (!winner) throw err;
      return { created: false, acceptance: winner };
    }
    this.cache.delete(p.tenantId);
    return { created: true, acceptance };
  }
}
