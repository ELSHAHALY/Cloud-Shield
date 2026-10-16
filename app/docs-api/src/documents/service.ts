// Tenant documents (plan §5). Every function takes the verified Principal;
// the partition key is always principal.tenantId, so another tenant's id is a
// plain miss (404). Expressions are static; user text only ever travels in
// ExpressionAttributeValues.
import { createHash } from "node:crypto";
import { GetCommand, QueryCommand, TransactWriteCommand, type DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { DeleteObjectCommand, GetObjectCommand, PutObjectCommand, type S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import type { Request } from "express";
import type { Logger } from "pino";
import { canWriteAny, type Principal } from "../auth/principal";
import type { AuditLog } from "../audit/audit";
import { decodeCursor, encodeCursor } from "../lib/cursor";
import { AppError } from "../lib/errors";
import { attachmentDisposition, EXTENSION } from "../lib/sanitize";
import { UUIDV7_RE, uuidv7 } from "../lib/uuidv7";
import { matchesType, mediaType, type ContentType } from "./magic";

export type Classification = "public" | "internal" | "confidential" | "restricted";
export type DocStatus = "PENDING_UPLOAD" | "AVAILABLE" | "DELETED";

export interface DocumentItem {
  tenantId: string;
  docId: string; // "doc#<uuidv7>"
  title?: string;
  description?: string;
  contentType: ContentType;
  sizeBytes: number;
  sha256: string;
  classification: Classification;
  tags?: string[];
  ownerSub: string;
  status: DocStatus;
  createdAt: string;
  updatedAt: string;
  version: number;
  s3Key: string;
  s3VersionId?: string;
  deletedAt?: string;
}

export interface DocumentCreate {
  title: string;
  description?: string;
  contentType: ContentType;
  sizeBytes: number;
  sha256: string;
  classification: Classification;
  tags?: string[];
}

export type DocumentPatch = Partial<Pick<DocumentCreate, "title" | "description" | "classification" | "tags">>;

const DOC_PREFIX = "doc#";
const SORT_KEY_RE = /^doc#[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PATCH_FIELDS = ["title", "description", "classification", "tags"] as const;

export interface DocumentsDeps {
  ddb: DynamoDBDocumentClient;
  s3: S3Client;
  s3Presign: S3Client;
  audit: AuditLog;
  logger: Logger;
  table: string;
  bucket: string;
  kmsKeyArn: string;
  presignMaxSeconds: number;
  maxUploadBytes: number;
  now?: () => Date;
}

export function toMeta(item: DocumentItem) {
  return {
    docId: item.docId.slice(DOC_PREFIX.length),
    title: item.title ?? "",
    ...(item.description !== undefined ? { description: item.description } : {}),
    contentType: item.contentType,
    sizeBytes: item.sizeBytes,
    sha256: item.sha256,
    classification: item.classification,
    tags: item.tags ?? [],
    ownerSub: item.ownerSub,
    status: item.status as "PENDING_UPLOAD" | "AVAILABLE",
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
    version: item.version,
  };
}

function isConditionalFailure(err: unknown): boolean {
  const name = (err as { name?: string } | null)?.name;
  return name === "ConditionalCheckFailedException" || name === "TransactionCanceledException";
}

export class DocumentService {
  private readonly now: () => Date;
  constructor(private readonly d: DocumentsDeps) {
    this.now = d.now ?? (() => new Date());
  }

  private key(p: Principal, docId: string) {
    if (!UUIDV7_RE.test(docId)) throw new AppError("NOT_FOUND");
    return { tenantId: p.tenantId as string, docId: DOC_PREFIX + docId };
  }

  /** The live item, or 404 (missing, another tenant's, or tombstoned). */
  async load(p: Principal, docId: string, allowDeleted = false): Promise<DocumentItem> {
    const out = await this.d.ddb.send(new GetCommand({ TableName: this.d.table, Key: this.key(p, docId), ConsistentRead: true }));
    const item = out.Item as DocumentItem | undefined;
    if (!item || (item.status === "DELETED" && !allowDeleted)) throw new AppError("NOT_FOUND");
    return item;
  }

  /** ABAC: a member may write only their own documents. The tenant already matches, so 403 reveals nothing. */
  private assertWriter(p: Principal, item: DocumentItem): void {
    if (!canWriteAny(p) && item.ownerSub !== p.sub) throw new AppError("FORBIDDEN", "not the document owner");
  }

  async list(p: Principal, limit: number, cursor?: string) {
    const start = decodeCursor(cursor, { k: SORT_KEY_RE });
    const out = await this.d.ddb.send(
      new QueryCommand({
        TableName: this.d.table,
        KeyConditionExpression: "tenantId = :t AND begins_with(docId, :prefix)",
        FilterExpression: "#status <> :deleted",
        ExpressionAttributeNames: { "#status": "status" },
        ExpressionAttributeValues: { ":t": p.tenantId, ":prefix": DOC_PREFIX, ":deleted": "DELETED" },
        ScanIndexForward: false,
        Limit: limit,
        ...(start ? { ExclusiveStartKey: { tenantId: p.tenantId, docId: start.k } } : {}),
      }),
    );
    const last = out.LastEvaluatedKey?.docId;
    return {
      items: (out.Items as DocumentItem[] | undefined ?? []).map(toMeta),
      ...(typeof last === "string" ? { nextCursor: encodeCursor({ k: last }) } : {}),
    };
  }

  async get(p: Principal, docId: string) {
    return toMeta(await this.load(p, docId));
  }

  async create(req: Request, p: Principal, input: DocumentCreate) {
    if (input.sizeBytes > this.d.maxUploadBytes) throw new AppError("PAYLOAD_TOO_LARGE", "sizeBytes exceeds the upload limit");
    const id = uuidv7(this.now().getTime());
    const at = this.now().toISOString();
    const item: DocumentItem = {
      tenantId: p.tenantId,
      docId: DOC_PREFIX + id,
      title: input.title,
      ...(input.description !== undefined ? { description: input.description } : {}),
      contentType: input.contentType,
      sizeBytes: input.sizeBytes,
      sha256: input.sha256,
      classification: input.classification,
      tags: input.tags ?? [],
      ownerSub: p.sub,
      status: "PENDING_UPLOAD",
      createdAt: at,
      updatedAt: at,
      version: 1,
      s3Key: `tenants/${p.tenantId}/docs/${id}`,
    };
    const event = this.d.audit.build(req, {
      partition: p.tenantId,
      action: "DOCUMENT_CREATED",
      resource: { type: "document", id },
      details: { sizeBytes: input.sizeBytes, contentType: input.contentType, classification: input.classification, sha256: input.sha256 },
    });
    try {
      await this.d.ddb.send(
        new TransactWriteCommand({
          TransactItems: [
            { Put: { TableName: this.d.table, Item: item, ConditionExpression: "attribute_not_exists(docId)" } },
            this.d.audit.transactPut(event),
          ],
        }),
      );
    } catch (err) {
      if (isConditionalFailure(err)) throw new AppError("CONFLICT", "document already exists");
      throw err;
    }
    return toMeta(item);
  }

  async upload(req: Request, p: Principal, docId: string, body: unknown, contentTypeHeader: unknown) {
    const item = await this.load(p, docId);
    this.assertWriter(p, item);
    if (item.status !== "PENDING_UPLOAD") throw new AppError("CONFLICT", "content already uploaded");
    if (mediaType(contentTypeHeader) !== item.contentType) throw new AppError("UNSUPPORTED_MEDIA_TYPE", "Content-Type differs from the declared type");
    if (!Buffer.isBuffer(body) || body.length === 0) throw new AppError("VALIDATION_FAILED", "empty body");
    if (body.length > this.d.maxUploadBytes) throw new AppError("PAYLOAD_TOO_LARGE");
    if (!matchesType(item.contentType, body)) throw new AppError("UNSUPPORTED_MEDIA_TYPE", "content does not match the declared type");
    const digest = createHash("sha256").update(body).digest();
    if (digest.toString("hex") !== item.sha256 || body.length !== item.sizeBytes) {
      throw new AppError("INTEGRITY_MISMATCH", "uploaded bytes do not match the declared sha256/sizeBytes");
    }

    const put = await this.d.s3.send(
      new PutObjectCommand({
        Bucket: this.d.bucket,
        Key: item.s3Key,
        Body: body,
        ContentType: item.contentType,
        ContentLength: body.length,
        ServerSideEncryption: "aws:kms",
        SSEKMSKeyId: this.d.kmsKeyArn,
        ChecksumAlgorithm: "SHA256",
        ChecksumSHA256: digest.toString("base64"),
      }),
    );
    const at = this.now().toISOString();
    const event = this.d.audit.build(req, {
      partition: p.tenantId,
      action: "DOCUMENT_UPLOADED",
      resource: { type: "document", id: docId },
      details: { sha256: item.sha256, sizeBytes: body.length, contentType: item.contentType },
    });
    const ownerCondition = canWriteAny(p) ? "" : " AND ownerSub = :sub";
    try {
      await this.d.ddb.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Update: {
                TableName: this.d.table,
                Key: this.key(p, docId),
                UpdateExpression: "SET #status = :available, s3VersionId = :vid, updatedAt = :at, version = version + :one",
                ConditionExpression: `#status = :pending${ownerCondition}`,
                ExpressionAttributeNames: { "#status": "status" },
                ExpressionAttributeValues: {
                  ":available": "AVAILABLE",
                  ":pending": "PENDING_UPLOAD",
                  ":vid": put.VersionId ?? "null",
                  ":at": at,
                  ":one": 1,
                  ...(ownerCondition ? { ":sub": p.sub } : {}),
                },
              },
            },
            this.d.audit.transactPut(event),
          ],
        }),
      );
    } catch (err) {
      // Best effort: do not leave an orphan object version behind.
      await this.d.s3
        .send(new DeleteObjectCommand({ Bucket: this.d.bucket, Key: item.s3Key, ...(put.VersionId ? { VersionId: put.VersionId } : {}) }))
        .catch((cleanupErr: unknown) => this.d.logger.error({ err: cleanupErr, requestId: req.requestId }, "orphan upload cleanup failed"));
      if (isConditionalFailure(err)) throw new AppError("CONFLICT", "document changed during upload");
      throw err;
    }
    return toMeta({ ...item, status: "AVAILABLE", updatedAt: at, version: item.version + 1, ...(put.VersionId ? { s3VersionId: put.VersionId } : {}) });
  }

  async patch(req: Request, p: Principal, docId: string, patch: DocumentPatch, ifMatch: unknown) {
    const item = await this.load(p, docId);
    this.assertWriter(p, item);
    if (item.status !== "AVAILABLE") throw new AppError("CONFLICT", "document content not uploaded yet");
    let expected = item.version;
    if (ifMatch !== undefined) {
      const m = typeof ifMatch === "string" ? /^"(\d{1,9})"$/.exec(ifMatch) : null;
      if (!m || Number(m[1]) !== item.version) throw new AppError("PRECONDITION_FAILED");
      expected = Number(m[1]);
    }
    const fields = PATCH_FIELDS.filter((f) => patch[f] !== undefined);
    if (fields.length === 0) throw new AppError("VALIDATION_FAILED", "empty patch");
    const names: Record<string, string> = { "#status": "status" };
    const values: Record<string, unknown> = { ":available": "AVAILABLE", ":expected": expected, ":one": 1, ":at": this.now().toISOString() };
    const sets = ["updatedAt = :at", "version = version + :one"];
    for (const f of fields) {
      names[`#${f}`] = f;
      values[`:${f}`] = patch[f];
      sets.push(`#${f} = :${f}`);
    }
    const ownerCondition = canWriteAny(p) ? "" : " AND ownerSub = :sub";
    if (ownerCondition) values[":sub"] = p.sub;
    const event = this.d.audit.build(req, {
      partition: p.tenantId,
      action: "DOCUMENT_UPDATED",
      resource: { type: "document", id: docId },
      details: { fields: fields.join(","), version: item.version + 1 },
    });
    try {
      await this.d.ddb.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Update: {
                TableName: this.d.table,
                Key: this.key(p, docId),
                UpdateExpression: `SET ${sets.join(", ")}`,
                ConditionExpression: `#status = :available AND version = :expected${ownerCondition}`,
                ExpressionAttributeNames: names,
                ExpressionAttributeValues: values,
              },
            },
            this.d.audit.transactPut(event),
          ],
        }),
      );
    } catch (err) {
      if (isConditionalFailure(err)) throw new AppError(ifMatch !== undefined ? "PRECONDITION_FAILED" : "CONFLICT");
      throw err;
    }
    const next: DocumentItem = { ...item, version: item.version + 1, updatedAt: values[":at"] as string };
    for (const f of fields) (next as unknown as Record<string, unknown>)[f] = patch[f];
    return toMeta(next);
  }

  async downloadUrl(req: Request, p: Principal, docId: string) {
    const item = await this.load(p, docId);
    if (item.status !== "AVAILABLE") throw new AppError("CONFLICT", "document content not uploaded yet");
    const expiresIn = this.d.presignMaxSeconds;
    const event = this.d.audit.build(req, {
      partition: p.tenantId,
      action: "DOCUMENT_DOWNLOAD_URL_ISSUED",
      resource: { type: "document", id: docId },
      details: { expiresInSeconds: expiresIn },
    });
    await this.d.audit.put(event);
    const filename = `${item.title ?? "document"}${EXTENSION[item.contentType] ?? ""}`;
    const url = await getSignedUrl(
      this.d.s3Presign,
      new GetObjectCommand({
        Bucket: this.d.bucket,
        Key: item.s3Key,
        ...(item.s3VersionId && item.s3VersionId !== "null" ? { VersionId: item.s3VersionId } : {}),
        ResponseContentDisposition: attachmentDisposition(filename),
        ResponseContentType: item.contentType,
      }),
      { expiresIn },
    );
    return { url, expiresAt: new Date(this.now().getTime() + expiresIn * 1000).toISOString() };
  }

  /**
   * Tombstone + audit in one transaction, then an S3 delete marker. Non-current
   * versions expire after 30 days (bucket lifecycle), which completes erasure.
   * DELETE is idempotent: repeating it on a tombstone re-places the marker.
   */
  async delete(req: Request, p: Principal, docId: string): Promise<void> {
    const item = await this.load(p, docId, true);
    this.assertWriter(p, item);
    if (item.status !== "DELETED") {
      const ownerCondition = canWriteAny(p) ? "" : " AND ownerSub = :sub";
      const event = this.d.audit.build(req, {
        partition: p.tenantId,
        action: "DOCUMENT_DELETED",
        resource: { type: "document", id: docId },
        details: { previousStatus: item.status },
      });
      try {
        await this.d.ddb.send(
          new TransactWriteCommand({
            TransactItems: [
              {
                Update: {
                  TableName: this.d.table,
                  Key: this.key(p, docId),
                  UpdateExpression: "SET #status = :deleted, deletedAt = :at, updatedAt = :at REMOVE title, description, tags",
                  ConditionExpression: `#status <> :deleted${ownerCondition}`,
                  ExpressionAttributeNames: { "#status": "status" },
                  ExpressionAttributeValues: { ":deleted": "DELETED", ":at": this.now().toISOString(), ...(ownerCondition ? { ":sub": p.sub } : {}) },
                },
              },
              this.d.audit.transactPut(event),
            ],
          }),
        );
      } catch (err) {
        if (isConditionalFailure(err)) throw new AppError("NOT_FOUND");
        throw err;
      }
    }
    if (item.s3VersionId) {
      await this.d.s3.send(new DeleteObjectCommand({ Bucket: this.d.bucket, Key: item.s3Key }));
    }
  }
}
