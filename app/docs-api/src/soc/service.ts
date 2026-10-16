// SOC read model orchestration (plan D16–D19). SOC data only, never tenant
// data, is cached in memory (10 s) and shared across analysts.
import { GetParameterCommand, type SSMClient } from "@aws-sdk/client-ssm";
import type { ECRClient } from "@aws-sdk/client-ecr";
import type { S3Client } from "@aws-sdk/client-s3";
import type { Request } from "express";
import { PLATFORM_PARTITION } from "../auth/principal";
import type { AuditLog } from "../audit/audit";
import { DECOY_FINDING_TYPE } from "../decoy/router";
import { AppError } from "../lib/errors";
import { ecrScan, IMAGE_POLICY, parseImage, type BuildInfo } from "../posture/posture";
import { bucketLock, verifyAll } from "./evidence";
import { metrics, type Window } from "./metrics";
import { detail, evidenceRecords, summary } from "./projection";
import { buildReport, toMarkdown } from "./report";
import { STATUSES, type IncidentRepository, type IncidentStatus } from "./repository";
import { MTTC_TARGET_SECONDS } from "./time";

export class TtlCache<T> {
  private value?: { at: number; v: T };
  constructor(
    private readonly ttlMs: number,
    private readonly now: () => number = Date.now,
  ) {}
  async get(load: () => Promise<T>): Promise<T> {
    const t = this.now();
    if (this.value && t - this.value.at < this.ttlMs) return this.value.v;
    const v = await load();
    this.value = { at: t, v };
    return v;
  }
}

/** The SSM dry-run switch: true / false, or null when unreadable (never guessed). */
export class DryRunSwitch {
  private readonly cache = new TtlCache<boolean | null>(15_000);
  constructor(
    private readonly ssm: SSMClient,
    private readonly name: string | undefined,
  ) {}
  read(): Promise<boolean | null> {
    return this.cache.get(async () => {
      if (!this.name) return null;
      try {
        const out = await this.ssm.send(new GetParameterCommand({ Name: this.name }));
        const v = out.Parameter?.Value;
        return v === "true" ? true : v === "false" ? false : null;
      } catch {
        return null;
      }
    });
  }
}

export interface SocDeps {
  repo: IncidentRepository | undefined;
  s3: S3Client;
  ecr: ECRClient;
  audit: AuditLog;
  evidenceBucket: string;
  playbooksEnabled: boolean;
  dryRun: DryRunSwitch;
  buildInfo: BuildInfo;
  appImage?: string;
  ecrRepositoryName?: string;
  now?: () => Date;
}

const DECOY_ID_RE = /-(\d{4})(\d{2})(\d{2})(\d{2})$/;

export class SocService {
  private readonly overviewCache = new TtlCache<unknown>(10_000);
  private readonly postureCache = new TtlCache<unknown>(10_000);
  private readonly now: () => Date;

  constructor(private readonly d: SocDeps) {
    this.now = d.now ?? (() => new Date());
  }

  private repo(): IncidentRepository {
    if (!this.d.repo) throw new AppError("SERVICE_UNAVAILABLE", "SOC integration is not configured");
    return this.d.repo;
  }

  overview() {
    const repo = this.repo();
    return this.overviewCache.get(async () => {
      const pages = await Promise.all(STATUSES.map((s) => repo.page(s, 50)));
      const rows = pages
        .flatMap((p) => p.items)
        .sort((a, b) => String(b.eventTime ?? "").localeCompare(String(a.eventTime ?? "")))
        .slice(0, 50);
      const now = this.now();
      return { incidents: rows.map(summary), metrics: await metrics(repo, "24h", now), generatedAt: now.toISOString() };
    });
  }

  async list(status: IncidentStatus, limit: number, cursor?: string) {
    const page = await this.repo().page(status, limit, cursor);
    return { items: page.items.map(summary), ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}) };
  }

  private async row(incidentId: string) {
    const row = await this.repo().get(incidentId);
    if (!row) throw new AppError("NOT_FOUND");
    return row;
  }

  async incident(incidentId: string) {
    const row = await this.row(incidentId);
    let related: unknown[] = [];
    const m = row.findingType === DECOY_FINDING_TYPE ? DECOY_ID_RE.exec(incidentId) : null;
    if (m) {
      const hourStart = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:00:00.000Z`;
      const hourEnd = `${m[1]}-${m[2]}-${m[3]}T${m[4]}:59:59.999Z`;
      related = await this.d.audit.relatedToIncident(incidentId, hourStart, hourEnd);
    }
    return detail(row, related);
  }

  private async verifyRow(row: Record<string, unknown>) {
    return verifyAll(this.d.s3, this.d.evidenceBucket, evidenceRecords(row));
  }

  async evidence(req: Request, incidentId: string) {
    const row = await this.row(incidentId);
    const [result, lock] = await Promise.all([this.verifyRow(row), bucketLock(this.d.s3, this.d.evidenceBucket)]);
    await this.d.audit.put(
      this.d.audit.build(req, {
        partition: PLATFORM_PARTITION,
        action: "SOC_EVIDENCE_VERIFIED",
        resource: { type: "incident", id: incidentId },
        details: { incidentId, objects: result.checks.length, chainOfCustodyOk: result.chainOfCustodyOk },
      }),
    );
    return {
      incidentId,
      verifiedAt: this.now().toISOString(),
      chainOfCustodyOk: result.chainOfCustodyOk,
      objectLock: lock,
      checks: result.checks,
      truncated: result.truncated,
      label: "Live verification view: SHA-256 recomputed from S3 by docs-api",
    };
  }

  async report(req: Request, incidentId: string, format: "json" | "md") {
    const row = await this.row(incidentId);
    const result = await this.verifyRow(row);
    const report = buildReport(row, result.checks, result.chainOfCustodyOk);
    await this.d.audit.put(
      this.d.audit.build(req, {
        partition: PLATFORM_PARTITION,
        action: "SOC_REPORT_EXPORTED",
        resource: { type: "incident", id: incidentId },
        details: { incidentId, format, chainOfCustodyOk: result.chainOfCustodyOk },
      }),
    );
    return format === "md" ? { markdown: toMarkdown(report) } : { report };
  }

  metrics(window: Window) {
    return metrics(this.repo(), window, this.now());
  }

  posture() {
    return this.postureCache.get(async () => {
      const image = parseImage(this.d.appImage, this.d.ecrRepositoryName);
      const [scan, dryRun, m] = await Promise.all([
        ecrScan(this.d.ecr, image),
        this.d.dryRun.read(),
        this.d.repo ? metrics(this.d.repo, "24h", this.now()).catch(() => null) : Promise.resolve(null),
      ]);
      return {
        generatedAt: this.now().toISOString(),
        build: this.d.buildInfo,
        imagePolicy: IMAGE_POLICY,
        image: { reference: image ? `${image.registryId}.dkr.ecr.${image.region}.amazonaws.com/${image.repositoryName}@${image.digest}` : null, ecrScan: scan },
        containment: {
          playbooksEnabled: this.d.playbooksEnabled,
          dryRun,
          failedLast24h: m ? m.byStatus.FAILED : null,
          lastMttcSeconds: m ? m.mttc.last : null,
          targetSeconds: MTTC_TARGET_SECONDS,
        },
      };
    });
  }
}
