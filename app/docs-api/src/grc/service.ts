// GRC hub (plan §8): ruleset summary, matrix, tenant profile, assessment.
import { GetCommand, TransactWriteCommand, type DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import type { Request } from "express";
import type { Principal } from "../auth/principal";
import type { AuditLog } from "../audit/audit";
import { AppError } from "../lib/errors";
import { assess, deploymentCountries, type GrcProfile, type PlatformFacts } from "./engine";
import type { GrcContent } from "./content";

const PROFILE_KEY = "meta#grc-profile";

export interface PlatformRuntime {
  region: string;
  playbooksEnabled: boolean;
  dryRun(): Promise<boolean | null>;
}

export class GrcService {
  constructor(
    private readonly ddb: DynamoDBDocumentClient,
    private readonly table: string,
    private readonly audit: AuditLog,
    private readonly content: GrcContent | undefined,
    private readonly runtime: PlatformRuntime,
    private readonly now: () => Date = () => new Date(),
  ) {}

  private require(): GrcContent {
    if (!this.content) throw new AppError("SERVICE_UNAVAILABLE", "GRC ruleset unavailable");
    return this.content;
  }

  summary() {
    const { ruleset, sha256 } = this.require();
    return {
      version: ruleset.version,
      sha256,
      lastReviewed: ruleset.lastReviewed,
      disclaimer: ruleset.disclaimer,
      jurisdictions: ruleset.jurisdictions,
      frameworks: ruleset.frameworks,
      ruleCount: ruleset.rules.length,
    };
  }

  matrix() {
    const { matrix } = this.require();
    return {
      version: matrix.version,
      lastReviewed: matrix.lastReviewed,
      disclaimer: matrix.disclaimer,
      providers: matrix.providers,
      controls: matrix.controls,
      layers: matrix.layers,
    };
  }

  async getProfile(p: Principal) {
    const out = await this.ddb.send(new GetCommand({ TableName: this.table, Key: { tenantId: p.tenantId, docId: PROFILE_KEY }, ConsistentRead: true }));
    if (!out.Item) throw new AppError("NOT_FOUND", "no GRC profile yet");
    return {
      profile: out.Item.profile as GrcProfile,
      version: Number(out.Item.version),
      updatedAt: String(out.Item.updatedAt),
      updatedBy: String(out.Item.updatedBy),
    };
  }

  async putProfile(req: Request, p: Principal, profile: GrcProfile) {
    this.require();
    const current = await this.getProfile(p).catch((err: unknown) => {
      if (err instanceof AppError && err.code === "NOT_FOUND") return undefined;
      throw err;
    });
    const version = (current?.version ?? 0) + 1;
    const record = { profile, version, updatedAt: this.now().toISOString(), updatedBy: p.sub };
    const event = this.audit.build(req, {
      partition: p.tenantId,
      action: "GRC_PROFILE_UPDATED",
      resource: { type: "grc-profile" },
      details: { version, jurisdictions: profile.jurisdictions.join(",") },
    });
    try {
      await this.ddb.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Put: {
                TableName: this.table,
                Item: { tenantId: p.tenantId, docId: PROFILE_KEY, ...record },
                ConditionExpression: current ? "version = :v" : "attribute_not_exists(docId)",
                ...(current ? { ExpressionAttributeValues: { ":v": current.version } } : {}),
              },
            },
            this.audit.transactPut(event),
          ],
        }),
      );
    } catch (err) {
      if ((err as { name?: string }).name === "TransactionCanceledException") throw new AppError("CONFLICT", "profile changed concurrently");
      throw err;
    }
    return record;
  }

  async platformFacts(): Promise<PlatformFacts> {
    const { platform } = this.require();
    const dryRun = await this.runtime.dryRun();
    return {
      ...platform.facts,
      deploymentRegions: [this.runtime.region],
      incidentAutomation: !this.runtime.playbooksEnabled ? "disabled" : dryRun === false ? "enabled" : "dry-run",
    };
  }

  async assessment(p: Principal) {
    const { ruleset, sha256 } = this.require();
    const record = await this.getProfile(p);
    const platform = await this.platformFacts();
    const { findings, summary } = assess(ruleset, record.profile, platform);
    return {
      rulesetVersion: ruleset.version,
      rulesetSha256: sha256,
      profileVersion: record.version,
      generatedAt: this.now().toISOString(),
      platformFacts: { ...platform, deploymentCountries: deploymentCountries(ruleset, platform.deploymentRegions) },
      disclaimer: ruleset.disclaimer,
      summary,
      findings,
    };
  }
}
