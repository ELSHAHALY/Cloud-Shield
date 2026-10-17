// Wires config → clients → services. Content (agreements, GRC) that fails to
// load leaves only its own endpoints unavailable (503, fail closed).
import path from "node:path";
import type { Logger } from "pino";
import type { Config } from "./config";
import type { AppDeps } from "./app";
import { createClients, type AwsClients } from "./aws/clients";
import { createVerifier, type TokenVerifier } from "./auth/verifier";
import { AuditLog } from "./audit/audit";
import { loadCatalogue, type Catalogue } from "./agreements/catalogue";
import { AgreementService } from "./agreements/service";
import { DocumentService } from "./documents/service";
import { loadGrcContent, type GrcContent } from "./grc/content";
import { GrcService } from "./grc/service";
import { loadBuildInfo } from "./posture/posture";
import { IncidentRepository } from "./soc/repository";
import { DryRunSwitch, SocService } from "./soc/service";

export interface DepsOverrides {
  clients?: AwsClients;
  verifier?: TokenVerifier;
  now?: () => Date;
  catalogue?: Catalogue | null;
  grc?: GrcContent | null;
  validateResponses?: boolean;
}

export function createDeps(config: Config, logger: Logger, o: DepsOverrides = {}): AppDeps {
  const clients = o.clients ?? createClients(config);
  const now = o.now ?? (() => new Date());
  const audit = new AuditLog(clients.ddb, config.data.auditTable, now);

  let catalogue: Catalogue | undefined;
  if (o.catalogue !== undefined) catalogue = o.catalogue ?? undefined;
  else {
    try {
      catalogue = loadCatalogue(config.contentRoot);
    } catch (err) {
      logger.error({ err }, "agreement catalogue failed to load: agreement routes and document writes answer 503");
    }
  }
  let grc: GrcContent | undefined;
  if (o.grc !== undefined) grc = o.grc ?? undefined;
  else {
    try {
      grc = loadGrcContent(config.contentRoot);
    } catch (err) {
      logger.error({ err }, "GRC content failed validation: GRC routes answer 503");
    }
  }

  const dryRun = new DryRunSwitch(clients.ssm, config.soc?.dryRunParam);
  const services = {
    audit,
    now,
    documents: new DocumentService({
      ddb: clients.ddb,
      s3: clients.s3,
      s3Presign: clients.s3Presign,
      audit,
      logger,
      table: config.data.documentsTable,
      bucket: config.data.documentsBucket,
      kmsKeyArn: config.data.kmsKeyArn,
      presignMaxSeconds: config.data.presignMaxSeconds,
      maxUploadBytes: config.data.maxUploadBytes,
      now,
    }),
    agreements: new AgreementService(clients.ddb, config.data.auditTable, audit, catalogue, now),
    grc: new GrcService(clients.ddb, config.data.documentsTable, audit, grc, {
      region: config.region,
      playbooksEnabled: config.soc?.playbooksEnabled ?? false,
      dryRun: () => dryRun.read(),
    }, now),
    soc: new SocService({
      repo: config.soc ? new IncidentRepository(clients.ddb, config.soc.incidentsTable, config.soc.statusIndex) : undefined,
      s3: clients.s3,
      ecr: clients.ecr,
      audit,
      evidenceBucket: config.soc?.evidenceBucket ?? "",
      playbooksEnabled: config.soc?.playbooksEnabled ?? false,
      dryRun,
      buildInfo: loadBuildInfo(path.join(config.contentRoot, "docs-api", "build-info.json")),
      appImage: config.posture.appImage,
      ecrRepositoryName: config.posture.ecrRepositoryName,
      now,
    }),
  };

  return {
    services,
    verifier: o.verifier ?? createVerifier(config),
    logger,
    contentRoot: config.contentRoot,
    maxUploadBytes: config.data.maxUploadBytes,
    validateResponses: o.validateResponses ?? false,
    decoy: {
      events: clients.events,
      publishEnabled: config.decoy.publishEnabled,
      busName: config.decoy.busName,
      source: config.decoy.source,
      accountId: config.decoy.accountId,
      region: config.region,
      now,
    },
  };
}
