// Loads and validates the GRC content at startup. Any failure leaves the GRC
// endpoints answering 503 (fail closed) without affecting the rest of the API.
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { normaliseText } from "../agreements/catalogue";
import { checkRuleset, type Ruleset } from "./engine";
import { compileSchema, type SchemaName } from "./schemas";

export interface MatrixFile {
  schemaVersion: "1";
  version: string;
  lastReviewed: string;
  disclaimer: string;
  providers: ("aws" | "azure" | "gcp")[];
  controls: unknown[];
  layers: unknown[];
}

export interface PlatformFactsFile {
  schemaVersion: "1";
  reviewedAgainst: string;
  lastReviewed: string;
  facts: {
    provider: string;
    encryptionAtRest: string;
    mfa: string;
    auditTrail: string;
    mttcTargetSeconds: number;
    erasureCompletesWithinDays: number;
    transitInternalHop: string;
    evidenceObjectLock: string;
    wafEnabled: boolean;
    malwareScanning: boolean;
    breachNotificationTooling: string;
    backupPitr: boolean;
  };
}

export interface GrcContent {
  ruleset: Ruleset;
  sha256: string;
  matrix: MatrixFile;
  platform: PlatformFactsFile;
}

const RULESET_FILE_RE = /^\d{4}\.\d{1,2}\.\d{1,3}\.json$/;

function readJson(file: string): { value: unknown; text: string } {
  const text = normaliseText(readFileSync(file, "utf8"));
  return { value: JSON.parse(text) as unknown, text };
}

function validated<T>(contentRoot: string, schema: SchemaName, value: unknown, what: string): T {
  const validate = compileSchema(contentRoot, schema);
  if (!validate(value)) {
    const first = validate.errors?.[0];
    throw new Error(`${what} failed schema validation at ${first?.instancePath ?? "/"}: ${first?.message ?? "invalid"}`);
  }
  return value as T;
}

/** Highest semver-like file name in grc/rules (YYYY.M.N.json). */
export function latestRulesetFile(rulesDir: string): string {
  const files = readdirSync(rulesDir).filter((f) => RULESET_FILE_RE.test(f));
  if (files.length === 0) throw new Error("no ruleset file");
  const key = (f: string) => f.replace(/\.json$/, "").split(".").map(Number);
  files.sort((a, b) => {
    const [x, y] = [key(a), key(b)];
    for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return (x[i] ?? 0) - (y[i] ?? 0);
    return 0;
  });
  return path.join(rulesDir, files[files.length - 1]!);
}

export function loadRuleset(contentRoot: string, file?: string): { ruleset: Ruleset; sha256: string } {
  const { value, text } = readJson(file ?? latestRulesetFile(path.join(contentRoot, "grc", "rules")));
  const ruleset = validated<Ruleset>(contentRoot, "ruleset", value, "ruleset");
  checkRuleset(ruleset);
  return { ruleset, sha256: createHash("sha256").update(text, "utf8").digest("hex") };
}

export function loadGrcContent(contentRoot: string): GrcContent {
  const { ruleset, sha256 } = loadRuleset(contentRoot);
  const matrix = validated<MatrixFile>(contentRoot, "matrix", readJson(path.join(contentRoot, "grc", "matrix", "shared-responsibility.json")).value, "matrix");
  const platform = validated<PlatformFactsFile>(contentRoot, "platform-facts", readJson(path.join(contentRoot, "grc", "platform-facts.json")).value, "platform facts");
  return { ruleset, sha256, matrix, platform };
}
