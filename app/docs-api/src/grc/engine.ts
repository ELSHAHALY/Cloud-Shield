// Rules-as-data GRC engine (plan D23, §8.2). A fixed operator set over an
// allow-listed fact enumeration, depth ≤ 8. No eval, no regexes from data, no
// dynamic property paths: facts live in a Map keyed by the enumerated names.
export const FACT_PATHS = [
  "tenant.jurisdictions",
  "tenant.sector",
  "tenant.cbeRegulated",
  "tenant.processesPersonalData",
  "tenant.processesSensitiveData",
  "tenant.governmentData",
  "tenant.dataSubjectRegions",
  "platform.provider",
  "platform.deploymentRegions",
  "platform.deploymentCountries",
  "platform.encryptionAtRest",
  "platform.mfa",
  "platform.auditTrail",
  "platform.incidentAutomation",
  "platform.mttcTargetSeconds",
  "platform.erasureCompletesWithinDays",
  "platform.transitInternalHop",
  "platform.evidenceObjectLock",
  "platform.wafEnabled",
  "platform.malwareScanning",
  "platform.breachNotificationTooling",
  "platform.backupPitr",
  "derived.crossBorder",
  "derived.residencyCountries",
] as const;
export type FactPath = (typeof FACT_PATHS)[number];
export type FactValue = string | number | boolean | string[];
export type Facts = ReadonlyMap<FactPath, FactValue>;

export const MAX_DEPTH = 8;
const OPS = new Set(["eq", "neq", "in", "includes", "includesAny", "gte", "lte", "exists"]);
const FACT_SET: ReadonlySet<string> = new Set(FACT_PATHS);

export type Condition =
  | { all: Condition[] }
  | { any: Condition[] }
  | { not: Condition }
  | { fact: FactPath; op: string; value?: FactValue };

export class RulesetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RulesetError";
  }
}

const own = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

/** Structural check independent of the JSON Schema (depth, operators, facts). */
export function checkCondition(c: unknown, depth = 1): void {
  if (depth > MAX_DEPTH) throw new RulesetError(`condition deeper than ${MAX_DEPTH}`);
  if (c === null || typeof c !== "object" || Array.isArray(c)) throw new RulesetError("condition must be an object");
  if (own(c, "all") || own(c, "any")) {
    const list = (c as Record<string, unknown>).all ?? (c as Record<string, unknown>).any;
    if (!Array.isArray(list) || list.length === 0) throw new RulesetError("combinator needs a non-empty list");
    for (const x of list) checkCondition(x, depth + 1);
    return;
  }
  if (own(c, "not")) {
    checkCondition((c as { not: unknown }).not, depth + 1);
    return;
  }
  const leaf = c as { fact?: unknown; op?: unknown };
  if (typeof leaf.fact !== "string" || !FACT_SET.has(leaf.fact)) throw new RulesetError("unknown fact path");
  if (typeof leaf.op !== "string" || !OPS.has(leaf.op)) throw new RulesetError("unknown operator");
}

export function evaluate(c: Condition, facts: Facts, depth = 1): boolean {
  if (depth > MAX_DEPTH) throw new RulesetError(`condition deeper than ${MAX_DEPTH}`);
  if ("all" in c) return c.all.every((x) => evaluate(x, facts, depth + 1));
  if ("any" in c) return c.any.some((x) => evaluate(x, facts, depth + 1));
  if ("not" in c) return !evaluate(c.not, facts, depth + 1);
  if (!FACT_SET.has(c.fact)) throw new RulesetError("unknown fact path");
  const v = facts.get(c.fact);
  const want = c.value;
  switch (c.op) {
    case "eq":
      return v !== undefined && !Array.isArray(v) && v === want;
    case "neq":
      return v === undefined || Array.isArray(v) || v !== want;
    case "in":
      return v !== undefined && !Array.isArray(v) && Array.isArray(want) && (want as unknown[]).includes(v);
    case "includes":
      return Array.isArray(v) && typeof want === "string" && v.includes(want);
    case "includesAny":
      return Array.isArray(v) && Array.isArray(want) && want.some((x) => v.includes(x));
    case "gte":
      return typeof v === "number" && typeof want === "number" && v >= want;
    case "lte":
      return typeof v === "number" && typeof want === "number" && v <= want;
    case "exists":
      return (v !== undefined) === (want !== false);
    default:
      throw new RulesetError("unknown operator");
  }
}

export interface Citation {
  source: string;
  article?: string;
  status: "doc" | "verify";
  url?: string;
}

export type FindingStatus = "MET" | "PARTIAL" | "GAP" | "CUSTOMER_ACTION" | "NOT_APPLICABLE" | "INFO";

export interface Rule {
  id: string;
  framework: string;
  topic: string;
  appliesWhen: Condition;
  obligation: string;
  parameters?: Record<string, string | number | boolean>;
  citations: Citation[];
  assessment: { type: "platform-control" | "customer-action" | "residency" | "info"; metWhen?: Condition; partialWhen?: Condition; country?: string };
  controls: string[];
  rationale: Partial<Record<FindingStatus, string>>;
}

export interface Ruleset {
  schemaVersion: "1";
  rulesetId: "cloudshield-grc";
  version: string;
  lastReviewed: string;
  disclaimer: string;
  jurisdictions: { id: "EG" | "EU" | "SA"; name: string; frameworks: string[] }[];
  regionCountry: Record<string, string>;
  frameworks: { id: string; title: string; citation: string; regulator: string; citationStatus: "doc" | "verify"; notes?: string }[];
  rules: Rule[];
}

export interface GrcProfile {
  jurisdictions: ("EG" | "EU" | "SA")[];
  sector: "general" | "financial" | "health" | "government" | "critical-infrastructure";
  cbeRegulated: boolean;
  processesPersonalData: boolean;
  processesSensitiveData: boolean;
  governmentData: boolean;
  dataSubjectRegions: ("EG" | "EU" | "SA" | "OTHER")[];
}

export interface PlatformFacts {
  provider: string;
  deploymentRegions: string[];
  encryptionAtRest: string;
  mfa: string;
  auditTrail: string;
  incidentAutomation: "enabled" | "dry-run" | "disabled";
  mttcTargetSeconds: number;
  erasureCompletesWithinDays: number;
  transitInternalHop: string;
  evidenceObjectLock: string;
  wafEnabled: boolean;
  malwareScanning: boolean;
  breachNotificationTooling: string;
  backupPitr: boolean;
}

/** Cross-rule checks the schema cannot express. */
export function checkRuleset(r: Ruleset): void {
  const frameworks = new Set(r.frameworks.map((f) => f.id));
  const ids = new Set<string>();
  for (const rule of r.rules) {
    if (ids.has(rule.id)) throw new RulesetError("duplicate rule id");
    ids.add(rule.id);
    if (!frameworks.has(rule.framework)) throw new RulesetError("rule names an unknown framework");
    checkCondition(rule.appliesWhen);
    if (rule.assessment.metWhen) checkCondition(rule.assessment.metWhen);
    if (rule.assessment.partialWhen) checkCondition(rule.assessment.partialWhen);
  }
  for (const j of r.jurisdictions) for (const f of j.frameworks) if (!frameworks.has(f)) throw new RulesetError("jurisdiction names an unknown framework");
}

export function deploymentCountries(r: Ruleset, regions: readonly string[]): string[] {
  return [...new Set(regions.map((reg) => (Object.prototype.hasOwnProperty.call(r.regionCountry, reg) ? r.regionCountry[reg]! : "UNKNOWN")))].sort();
}

export function buildFacts(r: Ruleset, profile: GrcProfile, platform: PlatformFacts): Map<FactPath, FactValue> {
  const countries = deploymentCountries(r, platform.deploymentRegions);
  const residency = [...profile.jurisdictions].sort();
  const facts = new Map<FactPath, FactValue>([
    ["tenant.jurisdictions", [...profile.jurisdictions]],
    ["tenant.sector", profile.sector],
    ["tenant.cbeRegulated", profile.cbeRegulated],
    ["tenant.processesPersonalData", profile.processesPersonalData],
    ["tenant.processesSensitiveData", profile.processesSensitiveData],
    ["tenant.governmentData", profile.governmentData],
    ["tenant.dataSubjectRegions", [...profile.dataSubjectRegions]],
    ["platform.provider", platform.provider],
    ["platform.deploymentRegions", [...platform.deploymentRegions]],
    ["platform.deploymentCountries", countries],
    ["platform.encryptionAtRest", platform.encryptionAtRest],
    ["platform.mfa", platform.mfa],
    ["platform.auditTrail", platform.auditTrail],
    ["platform.incidentAutomation", platform.incidentAutomation],
    ["platform.mttcTargetSeconds", platform.mttcTargetSeconds],
    ["platform.erasureCompletesWithinDays", platform.erasureCompletesWithinDays],
    ["platform.transitInternalHop", platform.transitInternalHop],
    ["platform.evidenceObjectLock", platform.evidenceObjectLock],
    ["platform.wafEnabled", platform.wafEnabled],
    ["platform.malwareScanning", platform.malwareScanning],
    ["platform.breachNotificationTooling", platform.breachNotificationTooling],
    ["platform.backupPitr", platform.backupPitr],
    ["derived.crossBorder", residency.some((c) => !countries.includes(c))],
    ["derived.residencyCountries", residency],
  ]);
  return facts;
}

function fill(template: string, vars: Readonly<Record<string, string>>): string {
  let out = template;
  for (const [k, v] of Object.entries(vars)) out = out.split(`{${k}}`).join(v);
  return out;
}

const DEFAULT_RATIONALE: Record<FindingStatus, string> = {
  MET: "The platform control is in place.",
  PARTIAL: "The platform control is partly in place.",
  GAP: "The platform does not meet this obligation as deployed.",
  CUSTOMER_ACTION: "This obligation rests with the customer (controller).",
  NOT_APPLICABLE: "Not applicable to this tenant profile.",
  INFO: "Informational.",
};

export function assess(r: Ruleset, profile: GrcProfile, platform: PlatformFacts) {
  const facts = buildFacts(r, profile, platform);
  const countries = facts.get("platform.deploymentCountries") as string[];
  const vars = { deploymentRegions: platform.deploymentRegions.join(", "), deploymentCountries: countries.join(", ") };
  const findings = r.rules.map((rule) => {
    let status: FindingStatus;
    if (!evaluate(rule.appliesWhen, facts)) status = "NOT_APPLICABLE";
    else if (rule.assessment.type === "customer-action") status = "CUSTOMER_ACTION";
    else if (rule.assessment.type === "info") status = "INFO";
    else if (rule.assessment.type === "residency") status = countries.includes(rule.assessment.country ?? "") ? "MET" : "GAP";
    else if (rule.assessment.metWhen && evaluate(rule.assessment.metWhen, facts)) status = "MET";
    else if (rule.assessment.partialWhen && evaluate(rule.assessment.partialWhen, facts)) status = "PARTIAL";
    else status = "GAP";
    return {
      ruleId: rule.id,
      framework: rule.framework,
      topic: rule.topic,
      status,
      obligation: rule.obligation,
      ...(rule.parameters ? { parameters: { ...rule.parameters } } : {}),
      citations: rule.citations.map((c) => ({ ...c })),
      citationStatus: rule.citations.some((c) => c.status === "verify") ? ("verify" as const) : ("doc" as const),
      controls: [...rule.controls],
      rationale: fill(rule.rationale[status] ?? DEFAULT_RATIONALE[status], { ...vars, country: rule.assessment.country ?? "" }),
    };
  });
  findings.sort((a, b) => (a.framework === b.framework ? a.ruleId.localeCompare(b.ruleId) : a.framework.localeCompare(b.framework)));
  const summary: Record<FindingStatus, number> = { MET: 0, PARTIAL: 0, GAP: 0, CUSTOMER_ACTION: 0, NOT_APPLICABLE: 0, INFO: 0 };
  for (const f of findings) summary[f.status] += 1;
  return { findings, summary, facts };
}
