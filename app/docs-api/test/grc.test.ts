import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { assess, buildFacts, checkCondition, evaluate, RulesetError, type Condition, type GrcProfile, type PlatformFacts, type Ruleset } from "../src/grc/engine";
import { latestRulesetFile, loadGrcContent, loadRuleset } from "../src/grc/content";

const CONTENT = path.resolve(__dirname, "..", "..");
const real = loadRuleset(CONTENT);

const platform: PlatformFacts = {
  provider: "aws",
  deploymentRegions: ["us-east-1"],
  encryptionAtRest: "kms-cmk",
  mfa: "totp-required",
  auditTrail: "insert-only-by-convention",
  incidentAutomation: "dry-run",
  mttcTargetSeconds: 60,
  erasureCompletesWithinDays: 30,
  transitInternalHop: "http-over-privatelink",
  evidenceObjectLock: "off-by-default",
  wafEnabled: true,
  malwareScanning: false,
  breachNotificationTooling: "sns-chatops",
  backupPitr: true,
};
const profile = (p: Partial<GrcProfile> = {}): GrcProfile => ({
  jurisdictions: ["EU"],
  sector: "general",
  cbeRegulated: false,
  processesPersonalData: true,
  processesSensitiveData: false,
  governmentData: false,
  dataSubjectRegions: ["EU"],
  ...p,
});

function withRuleset(mutate: (r: Ruleset) => unknown): () => unknown {
  return () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "grc-"));
    try {
      cpSync(path.join(CONTENT, "grc"), path.join(dir, "grc"), { recursive: true });
      const file = latestRulesetFile(path.join(dir, "grc", "rules"));
      const r = JSON.parse(readFileSync(file, "utf8")) as Ruleset;
      mutate(r);
      writeFileSync(file, JSON.stringify(r));
      return loadRuleset(dir);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
}

describe("ruleset validation (fail closed)", () => {
  const leaf = { fact: "tenant.cbeRegulated", op: "eq", value: true };
  it.each([
    ["an unknown operator", (r: Ruleset) => (r.rules[0]!.appliesWhen = { fact: "tenant.cbeRegulated", op: "regex", value: ".*" } as never)],
    ["an unknown fact path", (r: Ruleset) => (r.rules[0]!.appliesWhen = { fact: "tenant.__proto__", op: "eq", value: true } as never)],
    ["a constructor path", (r: Ruleset) => (r.rules[0]!.appliesWhen = { fact: "constructor.prototype", op: "eq", value: true } as never)],
    ["depth > 8", (r: Ruleset) => (r.rules[0]!.appliesWhen = Array.from({ length: 9 }).reduce<unknown>((c) => ({ not: c }), leaf) as never)],
    ["an extra property", (r: Ruleset) => ((r.rules[0] as unknown as Record<string, unknown>).eval = "1")],
    ["a duplicate rule id", (r: Ruleset) => r.rules.push({ ...r.rules[0]! })],
    ["an unknown framework", (r: Ruleset) => (r.rules[0]!.framework = "XX-NOPE")],
    ["a jurisdiction naming an unknown framework", (r: Ruleset) => r.jurisdictions[0]!.frameworks.push("XX-NOPE")],
    ["a rule without citations", (r: Ruleset) => (r.rules[0]!.citations = [])],
  ])("rejects %s", (_name, mutate) => {
    expect(withRuleset(mutate as (r: Ruleset) => unknown)).toThrow();
  });

  it("checkCondition rejects shapes the schema would also reject", () => {
    expect(() => checkCondition(null)).toThrow(RulesetError);
    expect(() => checkCondition([])).toThrow(RulesetError);
    expect(() => checkCondition({ all: [] })).toThrow(RulesetError);
    expect(() => checkCondition({ fact: "platform.mfa", op: "nope" })).toThrow(RulesetError);
    expect(() => checkCondition({ any: [{ not: { fact: "platform.mfa", op: "exists" } }] })).not.toThrow();
  });

  it("evaluate refuses deep or unknown conditions at runtime too", () => {
    const facts = buildFacts(real.ruleset, profile(), platform);
    const deep = Array.from({ length: 9 }).reduce<Condition>((c) => ({ not: c }), { fact: "platform.mfa", op: "exists" });
    expect(() => evaluate(deep, facts)).toThrow(RulesetError);
    expect(() => evaluate({ fact: "tenant.secret" as never, op: "eq", value: 1 }, facts)).toThrow(RulesetError);
    expect(() => evaluate({ fact: "platform.mfa", op: "bogus" }, facts)).toThrow(RulesetError);
  });

  it("has every operator", () => {
    const f = buildFacts(real.ruleset, profile({ jurisdictions: ["EG", "SA"] }), platform);
    expect(evaluate({ fact: "platform.mfa", op: "eq", value: "totp-required" }, f)).toBe(true);
    expect(evaluate({ fact: "platform.mfa", op: "neq", value: "none" }, f)).toBe(true);
    expect(evaluate({ fact: "tenant.sector", op: "in", value: ["general"] }, f)).toBe(true);
    expect(evaluate({ fact: "tenant.jurisdictions", op: "includes", value: "SA" }, f)).toBe(true);
    expect(evaluate({ fact: "tenant.jurisdictions", op: "includesAny", value: ["EU", "EG"] }, f)).toBe(true);
    expect(evaluate({ fact: "platform.mttcTargetSeconds", op: "gte", value: 60 }, f)).toBe(true);
    expect(evaluate({ fact: "platform.mttcTargetSeconds", op: "lte", value: 59 }, f)).toBe(false);
    expect(evaluate({ fact: "platform.mfa", op: "exists" }, f)).toBe(true);
    expect(evaluate({ fact: "platform.mfa", op: "exists", value: false }, f)).toBe(false);
    expect(evaluate({ all: [{ fact: "derived.crossBorder", op: "eq", value: true }, { any: [{ fact: "tenant.cbeRegulated", op: "eq", value: true }, { not: { fact: "tenant.cbeRegulated", op: "eq", value: true } }] }] }, f)).toBe(true);
  });

  it("fails the GRC endpoints closed via loadGrcContent", () => {
    expect(() => loadGrcContent("/nonexistent")).toThrow();
  });
});

describe("assessment", () => {
  it("is deterministic, versioned and hashed", () => {
    const a = assess(real.ruleset, profile(), platform);
    const b = assess(real.ruleset, profile(), platform);
    expect(a.findings).toEqual(b.findings);
    expect(real.sha256).toMatch(/^[0-9a-f]{64}$/);
    const ids = a.findings.map((f) => f.ruleId);
    expect([...ids].sort((x, y) => x.localeCompare(y))).toEqual([...ids].sort((x, y) => x.localeCompare(y)));
  });

  it("reports residency and transfer GAP for EG, SA and EU tenants hosted in us-east-1", () => {
    const eg = assess(real.ruleset, profile({ jurisdictions: ["EG"], cbeRegulated: true }), platform).findings;
    expect(eg.find((f) => f.ruleId === "EG-PDPL-CROSS-BORDER")!.status).toBe("GAP");
    const loc = eg.find((f) => f.ruleId === "EG-CBE-DATA-LOCATION-ACCESS")!;
    expect(loc.status).toBe("GAP");
    expect(loc.rationale).toContain("us-east-1 (US)");
    expect(loc.rationale).toContain("residency in EG not met");
    const sa = assess(real.ruleset, profile({ jurisdictions: ["SA"], governmentData: true, sector: "government" }), platform).findings;
    expect(sa.find((f) => f.ruleId === "SA-NCA-GOV-DATA-RESIDENCY")!.status).toBe("GAP");
    expect(sa.find((f) => f.ruleId === "SA-PDPL-CROSS-BORDER")!.status).toBe("GAP");
    const eu = assess(real.ruleset, profile(), platform).findings;
    expect(eu.find((f) => f.ruleId === "EU-GDPR-ART44-46-TRANSFERS")!.status).toBe("GAP");
    const euHosted = assess(real.ruleset, profile(), { ...platform, deploymentRegions: ["eu-central-1"] }).findings;
    expect(euHosted.find((f) => f.ruleId === "EU-GDPR-ART44-46-TRANSFERS")!.status).toBe("MET");
  });

  it("adds the CBE scope note for CBE-regulated tenants only", () => {
    expect(assess(real.ruleset, profile({ jurisdictions: ["EG"], cbeRegulated: true }), platform).findings.find((f) => f.ruleId === "EG-PDPL-SCOPE-CBE")!.status).toBe("INFO");
    expect(assess(real.ruleset, profile({ jurisdictions: ["EG"] }), platform).findings.find((f) => f.ruleId === "EG-PDPL-SCOPE-CBE")!.status).toBe("NOT_APPLICABLE");
  });

  it("marks breach readiness PARTIAL in dry-run and MET when containment is enabled", () => {
    const f = (automation: PlatformFacts["incidentAutomation"]) => assess(real.ruleset, profile(), { ...platform, incidentAutomation: automation }).findings.find((x) => x.ruleId === "EU-GDPR-ART33-BREACH-72H")!.status;
    expect(f("dry-run")).toBe("PARTIAL");
    expect(f("enabled")).toBe("MET");
    expect(assess(real.ruleset, profile(), { ...platform, breachNotificationTooling: "none" }).findings.find((x) => x.ruleId === "EU-GDPR-ART33-BREACH-72H")!.status).toBe("GAP");
  });

  it("carries citationStatus on every finding and counts the summary", () => {
    const a = assess(real.ruleset, profile({ jurisdictions: ["EG", "EU", "SA"] }), platform);
    for (const f of a.findings) expect(["doc", "verify"]).toContain(f.citationStatus);
    expect(Object.values(a.summary).reduce((x, y) => x + y, 0)).toBe(a.findings.length);
    expect(a.findings.find((f) => f.ruleId === "EU-GDPR-ART17-ERASURE")!.citationStatus).toBe("doc");
    expect(a.findings.find((f) => f.ruleId === "EG-PDPL-BREACH-NOTICE")!.citationStatus).toBe("verify");
  });

  it("maps an unknown deployment region to UNKNOWN", () => {
    const facts = buildFacts(real.ruleset, profile(), { ...platform, deploymentRegions: ["xx-nowhere-9"] });
    expect(facts.get("platform.deploymentCountries")).toEqual(["UNKNOWN"]);
  });
});
