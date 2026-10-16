// Stage 2 content gate: the real files validate, every rule cites something,
// and no non-GDPR legal claim is presented as checked unless reviewed.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { loadCatalogue } from "../src/agreements/catalogue";
import { loadGrcContent } from "../src/grc/content";
import { compileSchema } from "../src/grc/schemas";

const ROOT = path.resolve(__dirname, "..", "..");
const content = loadGrcContent(ROOT);

/** Non-GDPR citations a reviewer has checked against the official text. */
const REVIEWED_DOC = new Set<string>([
  "Commission Implementing Decision (EU) 2021/914 (standard contractual clauses)",
  "Commission adequacy decision for the EU–US Data Privacy Framework, 10 July 2023",
]);

describe("GRC content", () => {
  it("validates the ruleset, matrix, platform facts and agreements", () => {
    expect(content.ruleset.version).toBe("2026.10.0");
    expect(content.ruleset.rules.length).toBeGreaterThanOrEqual(25);
    expect(content.matrix.controls.length).toBeGreaterThanOrEqual(12);
    expect(loadCatalogue(ROOT).required().map((a) => a.agreementId).sort()).toEqual(["dpa", "sla"]);
  });

  it("gives every rule at least one citation and marks non-GDPR claims verify", () => {
    for (const rule of content.ruleset.rules) {
      expect(rule.citations.length).toBeGreaterThan(0);
      for (const c of rule.citations) {
        const isGdprArticle = c.source.startsWith("Regulation (EU) 2016/679");
        if (!isGdprArticle && !REVIEWED_DOC.has(c.source)) expect({ rule: rule.id, source: c.source, status: c.status }).toEqual({ rule: rule.id, source: c.source, status: "verify" });
      }
    }
  });

  it("keeps the disclaimer and the honesty wording", () => {
    expect(content.ruleset.disclaimer).toMatch(/not legal advice/i);
    const text = JSON.stringify(content.ruleset) + readFileSync(path.join(ROOT, "grc", "agreements", "dpa-2026-10.txt"), "utf8");
    expect(text.toLowerCase()).not.toContain("immutable");
    expect(text).toMatch(/not a\s+qualified or advanced electronic signature/);
  });

  it("covers Egypt, the EU and Saudi Arabia", () => {
    const frameworks = new Set(content.ruleset.rules.map((r) => r.framework));
    for (const f of ["EG-PDPL", "EG-CBE", "EU-GDPR", "SA-PDPL", "SA-NCA"]) expect(frameworks.has(f)).toBe(true);
  });

  it("has stable agreement hashes (a text change needs a new version)", () => {
    const hashes = Object.fromEntries(loadCatalogue(ROOT).entries.map((e) => [`${e.agreementId}@${e.version}`, e.sha256]));
    const expected = JSON.parse(readFileSync(path.join(__dirname, "fixtures", "agreement-hashes.json"), "utf8"));
    expect(hashes).toEqual(expected);
  });

  it("validates a stored profile shape", () => {
    const validate = compileSchema(ROOT, "profile");
    expect(validate({ jurisdictions: ["EG"], sector: "general", cbeRegulated: false, processesPersonalData: true, processesSensitiveData: false, governmentData: false, dataSubjectRegions: [] })).toBe(true);
    expect(validate({ jurisdictions: [] })).toBe(false);
  });

  it("hashes the ruleset file bytes", () => {
    const text = readFileSync(path.join(ROOT, "grc", "rules", "2026.10.0.json"), "utf8");
    expect(content.sha256).toBe(createHash("sha256").update(text).digest("hex"));
  });
});
