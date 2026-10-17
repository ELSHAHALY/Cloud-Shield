import { afterEach, describe, expect, it, vi } from "vitest";
import type { GrcAssessment, GrcFinding, RulesetSummary } from "../api/types";
import { buildReadinessPackJson, buildReadinessPackMarkdown, downloadText, mdCell, packFilename, PACK_BANNER, PACK_FORMAT, VERIFY_MARKER } from "./readinessPack";

const ruleset: RulesetSummary = { version: "2026.10.0", sha256: "a".repeat(64), lastReviewed: "2026-10-16", disclaimer: "Informational mapping; not legal advice.", jurisdictions: [], frameworks: [], ruleCount: 4 };

const finding = (over: Partial<GrcFinding>): GrcFinding => ({
  ruleId: "R",
  framework: "EG-PDPL",
  topic: "security",
  status: "MET",
  obligation: "o",
  citations: [{ source: "Law 151/2020", status: "doc" }],
  citationStatus: "doc",
  controls: [],
  rationale: "r",
  ...over,
});

const assessment: GrcAssessment = {
  rulesetVersion: "2026.10.0",
  rulesetSha256: "a".repeat(64),
  profileVersion: 3,
  generatedAt: "2026-10-17T10:00:00.000Z",
  platformFacts: { deploymentRegions: ["us-east-1"], incidentAutomation: "dry-run" },
  disclaimer: "Informational mapping; not legal advice.",
  summary: { MET: 1, PARTIAL: 0, GAP: 1, CUSTOMER_ACTION: 1, NOT_APPLICABLE: 1, INFO: 0 },
  findings: [
    finding({ ruleId: "EG-PDPL-CROSS-BORDER", topic: "cross-border", status: "GAP", obligation: "Transfer only | with a\nlicence <script>alert(1)</script>", citations: [{ source: "Law 151/2020", article: "Art. 14", status: "verify" }], citationStatus: "verify", controls: ["region"] }),
    finding({ ruleId: "EU-GDPR-ART17-ERASURE", framework: "EU-GDPR", topic: "erasure", status: "MET", citations: [{ source: "GDPR", article: "Art. 17", status: "doc" }] }),
    finding({ ruleId: "EG-CBE-OUTSOURCING", framework: "EG-CBE", topic: "outsourcing", status: "CUSTOMER_ACTION", obligation: "Notify the regulator.", citationStatus: "verify" }),
    finding({ ruleId: "EG-PDPL-SCOPE-HIDDEN", status: "NOT_APPLICABLE", citationStatus: "verify" }),
  ],
};

const md = () => buildReadinessPackMarkdown(assessment, ruleset, "t-nile-02", "2026-10-17T11:00:00.000Z");
const line = (text: string, id: string) => text.split("\n").find((l) => l.includes(id)) ?? "";

describe("mdCell", () => {
  it("keeps table structure and blocks HTML, links and code", () => {
    expect(mdCell("a|b\r\nc\\d")).toBe("a\\|b c\\\\d");
    expect(mdCell("<img src=x onerror=1> & [x](javascript:1) `c`")).toBe("&lt;img src=x onerror=1&gt; &amp; \\[x\\](javascript:1) \\`c\\`");
    expect(mdCell(undefined)).toBe("");
    expect(mdCell("x".repeat(5000))).toHaveLength(2000);
  });
});

describe("buildReadinessPackMarkdown", () => {
  it("always carries the banner, the disclaimer and the provenance", () => {
    const text = md();
    expect(text).toContain(PACK_BANNER);
    expect(text).toContain("not audited and not signed");
    expect(text).toContain("> Informational mapping; not legal advice.");
    for (const v of ["t-nile-02", "2026.10.0", "a".repeat(64), "2026-10-16", "| Profile version | 3 |", "2026-10-17T10:00:00.000Z", "2026-10-17T11:00:00.000Z", PACK_FORMAT, "deploymentRegions: us-east-1"]) {
      expect(text).toContain(v);
    }
    expect(text).not.toContain("differs from the one this assessment used");
  });

  it("marks every verify finding and no doc finding", () => {
    const text = md();
    expect(line(text, "| EG-PDPL-CROSS-BORDER")).toContain(VERIFY_MARKER);
    expect(line(text, "| EG-CBE-OUTSOURCING")).toContain(VERIFY_MARKER);
    expect(line(text, "| EU-GDPR-ART17-ERASURE")).not.toContain(VERIFY_MARKER);
    expect(line(text, "- **EG-CBE-OUTSOURCING**")).toContain(VERIFY_MARKER);
    expect(text).toContain("2 listed finding(s) cite text");
  });

  it("counts NOT_APPLICABLE but does not list it, and groups by framework", () => {
    const text = md();
    expect(text).toContain("| NOT_APPLICABLE | 1 |");
    expect(text).not.toContain("EG-PDPL-SCOPE-HIDDEN");
    expect(text.indexOf("## EG-CBE")).toBeLessThan(text.indexOf("## EG-PDPL"));
    expect(text.indexOf("## EG-PDPL")).toBeLessThan(text.indexOf("## EU-GDPR"));
    expect(text).toContain("GAP findings affected: EG-PDPL-CROSS-BORDER.");
  });

  it("escapes hostile ruleset text", () => {
    const row = line(md(), "| EG-PDPL-CROSS-BORDER");
    expect(row).toContain("Transfer only \\| with a licence &lt;script&gt;alert(1)&lt;/script&gt;");
    expect(md()).not.toContain("<script>");
    expect(row.split(" | ")).toHaveLength(8);
  });

  it("warns when the served ruleset no longer matches, and handles no customer actions", () => {
    const only = { ...assessment, findings: [assessment.findings[1]!] };
    const text = buildReadinessPackMarkdown(only, { ...ruleset, sha256: "b".repeat(64) }, "t", "x");
    expect(text).toContain("differs from the one this assessment used");
    expect(text).toContain("None for this profile.");
    expect(text).not.toContain("GAP findings affected");
  });
});

describe("buildReadinessPackJson", () => {
  it("is the assessment verbatim plus exportMeta", () => {
    const pack = JSON.parse(buildReadinessPackJson(assessment, ruleset, "t-nile-02", "2026-10-17T11:00:00.000Z")) as { assessment: unknown; exportMeta: Record<string, string> };
    expect(pack.assessment).toEqual(assessment);
    expect(pack.exportMeta).toMatchObject({ format: PACK_FORMAT, exportedAt: "2026-10-17T11:00:00.000Z", tenantId: "t-nile-02", rulesetVersion: "2026.10.0", rulesetSha256: "a".repeat(64), rulesetLastReviewed: "2026-10-16", disclaimer: assessment.disclaimer });
    expect(pack.exportMeta.notice).toContain(PACK_BANNER);
  });
});

describe("packFilename and downloadText", () => {
  afterEach(() => vi.restoreAllMocks());

  it("sanitises the filename", () => {
    expect(packFilename("t-nile-02", "2026.10.0", "md")).toBe("cloudshield-grc-readiness-t-nile-02-2026.10.0.md");
    expect(packFilename("../../etc/passwd", "v 1/2", "json")).toBe("cloudshield-grc-readiness-.._.._etc_passwd-v_1_2.json");
    expect(packFilename("", "", "md")).toBe("cloudshield-grc-readiness-unknown-unknown.md");
  });

  it("downloads through an object URL and revokes it", () => {
    const create = vi.fn<(b: Blob) => string>(() => "blob:x");
    const revoke = vi.fn();
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    downloadText("hello", "text/markdown;charset=utf-8", "f.md");
    expect(create.mock.calls[0]![0].type).toBe("text/markdown;charset=utf-8");
    expect(click).toHaveBeenCalledOnce();
    expect(revoke).toHaveBeenCalledWith("blob:x");
    expect(document.querySelector("a[download]")).toBeNull();
  });
});
