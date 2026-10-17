// Compliance Readiness Pack (Phase F D12): a client-side export of the
// assessment the hub already fetched. No API call, no audit event, no
// signature: it is a self-assessment, and the pack says so on every export.
import type { GrcAssessment, GrcFinding, RulesetSummary } from "../api/types";

export const PACK_FORMAT = "cloudshield.grc.readiness-pack/1";
export const PACK_BANNER = "Not legal advice. Not an audit or certification.";
export const VERIFY_MARKER = "⚠ VERIFY against the official text";

const MAX_CELL = 2000;
// Topics whose GAP is a consequence of the single-region deployment.
const RESIDENCY_TOPICS: ReadonlySet<string> = new Set(["cross-border", "data-hosting", "data-location", "government-data"]);
const STATUS_ORDER: GrcFinding["status"][] = ["GAP", "PARTIAL", "CUSTOMER_ACTION", "MET", "INFO", "NOT_APPLICABLE"];

/**
 * Escapes ruleset text for a Markdown table cell or line: the output cannot
 * break the table or become HTML, an inline link, an image or code, and GFM
 * autolinks (scheme://, www., e-mail) are defused with character references.
 */
export function mdCell(value: unknown): string {
  const text = String(value ?? "")
    .replace(/[\r\n\u2028\u2029]+/g, " ")
    .slice(0, MAX_CELL);
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/[\\|[\]`]/g, (c) => `\\${c}`)
    .replace(/:\/\//g, ":&#47;&#47;")
    .replace(/\b(www)\./gi, "$1&#46;")
    .replace(/@/g, "&#64;");
}

export function packFilename(tenantId: string, rulesetVersion: string, ext: "md" | "json"): string {
  const safe = (s: string) => s.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 64) || "unknown";
  return `cloudshield-grc-readiness-${safe(tenantId)}-${safe(rulesetVersion)}.${ext}`;
}

function citations(f: GrcFinding): string {
  return f.citations.map((c) => `${mdCell(c.source)}${c.article ? `, ${mdCell(c.article)}` : ""} (${mdCell(c.status)})`).join("; ");
}

function facts(platformFacts: GrcAssessment["platformFacts"]): string {
  return Object.keys(platformFacts)
    .sort()
    .map((k) => {
      const v = platformFacts[k];
      return `${mdCell(k)}: ${mdCell(Array.isArray(v) ? v.join(", ") : v)}`;
    })
    .join("; ");
}

function byStatus(a: GrcFinding, b: GrcFinding): number {
  return STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status) || a.ruleId.localeCompare(b.ruleId);
}

export function buildReadinessPackMarkdown(assessment: GrcAssessment, ruleset: RulesetSummary, tenantId: string, exportedAt: string): string {
  const applicable = assessment.findings.filter((f) => f.status !== "NOT_APPLICABLE");
  const frameworks = [...new Set(applicable.map((f) => f.framework))].sort();
  const verifyCount = applicable.filter((f) => f.citationStatus === "verify").length;
  const out: string[] = [];

  out.push("# CloudShield Compliance Readiness Pack", "");
  out.push(`> **${PACK_BANNER}**`);
  out.push("> A self-assessment generated in the browser from the CloudShield GRC rules engine. It is not audited and not signed.", "");
  out.push("## Disclaimer", "", `> ${mdCell(assessment.disclaimer)}`, "");

  out.push("## Provenance", "", "| Field | Value |", "|---|---|");
  const rows: [string, string][] = [
    ["Tenant", tenantId],
    ["Ruleset version", assessment.rulesetVersion],
    ["Ruleset SHA-256", assessment.rulesetSha256],
    ["Ruleset last reviewed", ruleset.lastReviewed],
    ["Profile version", String(assessment.profileVersion)],
    ["Assessment generated (server)", assessment.generatedAt],
    ["Pack exported (this browser)", exportedAt],
    ["Format", PACK_FORMAT],
  ];
  for (const [k, v] of rows) out.push(`| ${k} | ${mdCell(v)} |`);
  out.push(`| Platform facts | ${facts(assessment.platformFacts)} |`, "");
  if (ruleset.sha256 !== assessment.rulesetSha256) {
    out.push(`> The ruleset served now (SHA-256 ${mdCell(ruleset.sha256)}) differs from the one this assessment used. Re-run the assessment before relying on the pack.`, "");
  }

  out.push("## Summary", "", "| Status | Count |", "|---|---|");
  for (const s of STATUS_ORDER) out.push(`| ${s} | ${assessment.summary[s]} |`);
  out.push("");
  out.push(`NOT_APPLICABLE findings are counted above but not listed. ${verifyCount} listed finding(s) cite text that has not been checked against the official source; each is marked "${VERIFY_MARKER}".`, "");

  for (const fw of frameworks) {
    out.push(`## ${mdCell(fw)}`, "", "| Status | Rule | Topic | Obligation | Rationale | Controls | Citations | Check |", "|---|---|---|---|---|---|---|---|");
    for (const f of applicable.filter((x) => x.framework === fw).sort(byStatus)) {
      const check = f.citationStatus === "verify" ? VERIFY_MARKER : "";
      out.push(`| ${mdCell(f.status)} | ${mdCell(f.ruleId)} | ${mdCell(f.topic)} | ${mdCell(f.obligation)} | ${mdCell(f.rationale)} | ${f.controls.map(mdCell).join(", ")} | ${citations(f)} | ${check} |`);
    }
    out.push("");
  }

  const actions = applicable.filter((f) => f.status === "CUSTOMER_ACTION").sort(byStatus);
  out.push("## Customer actions", "");
  if (actions.length === 0) out.push("None for this profile.");
  for (const f of actions) out.push(`- **${mdCell(f.ruleId)}** (${mdCell(f.framework)}): ${mdCell(f.obligation)}${f.citationStatus === "verify" ? ` ${VERIFY_MARKER}` : ""}`);
  out.push("");

  const residency = applicable.filter((f) => f.status === "GAP" && RESIDENCY_TOPICS.has(f.topic));
  out.push("## Data residency and transfers", "");
  out.push("Residency and transfer rules report GAP by construction: the platform is deployed in one region only and multi-region deployment is out of the capstone scope. That is the honest output, not a defect in the assessment.");
  if (residency.length > 0) out.push("", `GAP findings affected: ${residency.map((f) => mdCell(f.ruleId)).join(", ")}.`);
  out.push("");

  return out.join("\n");
}

export function buildReadinessPackJson(assessment: GrcAssessment, ruleset: RulesetSummary, tenantId: string, exportedAt: string): string {
  const pack = {
    exportMeta: {
      format: PACK_FORMAT,
      exportedAt,
      tenantId,
      rulesetVersion: assessment.rulesetVersion,
      rulesetSha256: assessment.rulesetSha256,
      rulesetLastReviewed: ruleset.lastReviewed,
      notice: `${PACK_BANNER} Self-assessment generated client-side; not audited and not signed.`,
      disclaimer: assessment.disclaimer,
    },
    assessment,
  };
  return `${JSON.stringify(pack, null, 2)}\n`;
}

/** Blob → object URL → <a download>, as EvidencePanel.downloadReport does. */
export function downloadText(text: string, mime: string, filename: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
