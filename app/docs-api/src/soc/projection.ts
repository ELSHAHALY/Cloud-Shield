// Allow-listed projections of incident rows (plan §7.2). Unknown attributes
// never leave the API; strings are truncated to 2 KiB.
import { DECOY_FINDING_TYPE } from "../decoy/router";
import { triage } from "./triage";
import { mttcOf } from "./time";
import type { Row } from "./repository";

const MAX = 2048;

export function str(v: unknown, max = MAX): string | null {
  return typeof v === "string" ? v.slice(0, max) : null;
}

export function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

export function isNotifyOnly(row: Row): boolean {
  return row.findingType === DECOY_FINDING_TYPE || (typeof row.guardReason === "string" && row.guardReason.startsWith("notify-only"));
}

const DISPLAY: Readonly<Record<string, string>> = {
  DETECTED: "In progress",
  CONTAINED: "Contained",
  WOULD_CONTAIN_DRY_RUN: "Would contain (dry run)",
  BLOCKED_BY_GUARD: "Blocked by guard",
  NO_PLAYBOOK_ANALYST_REVIEW: "Analyst review (no playbook)",
  FAILED: "Failed",
};

export function displayStatus(row: Row): string {
  const status = String(row.status ?? "UNKNOWN");
  if (status === "BLOCKED_BY_GUARD" && isNotifyOnly(row)) return "Decoy hit: notify only";
  return Object.prototype.hasOwnProperty.call(DISPLAY, status) ? DISPLAY[status]! : status.slice(0, 64);
}

export function summary(row: Row) {
  const t = triage(row.findingType);
  return {
    incidentId: String(row.incidentId).slice(0, 128),
    status: String(row.status ?? "UNKNOWN").slice(0, 64),
    displayStatus: displayStatus(row),
    findingType: str(row.findingType),
    severity: num(row.severity),
    eventTime: str(row.eventTime, 40),
    containedAt: row.status === "CONTAINED" ? str(row.containedAt, 40) : null,
    mttcSeconds: mttcOf(row),
    scenario: t.scenario,
    tactic: t.tactic,
  };
}

export interface EvidenceRecord {
  bucket: string | null;
  key: string;
  versionId: string | null;
  sha256: string | null;
  sha256Base64: string | null;
}

export function evidenceRecords(row: Row): EvidenceRecord[] {
  const list = Array.isArray(row.evidenceRecords) ? row.evidenceRecords : [];
  return list
    .filter((r): r is Record<string, unknown> => r !== null && typeof r === "object" && !Array.isArray(r))
    .slice(0, 50)
    .map((r) => ({
      bucket: str(r.bucket, 255),
      key: str(r.key) ?? "",
      versionId: str(r.versionId, 1024),
      sha256: str(r.sha256, 64),
      sha256Base64: str(r.sha256Base64, 64),
    }));
}

export function actions(row: Row) {
  const list = Array.isArray(row.actions) ? row.actions : [];
  return list
    .filter((a): a is Record<string, unknown> => a !== null && typeof a === "object" && !Array.isArray(a))
    .sort((a, b) => String(a.at ?? "").localeCompare(String(b.at ?? "")))
    .slice(0, 50)
    .map((a) => {
      const rest: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(a)) if (k !== "at" && k !== "playbook" && k !== "step") rest[k] = v;
      return {
        at: str(a.at, 40),
        playbook: str(a.playbook, 64),
        step: str(a.step, 256),
        ...(Object.keys(rest).length > 0 ? { details: JSON.stringify(rest).slice(0, MAX) } : {}),
      };
    });
}

type TimelineKind = "DETECTED" | "GUARD" | "ACTION" | "CONTAINED" | "WOULD_CONTAIN" | "FAILED" | "EVIDENCE" | "ANALYST";

export function timeline(row: Row) {
  const out: { at: string | null; kind: TimelineKind; label: string; detail?: string }[] = [];
  const status = row.status;
  out.push({ at: str(row.eventTime, 40), kind: "DETECTED", label: "Finding received (MTTC start)", ...(row.findingCreatedAt ? { detail: `GuardDuty createdAt ${String(row.findingCreatedAt).slice(0, 40)}` } : {}) });
  if (status === "BLOCKED_BY_GUARD") {
    out.push({ at: str(row.sfnStartedAt, 40), kind: "GUARD", label: isNotifyOnly(row) ? "Guard: notify only (decoy route hit)" : "Guard refused the playbook", ...(row.guardReason ? { detail: str(row.guardReason)! } : {}) });
  } else if (status === "CONTAINED" || status === "WOULD_CONTAIN_DRY_RUN" || status === "FAILED") {
    out.push({ at: str(row.sfnStartedAt, 40), kind: "GUARD", label: "Guard allowed the playbook" });
  }
  for (const a of actions(row)) {
    out.push({ at: a.at, kind: "ACTION", label: `${a.playbook ?? "playbook"}: ${a.step ?? "step"}`, ...(a.details ? { detail: a.details } : {}) });
  }
  if (status === "CONTAINED") out.push({ at: str(row.containedAt, 40), kind: "CONTAINED", label: "Contained (MTTC stop)" });
  if (status === "WOULD_CONTAIN_DRY_RUN") out.push({ at: str(row.wouldContainAt, 40), kind: "WOULD_CONTAIN", label: "Would have contained (dry run: no change made)" });
  if (status === "FAILED") out.push({ at: null, kind: "FAILED", label: "Playbook failed", ...(row.failure ? { detail: str(row.failure)! } : {}) });
  if (status === "NO_PLAYBOOK_ANALYST_REVIEW") out.push({ at: null, kind: "ANALYST", label: "No playbook for this type: analyst review" });
  if (status === "DETECTED") out.push({ at: null, kind: "ANALYST", label: "In progress" });
  for (const e of evidenceRecords(row)) out.push({ at: null, kind: "EVIDENCE", label: "Evidence recorded", detail: e.key });
  return out.slice(0, 100);
}

export function detail(row: Row, relatedAudit: unknown[] = []) {
  const t = triage(row.findingType);
  const hasBlock = row.blockedCidr !== undefined || row.blockState !== undefined || row.blockExpiresAt !== undefined;
  return {
    incidentId: String(row.incidentId).slice(0, 128),
    status: String(row.status ?? "UNKNOWN").slice(0, 64),
    displayStatus: displayStatus(row),
    notifyOnly: isNotifyOnly(row),
    findingType: str(row.findingType),
    severity: num(row.severity),
    resourceType: str(row.resourceType, 64),
    eventTime: str(row.eventTime, 40),
    firstEventTime: str(row.firstEventTime, 40),
    findingCreatedAt: str(row.findingCreatedAt, 40),
    sfnStartedAt: str(row.sfnStartedAt, 40),
    containedAt: str(row.containedAt, 40),
    wouldContainAt: str(row.wouldContainAt, 40),
    attempts: num(row.attempts),
    mttcSeconds: mttcOf(row),
    triage: { scenario: t.scenario, techniques: t.attack_techniques, tactic: t.tactic, impact: t.impact, eradication: t.eradication, recovery: t.recovery, references: t.references },
    timeline: timeline(row),
    guardReason: str(row.guardReason),
    failure: str(row.failure),
    actions: actions(row),
    evidenceRecords: evidenceRecords(row),
    executionArn: str(row.executionArn),
    block: hasBlock ? { blockedCidr: str(row.blockedCidr, 64), blockState: str(row.blockState, 32), blockExpiresAt: str(row.blockExpiresAt, 40) } : null,
    relatedAudit,
  };
}
