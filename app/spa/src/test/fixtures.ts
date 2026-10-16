import type { EvidenceVerification, IncidentDetail, IncidentSummary, Posture, SocMetrics } from "../api/types";

export const posture = (o: Partial<Posture> = {}): Posture => ({
  generatedAt: "2026-10-16T12:00:00.000Z",
  build: { commit: "a".repeat(40), builtAt: "2026-10-16T10:00:00Z", ciRunId: "42", local: false, gates: { secrets: "success", sast: "failure", sca: "skipped", app: "unknown" }, gatesEnforced: true },
  imagePolicy: "CI pushes to ECR only when Trivy reports no fixable CRITICAL/HIGH vulnerabilities at scan time (audit A9).",
  image: { reference: "123456789012.dkr.ecr.us-east-1.amazonaws.com/r@sha256:" + "b".repeat(64), ecrScan: { status: "COMPLETE", critical: 0, high: 1, medium: 2, low: 3, completedAt: "2026-10-16T11:00:00.000Z" } },
  containment: { playbooksEnabled: true, dryRun: false, failedLast24h: 1, lastMttcSeconds: 18.4, targetSeconds: 60 },
  ...o,
});

export const metrics = (o: Partial<SocMetrics> = {}): SocMetrics => ({
  window: "24h",
  since: "2026-10-15T12:00:00.000Z",
  mttc: { targetSeconds: 60, samples: 3, last: 18, p50: 18, p90: 40, max: 40 },
  byStatus: { DETECTED: 1, CONTAINED: 3, WOULD_CONTAIN_DRY_RUN: 1, BLOCKED_BY_GUARD: 1, NO_PLAYBOOK_ANALYST_REVIEW: 0, FAILED: 1 },
  byTactic: [
    { tactic: "Credential Access", count: 2, techniques: ["T1552.005"] },
    { tactic: "Discovery", count: 1, techniques: ["T1046"] },
  ],
  truncated: false,
  ...o,
});

export const incident = (o: Partial<IncidentSummary> = {}): IncidentSummary => ({
  incidentId: "inc-1",
  status: "CONTAINED",
  displayStatus: "Contained",
  findingType: "Recon:EC2/Portscan",
  severity: 5,
  eventTime: "2026-10-16T10:00:00.000Z",
  containedAt: "2026-10-16T10:00:18.000Z",
  mttcSeconds: 18,
  scenario: "A-recon",
  tactic: "Discovery",
  ...o,
});

export const detail = (o: Partial<IncidentDetail> = {}): IncidentDetail => ({
  incidentId: "inc-1",
  status: "CONTAINED",
  displayStatus: "Contained",
  notifyOnly: false,
  findingType: "Recon:EC2/Portscan",
  severity: 5,
  resourceType: "Instance",
  eventTime: "2026-10-16T10:00:00.000Z",
  firstEventTime: null,
  findingCreatedAt: null,
  sfnStartedAt: null,
  containedAt: "2026-10-16T10:00:18.000Z",
  wouldContainAt: null,
  attempts: 1,
  mttcSeconds: 18,
  triage: { scenario: "A-recon", techniques: ["T1046"], tactic: "Discovery", impact: "Scan", eradication: ["Find the scanner"], recovery: ["Replace the instance"], references: [] },
  timeline: [
    { at: "2026-10-16T10:00:00.000Z", kind: "DETECTED", label: "Finding received (MTTC start)" },
    { at: null, kind: "GUARD", label: "Guard allowed the playbook" },
    { at: "2026-10-16T10:00:05.000Z", kind: "ACTION", label: "PB-01: isolate", detail: '{"sg":"sg-1"}' },
    { at: "2026-10-16T10:00:18.000Z", kind: "CONTAINED", label: "Contained (MTTC stop)" },
  ],
  guardReason: null,
  failure: null,
  actions: [],
  evidenceRecords: [],
  executionArn: "arn:aws:states:us-east-1:123456789012:execution:x:y",
  block: null,
  relatedAudit: [],
  ...o,
});

export const evidence = (o: Partial<EvidenceVerification> = {}): EvidenceVerification => ({
  incidentId: "inc-1",
  verifiedAt: "2026-10-16T12:00:00.000Z",
  chainOfCustodyOk: false,
  objectLock: { enabled: false, mode: null, days: null },
  checks: [
    { key: "incidents/inc-1/a.json", versionId: "v1", recordedSha256: "c".repeat(64), actualSha256: "c".repeat(64), ok: true, error: null, retention: null, legalHold: null },
    { key: "incidents/inc-1/b.json", versionId: null, recordedSha256: "d".repeat(64), actualSha256: "e".repeat(64), ok: false, error: "mismatch", retention: { mode: "GOVERNANCE", retainUntil: "2026-10-17T00:00:00.000Z" }, legalHold: true },
  ],
  truncated: false,
  label: "Live verification view: SHA-256 recomputed from S3 by docs-api",
  ...o,
});
