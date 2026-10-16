// SOC read model against moto, with golden parity to soar/tools/generate_ir_report.py
// (soar/tests/fixtures/coc_golden.json) and the ATT&CK triage corpus.
import { readFileSync } from "node:fs";
import path from "node:path";
import { PutObjectCommand } from "@aws-sdk/client-s3";
import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb";
import { api, makeApp, type TestApp } from "./helpers/app";
import { createResources, raw, testConfig, type Resources } from "./helpers/moto";
import { triage } from "../src/soc/triage";
import { buildReport, md, toMarkdown } from "../src/soc/report";
import { computeMetrics, percentile } from "../src/soc/metrics";
import { detail, displayStatus, summary, timeline } from "../src/soc/projection";
import { mttcOf, parseTime } from "../src/soc/time";

const FIXTURES = path.resolve(__dirname, "..", "..", "..", "soar", "tests", "fixtures");
const golden = JSON.parse(readFileSync(path.join(FIXTURES, "coc_golden.json"), "utf8"));
const corpus = JSON.parse(readFileSync(path.join(FIXTURES, "triage_corpus.json"), "utf8"));
const ddb = DynamoDBDocumentClient.from(raw.ddb);

let r: Resources;
let t: TestApp;
const now = new Date();
const iso = (msAgo: number) => new Date(now.getTime() - msAgo).toISOString();

async function putIncident(row: Record<string, unknown>) {
  await ddb.send(new PutCommand({ TableName: r.incidentsTable, Item: row }));
}

beforeAll(async () => {
  r = await createResources({ objectLock: true });
  t = await makeApp(testConfig(r));
});

describe("golden chain-of-custody parity with the Python IR tool", () => {
  const goldenCases: [string, any][] = golden.cases.map((c: { name: string }) => [c.name, c]);
  it.each(goldenCases)("%s", async (_name: string, c: any) => {
    const versionIds: Record<string, string[]> = {};
    for (const o of c.objects) {
      versionIds[o.key] = [];
      for (const body of o.versions) {
        const out = await raw.s3.send(new PutObjectCommand({ Bucket: r.evidenceBucket, Key: `${o.key}`, Body: body }));
        versionIds[o.key]!.push(out.VersionId!);
      }
    }
    const records = c.records.map((rec: any) => ({
      bucket: r.evidenceBucket,
      key: rec.key,
      ...(rec.version !== null ? { versionId: versionIds[rec.key]![rec.version] } : {}),
      sha256: rec.sha256,
      sha256Base64: rec.sha256Base64,
    }));
    const incidentId = `${c.row.incidentId}-${r.suffix}`;
    await putIncident({ ...c.row, incidentId, evidenceRecords: records });
    const { auth } = await t.as("sam");
    const report = (await api(t).get(`/soc/incidents/${incidentId}/report`).set(...auth).expect(200)).body;
    const expected = c.expected.evidence.map((e: any) => ({
      ...e,
      version_id: typeof e.version_id === "string" && e.version_id.startsWith("$version:") ? versionIds[e.key]![Number(e.version_id.split(":")[1])] : e.version_id,
    }));
    expect(report.evidence).toEqual(expected);
    expect(report.chain_of_custody_ok).toBe(c.expected.chain_of_custody_ok);
    expect(report.mttc_seconds).toBe(c.expected.mttc_seconds);
    const ev = (await api(t).get(`/soc/incidents/${incidentId}/evidence`).set(...auth).expect(200)).body;
    expect(ev.chainOfCustodyOk).toBe(c.expected.chain_of_custody_ok);
    expect(ev.objectLock.enabled).toBe(true);
  });
});

describe("triage parity with soar/core/attack.py", () => {
  const corpusCases: [string, any][] = corpus.cases.map((c: any) => [String(c.findingType).slice(0, 60), c]);
  it.each(corpusCases)("%s", (_n: string, c: any) => {
    expect(triage(c.findingType)).toEqual(c.expected);
  });
});

describe("SOC API", () => {
  beforeAll(async () => {
    const base = { findingCreatedAt: iso(70_000), severity: 8 };
    await putIncident({ ...base, incidentId: `a-${r.suffix}`, status: "CONTAINED", findingType: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", eventTime: iso(60_000), containedAt: iso(42_000), actions: [{ at: iso(50_000), playbook: "PB-01", step: "isolate", extra: { sg: "sg-1" } }], secretColumn: "leak" });
    await putIncident({ ...base, incidentId: `b-${r.suffix}`, status: "CONTAINED", findingType: "UnauthorizedAccess:IAMUser/MaliciousIPCaller", eventTime: iso(120_000), containedAt: iso(30_000) });
    await putIncident({ ...base, incidentId: `d-${r.suffix}`, status: "WOULD_CONTAIN_DRY_RUN", findingType: "Execution:Runtime/NewBinaryExecuted", eventTime: iso(200_000), wouldContainAt: iso(190_000) });
    await putIncident({ ...base, incidentId: `edge-decoy-203-0-113-9-${now.toISOString().slice(0, 13).replace(/[-T]/g, "")}`, status: "BLOCKED_BY_GUARD", findingType: "CloudShield:IPAddress/DecoyRouteHit", guardReason: "notify-only edge finding (decoy route hit): analyst review", eventTime: iso(5_000) });
    await putIncident({ ...base, incidentId: `f-${r.suffix}`, status: "FAILED", findingType: "Policy:S3/BucketBlockPublicAccessDisabled", eventTime: iso(300_000), failure: "AccessDenied" });
    await putIncident({ ...base, incidentId: `n-${r.suffix}`, status: "NO_PLAYBOOK_ANALYST_REVIEW", findingType: "Trojan:EC2/DNSDataExfiltration", eventTime: iso(400_000) });
    await putIncident({ ...base, incidentId: `p-${r.suffix}`, status: "DETECTED", findingType: "Recon:EC2/Portscan", eventTime: iso(1_000) });
    await putIncident({ ...base, incidentId: `e-${r.suffix}`, status: "CONTAINED", findingType: "CloudShield:IPAddress/WafRateLimitExceeded", eventTime: iso(500_000), containedAt: iso(480_000), blockedCidr: "203.0.113.5/32", blockState: "active", blockExpiresAt: iso(-3_600_000) });
  });

  it("serves the overview from one Query per status and never Scans", async () => {
    const spy = jest.spyOn(t.deps.services.soc as any, "overview");
    const send = jest.spyOn(DynamoDBDocumentClient.prototype, "send");
    const { auth } = await t.as("sam");
    const res = await api(t).get("/soc/overview").set(...auth).expect(200);
    const names = send.mock.calls.map((c) => (c[0] as object).constructor.name);
    expect(names).not.toContain("ScanCommand");
    expect(names.filter((n) => n === "QueryCommand").length).toBeGreaterThanOrEqual(6);
    send.mockRestore();
    spy.mockRestore();
    const ids = res.body.incidents.map((i: { incidentId: string }) => i.incidentId);
    expect(ids).toContain(`a-${r.suffix}`);
    const decoy = res.body.incidents.find((i: { findingType: string }) => i.findingType === "CloudShield:IPAddress/DecoyRouteHit");
    expect(decoy.displayStatus).toBe("Decoy hit: notify only");
    expect(res.body.incidents.find((i: { status: string }) => i.status === "DETECTED").displayStatus).toBe("In progress");
    expect(res.body.metrics.byStatus.CONTAINED).toBeGreaterThanOrEqual(3);
    expect(res.body.metrics.mttc.targetSeconds).toBe(60);
    // eventTime desc
    const times = res.body.incidents.map((i: { eventTime: string }) => i.eventTime);
    expect([...times].sort().reverse()).toEqual(times);
  });

  it("projects only allow-listed attributes and computes MTTC like the Python report", async () => {
    const { auth } = await t.as("sam");
    const res = await api(t).get(`/soc/incidents/a-${r.suffix}`).set(...auth).expect(200);
    expect(JSON.stringify(res.body)).not.toContain("leak");
    expect(res.body.mttcSeconds).toBe(18);
    expect(res.body.triage.techniques).toEqual(["T1552.005"]);
    expect(res.body.timeline.map((e: { kind: string }) => e.kind)).toEqual(["DETECTED", "GUARD", "ACTION", "CONTAINED"]);
    expect(res.body.actions[0].details).toContain("sg-1");
    const e = await api(t).get(`/soc/incidents/e-${r.suffix}`).set(...auth).expect(200);
    expect(e.body.block).toMatchObject({ blockedCidr: "203.0.113.5/32", blockState: "active" });
    const d = await api(t).get(`/soc/incidents/d-${r.suffix}`).set(...auth).expect(200);
    expect(d.body.mttcSeconds).toBeNull();
    await api(t).get("/soc/incidents/does-not-exist").set(...auth).expect(404);
  });

  it("correlates a decoy incident with its _platform audit events", async () => {
    const { auth } = await t.as("sam");
    await api(t).get("/admin").set("CloudFront-Viewer-Address", "203.0.113.9:1").expect(403);
    const id = `edge-decoy-203-0-113-9-${new Date().toISOString().slice(0, 13).replace(/[-T]/g, "")}`;
    const res = await api(t).get(`/soc/incidents/${id}`).set(...auth).expect(200);
    expect(res.body.notifyOnly).toBe(true);
    expect(res.body.relatedAudit.length).toBeGreaterThanOrEqual(1);
    expect(res.body.relatedAudit[0].action).toBe("DECOY_ROUTE_HIT");
    const audit = await api(t).get("/soc/audit?limit=100").set(...auth).expect(200);
    expect(audit.body.items.some((x: { action: string }) => x.action === "DECOY_ROUTE_HIT")).toBe(true);
  });

  it("paginates one status with a validated cursor", async () => {
    const { auth } = await t.as("sam");
    const first = await api(t).get("/soc/incidents?status=CONTAINED&limit=1").set(...auth).expect(200);
    expect(first.body.items).toHaveLength(1);
    const second = await api(t).get(`/soc/incidents?status=CONTAINED&limit=1&cursor=${first.body.nextCursor}`).set(...auth).expect(200);
    expect(second.body.items[0].incidentId).not.toBe(first.body.items[0].incidentId);
    const other = await api(t).get(`/soc/incidents?status=FAILED&cursor=${first.body.nextCursor}`).set(...auth).expect(200);
    expect(other.body.items).toEqual([]);
  });

  it("exports Markdown as an attachment with no raw HTML", async () => {
    await putIncident({ incidentId: `x-${r.suffix}`, status: "FAILED", findingType: "<script>alert(1)</script>", failure: "<img src=x onerror=alert(1)>|`", eventTime: iso(10) });
    const { auth } = await t.as("sam");
    const res = await api(t).get(`/soc/incidents/x-${r.suffix}/report?format=md`).set(...auth).expect(200);
    expect(res.headers["content-disposition"]).toBe(`attachment; filename="ir-x-${r.suffix}.md"`);
    expect(res.headers["content-type"]).toMatch(/^text\/markdown/);
    expect(res.text).not.toMatch(/<script|<img/);
    expect(res.text).toContain("&lt;script&gt;");
    expect(res.text).toContain("Live verification view generated by docs-api");
  });

  it("reports metrics per window and posture with honest wording", async () => {
    const { auth } = await t.as("sam");
    const m = await api(t).get("/soc/metrics?window=7d").set(...auth).expect(200);
    expect(m.body.window).toBe("7d");
    const p = await api(t).get("/soc/posture").set(...auth).expect(200);
    expect(p.body.imagePolicy).toContain("no fixable CRITICAL/HIGH vulnerabilities at scan time");
    expect(p.body.image).toEqual({ reference: null, ecrScan: null });
    expect(p.body.build.local).toBe(true);
    expect(p.body.containment).toMatchObject({ playbooksEnabled: true, dryRun: true, targetSeconds: 60 });
    expect(JSON.stringify(p.body).toLowerCase()).not.toContain("no vulnerabilities");
  });

  it("answers 503 on SOC routes when the integration is not configured", async () => {
    const off = await makeApp(testConfig(r, { soc: undefined }));
    const { auth } = await off.as("sam");
    await api(off).get("/soc/overview").set(...auth).expect(503);
    const p = await api(off).get("/soc/posture").set(...auth).expect(200);
    expect(p.body.containment.failedLast24h).toBeNull();
  });
});

describe("report, projection and metrics helpers", () => {
  it("escape Markdown and mirror the Python fields", () => {
    expect(md(null)).toBe("—");
    expect(md("a|b`<c>&\n")).toBe("a\\|b'&lt;c&gt;&amp; ");
    const row = { incidentId: "i", status: "CONTAINED", eventTime: "2026-10-14T10:00:00.000Z", containedAt: "2026-10-14T10:01:30.000Z", findingCreatedAt: "2026-10-14T09:59:00.000Z", containmentVerified: true, severity: 5, guardReason: "g", actions: [{ at: "t", playbook: "PB", step: "s" }] };
    const r = buildReport(row, [], null);
    expect(r).toMatchObject({ mttc_seconds: 90, mttc_target_met: false, detection_latency_seconds: 60, containment_verified: true });
    expect(r.executive_summary.mttc_verdict).toBe("MISSED: 90.000 s against the 60 s target");
    const text = toMarkdown(r);
    expect(text).toContain("No evidence recorded");
    expect(text).toContain("Safety guard decision");
    expect(toMarkdown(buildReport({ incidentId: "j", status: "FAILED", failure: "f" }, [{ key: "k", versionId: null, recordedSha256: "a", actualSha256: null, ok: false, error: null, retention: null, legalHold: null }], false))).toContain("**BROKEN**");
    expect(toMarkdown(buildReport({ incidentId: "j", status: "X" }, [{ key: "k", versionId: null, recordedSha256: "a", actualSha256: "a", ok: true, error: null, retention: null, legalHold: null }], null))).toContain("not fully verified");
  });

  it("parse time like the Python tool (timezone-aware only)", () => {
    expect(parseTime("2026-10-14T10:00:00")).toBeNull();
    expect(parseTime("2026-10-14T10:00:00+02:00")).toBe(Date.parse("2026-10-14T08:00:00Z"));
    expect(mttcOf({ status: "WOULD_CONTAIN_DRY_RUN", eventTime: "2026-10-14T10:00:00Z", containedAt: "2026-10-14T10:00:01Z" })).toBeNull();
  });

  it("label every status and build timelines for each", () => {
    for (const status of ["DETECTED", "CONTAINED", "WOULD_CONTAIN_DRY_RUN", "BLOCKED_BY_GUARD", "NO_PLAYBOOK_ANALYST_REVIEW", "FAILED", "WEIRD"]) {
      expect(displayStatus({ status })).toBeTruthy();
      expect(timeline({ status, eventTime: "x", evidenceRecords: [{ key: "incidents/a" }, "junk"], failure: "f", guardReason: "g", actions: ["junk", { at: "b" }, { at: "a" }] }).length).toBeGreaterThan(1);
    }
    expect(summary({ incidentId: "i", status: "CONTAINED", severity: Infinity }).severity).toBeNull();
    expect(detail({ incidentId: "i" }).block).toBeNull();
  });

  it("compute percentiles and tactic breakdowns", () => {
    expect(percentile([], 50)).toBeNull();
    expect(percentile([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 90)).toBe(9);
    const m = computeMetrics(
      [
        { status: "CONTAINED", eventTime: "2026-10-14T10:00:00Z", containedAt: "2026-10-14T10:00:10Z", findingType: "Recon:EC2/Portscan" },
        { status: "CONTAINED", eventTime: "2026-10-14T10:00:00Z", containedAt: "2026-10-14T10:00:30Z", findingType: "Recon:EC2/Portscan" },
        { status: "FAILED", findingType: null },
        { status: "WEIRD" },
      ],
      "24h",
      "s",
      false,
    );
    expect(m.mttc).toMatchObject({ samples: 2, last: 30, p50: 10, p90: 30, max: 30 });
    expect(m.byTactic[0]).toEqual({ tactic: "Discovery", count: 2, techniques: ["T1046"] });
    expect(m.byStatus.FAILED).toBe(1);
  });
});
