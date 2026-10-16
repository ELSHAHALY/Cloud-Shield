import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { evidence, incident, metrics, posture } from "../test/fixtures";
import { fakeApi } from "../test/render";
import { chainLabel, downloadReport, EvidencePanel, lockLabel } from "./EvidencePanel";
import { IncidentsTable } from "./IncidentsTable";
import { MitreBreakdown } from "./MitreBreakdown";
import { MttcMeter, mttcVerdict } from "./MttcMeter";
import { PostureBanner } from "./PostureBanner";
import { SoarTimeline } from "./SoarTimeline";

describe("PostureBanner", () => {
  it("shows the real gate outcomes as text and the exact image policy", () => {
    render(<PostureBanner posture={posture()} />);
    for (const t of ["secrets: success", "sast: failure", "sca: skipped", "app: unknown"]) expect(screen.getByText(t)).toBeInTheDocument();
    expect(screen.getByTestId("image-policy").textContent).toBe("CI pushes to ECR only when Trivy reports no fixable CRITICAL/HIGH vulnerabilities at scan time (audit A9).");
    expect(screen.getByTestId("ecr-scan").textContent).toContain("0 critical, 1 high");
    expect(screen.getByText(/Gates were enforced/)).toBeInTheDocument();
  });

  it("never claims a clean image when the scan is unavailable, and labels local builds", () => {
    const p = posture({ image: { reference: null, ecrScan: null }, build: { ...posture().build, local: true, commit: "local", gatesEnforced: false } });
    p.containment = { ...p.containment, dryRun: null, lastMttcSeconds: null, failedLast24h: null };
    const { container } = render(<PostureBanner posture={p} />);
    expect(screen.getByTestId("ecr-scan").textContent).toContain("Live ECR scan: unavailable");
    expect(container.textContent!.toLowerCase()).not.toMatch(/no vulnerabilities|clean|secure image/);
    expect(screen.getByTestId("build-local")).toBeInTheDocument();
    expect(screen.getByText(/fail-open/)).toBeInTheDocument();
    expect(screen.getByText(/unknown \(switch not readable\)/)).toBeInTheDocument();
  });
});

describe("MttcMeter", () => {
  it("classifies against the 60 s target with an aria sentence", () => {
    expect(mttcVerdict(null, 60)).toBe("none");
    expect(mttcVerdict(60, 60)).toBe("within");
    expect(mttcVerdict(61, 60)).toBe("over");
    expect(mttcVerdict(500, 60)).toBe("far");
    render(<MttcMeter mttc={metrics().mttc} />);
    expect(screen.getByRole("img").getAttribute("aria-label")).toBe("Last MTTC 18.0 s, target 60 s: within target. Median 18.0 s, 90th percentile 40.0 s, 3 samples.");
    expect(screen.getByTestId("mttc-target").getAttribute("x1")).toBe("150");
  });
  it("handles no samples and clamps the bar", () => {
    const { rerender } = render(<MttcMeter mttc={{ targetSeconds: 60, samples: 0, last: null, p50: null, p90: null, max: null }} />);
    expect(screen.getByRole("img").getAttribute("aria-label")).toContain("no contained incidents");
    rerender(<MttcMeter mttc={{ targetSeconds: 60, samples: 1, last: 999, p50: 999, p90: 999, max: 999 }} />);
    expect(screen.getByTestId("mttc-bar").getAttribute("width")).toBe("280");
    expect(screen.getByRole("img").getAttribute("aria-label")).toContain("far over target");
  });
});

describe("MitreBreakdown", () => {
  it("draws one bar per tactic with technique ids", () => {
    render(<MitreBreakdown byTactic={metrics().byTactic} />);
    expect(screen.getByRole("img").getAttribute("aria-label")).toContain("Credential Access 2");
    expect(screen.getByText(/T1552.005/)).toBeInTheDocument();
  });
  it("says so when empty", () => {
    render(<MitreBreakdown byTactic={[]} />);
    expect(screen.getByText("No incidents in the window.")).toBeInTheDocument();
  });
});

describe("IncidentsTable", () => {
  const rows = [
    incident({ incidentId: "a", eventTime: "2026-10-16T10:00:00Z", severity: 2 }),
    incident({ incidentId: "decoy", status: "BLOCKED_BY_GUARD", displayStatus: "Decoy hit: notify only", eventTime: "2026-10-16T12:00:00Z", severity: 5, mttcSeconds: null }),
    incident({ incidentId: "p", status: "DETECTED", displayStatus: "In progress", eventTime: "2026-10-16T11:00:00Z", severity: 8, mttcSeconds: null }),
  ];
  const ids = () => screen.getAllByRole("row").slice(1).map((r) => within(r).getAllByRole("cell")[0]!.textContent);

  it("sorts by time (newest first) and severity, filters by status, and labels with text", () => {
    render(<MemoryRouter><IncidentsTable incidents={rows} /></MemoryRouter>);
    expect(ids()).toEqual(["2026-10-16T12:00:00Z", "2026-10-16T11:00:00Z", "2026-10-16T10:00:00Z"]);
    expect(screen.getByText("Decoy hit: notify only")).toBeInTheDocument();
    expect(screen.getByText("In progress")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Severity/ }));
    expect(screen.getAllByRole("row")[1]!.textContent).toContain("In progress");
    fireEvent.click(screen.getByRole("button", { name: /Severity/ }));
    expect(screen.getAllByRole("row")[1]!.textContent).toContain("2");
    fireEvent.click(screen.getByRole("button", { name: /Event time/ }));
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "BLOCKED_BY_GUARD" } });
    expect(screen.getAllByRole("row")).toHaveLength(2);
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "FAILED" } });
    expect(screen.getByText("No incidents.")).toBeInTheDocument();
  });
});

describe("SoarTimeline", () => {
  it("renders each step kind with its detail", () => {
    render(<SoarTimeline entries={[{ at: "t1", kind: "DETECTED", label: "Received" }, { at: null, kind: "GUARD", label: "Guard: notify only", detail: "notify-only edge finding" }, { at: "t2", kind: "ACTION", label: "PB-05: block" }, { at: null, kind: "FAILED", label: "Failed", detail: "AccessDenied" }, { at: null, kind: "WOULD_CONTAIN", label: "dry" }, { at: null, kind: "EVIDENCE", label: "Evidence recorded", detail: "incidents/x" }, { at: null, kind: "ANALYST", label: "review" }, { at: "t3", kind: "CONTAINED", label: "Contained" }]} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(8);
    expect(screen.getByText("notify-only edge finding")).toBeInTheDocument();
    expect(screen.getByText("Would contain (dry run)")).toBeInTheDocument();
  });
});

describe("EvidencePanel", () => {
  it("shows a BROKEN chain, Object Lock off and expands full hashes", async () => {
    const api = fakeApi({ "GET /soc/incidents/inc-1/evidence": evidence() });
    render(<EvidencePanel api={api} incidentId="inc-1" />);
    fireEvent.click(screen.getByRole("button", { name: "Verify evidence" }));
    expect(await screen.findByText("Chain of custody: BROKEN")).toBeInTheDocument();
    expect(screen.getByText("Object Lock not enabled on the evidence bucket")).toBeInTheDocument();
    expect(screen.getByText("✗ mismatch")).toBeInTheDocument();
    expect(screen.getByText(/GOVERNANCE until 2026-10-17T00:00:00.000Z · legal hold/)).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole("button", { name: "Full hash" })[0]!);
    expect(screen.getByText("c".repeat(64))).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Shorten" }));
  });

  it("labels lock on/unknown and every chain state", () => {
    expect(lockLabel({ enabled: true, mode: "GOVERNANCE", days: 1 })).toBe("Object Lock enabled: GOVERNANCE, default 1 day(s)");
    expect(lockLabel({ enabled: null, mode: null, days: null })).toContain("could not be read");
    expect(chainLabel(evidence({ chainOfCustodyOk: true })).text).toBe("Chain of custody: intact");
    expect(chainLabel(evidence({ chainOfCustodyOk: null, truncated: true })).tone).toBe("warn");
    expect(chainLabel(evidence({ chainOfCustodyOk: null, checks: [] })).text).toBe("No evidence recorded");
  });

  it("downloads the IR report through the API as a blob (bearer), never rendering it", async () => {
    const blob = new Blob(["# report <script>"], { type: "text/markdown" });
    const api = fakeApi({ "GET /soc/incidents/inc-1/report": blob });
    const create = vi.fn(() => "blob:x");
    const revoke = vi.fn();
    Object.assign(URL, { createObjectURL: create, revokeObjectURL: revoke });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    render(<EvidencePanel api={api} incidentId="inc-1" />);
    fireEvent.click(screen.getByRole("button", { name: "Download report (Markdown)" }));
    await waitFor(() => expect(click).toHaveBeenCalled());
    expect(api.get).toHaveBeenCalledWith("/soc/incidents/inc-1/report?format=md", "blob");
    expect(revoke).toHaveBeenCalledWith("blob:x");
    expect(document.body.innerHTML).not.toContain("<script>");
    await downloadReport(api, "inc-1", "json").catch(() => undefined);
  });

  it("shows API errors", async () => {
    const api = fakeApi({});
    render(<EvidencePanel api={api} incidentId="inc-1" />);
    fireEvent.click(screen.getByRole("button", { name: "Verify evidence" }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "JSON" }));
  });
});
