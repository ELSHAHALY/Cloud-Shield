// Regression tests for the UI redesign's security review (feat/ui-cyber-redesign):
// the screen must never overstate a security state.
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { makeCan, SessionContext } from "./auth/session";
import { ROLES } from "./auth/roles";
import { Layout } from "./components/Layout";
import { DocumentsPage } from "./portal/DocumentsPage";
import { EvidencePanel } from "./soc/EvidencePanel";
import { SocDashboard } from "./soc/SocDashboard";
import { evidence, incident, metrics, posture } from "./test/fixtures";
import { fakeApi, meFor, PERMS, renderWithSession } from "./test/render";

describe("shell in a deployed (cognito) build", () => {
  it("never offers the local persona switch or the local dev badge", () => {
    const me = meFor("admin");
    render(
      <MemoryRouter>
        <SessionContext.Provider value={{ me, api: fakeApi({}), backend: { mode: "cognito", getIdToken: async () => "t", signOut: async () => undefined, LoginForm: () => null }, can: makeCan(me), signOut: vi.fn() }}>
          <Layout>x</Layout>
        </SessionContext.Provider>
      </MemoryRouter>,
    );
    expect(screen.queryByRole("button", { name: /Switch persona/ })).toBeNull();
    expect(screen.queryByText("local dev")).toBeNull();
    expect(screen.getByRole("button", { name: "Sign out" })).toBeInTheDocument();
  });
});

describe("role badges mirror the server RBAC table", () => {
  it("covers every permission family each role really has", () => {
    // PERMS is the test copy of docs-api ROLE_PERMISSIONS.
    const family = (p: string) => ({ doc: "docs", audit: "audit", agreement: "agreements", grc: "GRC", soc: "SOC", posture: "posture" })[p.split(":")[0]!]!;
    for (const [role, perms] of Object.entries(PERMS)) {
      const text = ROLES[role]!.badges.join(" ");
      for (const p of perms) expect(text, `${role} ${p}`).toContain(p === "soc:evidence" ? "evidence" : family(p));
    }
    expect(ROLES.member!.badges.join(" ")).toContain("(own)");
  });
});

describe("evidence retention chip", () => {
  async function chipFor(objectLock: { enabled: boolean | null; mode: string | null; days: number | null }) {
    const api = fakeApi({ "GET /soc/incidents/inc-1/evidence": evidence({ objectLock }) });
    const view = render(<EvidencePanel api={api} incidentId="inc-1" />);
    fireEvent.click(screen.getByRole("button", { name: "Verify evidence" }));
    await screen.findByText(/Chain of custody/);
    return view;
  }

  it("says WORM only for COMPLIANCE mode with a default rule", async () => {
    const a = await chipFor({ enabled: true, mode: "COMPLIANCE", days: 1 });
    expect(screen.getByText("WORM (compliance)")).toBeInTheDocument();
    a.unmount();
    const b = await chipFor({ enabled: true, mode: "GOVERNANCE", days: 1 });
    expect(screen.getByText("Governance retention (bypassable)")).toBeInTheDocument();
    expect(screen.queryByText(/^WORM/)).toBeNull();
    b.unmount();
    const c = await chipFor({ enabled: true, mode: null, days: null });
    expect(screen.getByText("No default retention")).toBeInTheDocument();
    c.unmount();
    await chipFor({ enabled: false, mode: null, days: null });
    expect(screen.queryByText(/WORM|retention \(/)).toBeNull();
  });
});

describe("SOC KPI tiles", () => {
  const overview = (m = metrics()) => ({ incidents: [incident()], metrics: m, generatedAt: "t" });

  it("never shows Live when playbooks are disabled, and counts dry-run incidents as needing an analyst", async () => {
    const api = fakeApi({ "GET /soc/overview": overview(), "GET /soc/posture": posture({ containment: { playbooksEnabled: false, dryRun: false, failedLast24h: 0, lastMttcSeconds: null, targetSeconds: 60 } }) });
    renderWithSession(<SocDashboard />, { api, me: meFor("secops-analyst") });
    const mode = await screen.findByRole("group", { name: "Containment mode" });
    await waitFor(() => expect(mode).toHaveTextContent("Disabled"));
    expect(mode).not.toHaveTextContent("Live");
    // fixture byStatus: DETECTED 1 + DRY_RUN 1 + GUARD 1 + FAILED 1 (+ NO_PLAYBOOK 0)
    expect(screen.getByRole("group", { name: "Need analyst (24 h)" })).toHaveTextContent(/^Need analyst \(24 h\)4/);
  });

  it("shows a CVE count only for a COMPLETE scan", async () => {
    const api = fakeApi({ "GET /soc/overview": overview(), "GET /soc/posture": posture({ image: { reference: null, ecrScan: { status: "IN_PROGRESS", critical: null, high: null, medium: null, low: null, completedAt: null } } }) });
    renderWithSession(<SocDashboard />, { api, me: meFor("secops-analyst") });
    const cve = await screen.findByRole("group", { name: "Critical CVEs (running image)" });
    await waitFor(() => expect(cve).toHaveTextContent("no result (IN_PROGRESS)"));
    expect(cve).toHaveTextContent("—");
  });
});

describe("document drop zone", () => {
  function drop(files: File[]) {
    const zone = screen.getByText("Drop a file here").closest("div[class*='border-dashed']") ?? screen.getByText("Drop a file here").parentElement!;
    fireEvent.drop(zone, { dataTransfer: { files, types: ["Files"] } });
  }

  it("rejects several files, unsupported types and oversize files before anything is read", async () => {
    renderWithSession(<DocumentsPage />, { api: fakeApi({ "GET /documents": { items: [] } }), me: meFor("admin") });
    await screen.findByText("No documents yet.");
    drop([new File(["a"], "a.txt", { type: "text/plain" }), new File(["b"], "b.txt", { type: "text/plain" })]);
    expect(await screen.findByText("Drop one file at a time.")).toBeInTheDocument();
    drop([new File(["x"], "x.exe", { type: "application/x-msdownload" })]);
    expect(await screen.findByText(/Only PDF, text, PNG, JPEG and DOCX/)).toBeInTheDocument();
    const big = new File(["x"], "big.pdf", { type: "application/pdf" });
    Object.defineProperty(big, "size", { value: 6 * 1024 * 1024 });
    drop([big]);
    expect(await screen.findByText(/over 5 MiB/)).toBeInTheDocument();
  });
});
