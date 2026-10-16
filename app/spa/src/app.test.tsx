import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { App, AppRoutes } from "./App";
import type { AuthBackend } from "./auth/backend";
import { RoleGuard } from "./components/RoleGuard";
import { Layout } from "./components/Layout";
import { SocDashboard } from "./soc/SocDashboard";
import { IncidentPage } from "./soc/IncidentPage";
import { detail, incident, metrics, posture } from "./test/fixtures";
import { fakeApi, meFor, renderWithSession } from "./test/render";

describe("RoleGuard and Layout", () => {
  it("hides pages and nav entries the user cannot use (UX only)", async () => {
    renderWithSession(
      <Layout>
        <RoleGuard need="soc:read">secret SOC</RoleGuard>
      </Layout>,
      { me: meFor("member") },
    );
    expect(screen.getByText("You do not have access to this page.")).toBeInTheDocument();
    expect(screen.queryByText("secret SOC")).toBeNull();
    expect(screen.queryByRole("link", { name: "SOC" })).toBeNull();
    expect(screen.getByRole("link", { name: "Documents" })).toBeInTheDocument();
    expect(screen.getByText("local dev")).toBeInTheDocument();
  });

  it("signs out", async () => {
    const { signOut } = renderWithSession(<Layout>x</Layout>, { me: meFor("secops-analyst") });
    expect(screen.getByRole("link", { name: "SOC" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(signOut).toHaveBeenCalled();
  });
});

describe("SOC pages", () => {
  it("polls the overview and posture", async () => {
    const api = fakeApi({ "GET /soc/overview": { incidents: [incident()], metrics: metrics(), generatedAt: "t" }, "GET /soc/posture": posture() });
    renderWithSession(<SocDashboard />, { api, me: meFor("secops-analyst") });
    expect(await screen.findByText("Latest incidents")).toBeInTheDocument();
    expect(await screen.findByText("Security posture")).toBeInTheDocument();
    expect(screen.getByText(/refreshes every 15 s/)).toBeInTheDocument();
  });

  it("renders an incident with timeline, decoy notice and evidence panel", async () => {
    const api = fakeApi({
      "GET /soc/incidents/edge-decoy": detail({
        incidentId: "edge-decoy-1",
        status: "BLOCKED_BY_GUARD",
        displayStatus: "Decoy hit: notify only",
        notifyOnly: true,
        guardReason: "notify-only edge finding (decoy route hit): analyst review",
        mttcSeconds: null,
        block: { blockedCidr: "203.0.113.5/32", blockState: "active", blockExpiresAt: "t" },
        relatedAudit: [{ eventKey: "k", schemaVersion: "1", eventId: "e", at: "t", action: "DECOY_ROUTE_HIT", outcome: "DENIED", actor: { type: "anonymous" }, resource: { type: "decoy-route" }, sourceIp: "203.0.113.9", sourceIpTrusted: true, userAgent: null, requestId: "r", details: { method: "GET", path: "/admin" } }],
      }),
    });
    renderWithSession(<IncidentPage />, { api, me: meFor("secops-analyst"), path: "/soc/incidents/edge-decoy-1", route: "/soc/incidents/:incidentId" });
    expect(await screen.findByText(/Notify only: SOAR never blocks decoy hits/)).toBeInTheDocument();
    expect(screen.getByText("Decoy route audit (this hour)")).toBeInTheDocument();
    expect(screen.getByText(/GET \/admin · 203.0.113.9/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Verify evidence" })).toBeInTheDocument();
    renderWithSession(<IncidentPage />, { api: fakeApi({}), path: "/soc/incidents/x", route: "/soc/incidents/:incidentId" });
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });

  it("routes every page behind its guard", async () => {
    render(
      <MemoryRouter initialEntries={["/nope"]}>
        <AppRoutes />
      </MemoryRouter>,
    );
    expect(screen.getByText("Page not found.")).toBeInTheDocument();
  });
});

describe("App shell", () => {
  it("shows the login form when signed out, then loads /me", async () => {
    let token: string | null = null;
    const backend: AuthBackend = {
      mode: "local",
      getIdToken: vi.fn(async () => token),
      signOut: vi.fn(async () => {
        token = null;
      }),
      LoginForm: ({ onSignedIn }) => (
        <button
          onClick={() => {
            token = "tok";
            onSignedIn();
          }}
        >
          fake sign in
        </button>
      ),
    };
    const me = meFor("member");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith("/api/me")) return new Response(JSON.stringify(me), { status: 200, headers: { "content-type": "application/json" } });
      if (url.includes("/api/agreements/status")) return new Response(JSON.stringify({ complete: true, accepted: [], pending: [] }), { status: 200, headers: { "content-type": "application/json" } });
      return new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
    });
    render(<App backend={backend} />);
    fireEvent.click(await screen.findByText("fake sign in"));
    expect(await screen.findByText("Your access")).toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([, init]) => (init?.headers as Record<string, string>)?.Authorization === "Bearer tok")).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(screen.getByText("fake sign in")).toBeInTheDocument());
  });

  it("shows an error when /me fails", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ code: "TENANT_INVALID" }), { status: 403, headers: { "content-type": "application/problem+json" } }));
    render(<App backend={{ mode: "cognito", getIdToken: async () => "t", signOut: async () => undefined, LoginForm: () => null }} />);
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});
