import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import type { GrcAssessment } from "../api/types";
import { fakeApi, meFor, renderWithSession } from "../test/render";
import { GrcHub } from "./GrcHub";
import { MatrixPage } from "./MatrixPage";

const ruleset = { version: "2026.10.0", sha256: "a".repeat(64), lastReviewed: "2026-10-16", disclaimer: "Informational mapping for an academic capstone; not legal advice.", jurisdictions: [], frameworks: [], ruleCount: 2 };
const assessment: GrcAssessment = {
  rulesetVersion: "2026.10.0",
  rulesetSha256: "a".repeat(64),
  profileVersion: 1,
  generatedAt: "t",
  platformFacts: { deploymentRegions: ["us-east-1"], incidentAutomation: "dry-run" },
  disclaimer: ruleset.disclaimer,
  summary: { MET: 1, PARTIAL: 0, GAP: 1, CUSTOMER_ACTION: 0, NOT_APPLICABLE: 1, INFO: 0 },
  findings: [
    { ruleId: "EG-PDPL-CROSS-BORDER", framework: "EG-PDPL", topic: "cross-border", status: "GAP", obligation: "Transfer only with a licence.", citations: [{ source: "Law 151/2020", article: "Art. 14–15", status: "verify" }], citationStatus: "verify", controls: [], rationale: "Hosted in us-east-1." },
    { ruleId: "EU-GDPR-ART17-ERASURE", framework: "EU-GDPR", topic: "erasure", status: "MET", obligation: "Erase.", citations: [{ source: "GDPR", article: "Art. 17", status: "doc" }], citationStatus: "doc", controls: [], rationale: "Tombstone." },
    { ruleId: "EG-PDPL-SCOPE-CBE", framework: "EG-PDPL", topic: "scope", status: "NOT_APPLICABLE", obligation: "Scope.", citations: [{ source: "x", status: "verify" }], citationStatus: "verify", controls: [], rationale: "n/a" },
  ],
};
const profile = { profile: { jurisdictions: ["EG"], sector: "general", cbeRegulated: false, processesPersonalData: true, processesSensitiveData: false, governmentData: false, dataSubjectRegions: [] }, version: 1, updatedAt: "t", updatedBy: "sub-admin" };

describe("GrcHub", () => {
  it("always shows the disclaimer and badges verify citations", async () => {
    const api = fakeApi({ "GET /grc/ruleset": ruleset, "GET /grc/profile": profile, "GET /grc/assessment": assessment });
    renderWithSession(<GrcHub />, { api, me: meFor("auditor") });
    expect(screen.getByRole("note", { name: "Disclaimer" })).toHaveTextContent("Not legal advice.");
    expect(await screen.findByText("EG-PDPL-CROSS-BORDER")).toBeInTheDocument();
    expect(screen.getAllByText("⚠ Verify against the official text")).toHaveLength(1);
    expect(screen.queryByText("EG-PDPL-SCOPE-CBE")).toBeNull();
    expect(screen.getByText("GAP: 1")).toBeInTheDocument();
    expect(screen.queryByRole("form", { name: "GRC profile" })).toBeNull();
  });

  it("lets an admin set the profile when none exists", async () => {
    let saved: unknown = null;
    const api = fakeApi({
      "GET /grc/ruleset": ruleset,
      "GET /grc/profile": () => (saved ? profile : Promise.reject(new ApiError(404, "NOT_FOUND", "r"))),
      "GET /grc/assessment": assessment,
      "PUT /grc/profile": (_p: string, body: unknown) => {
        saved = body;
        return profile;
      },
    });
    renderWithSession(<GrcHub />, { api, me: meFor("admin") });
    expect(await screen.findByText("Set your tenant profile")).toBeInTheDocument();
    fireEvent.click(screen.getAllByLabelText("EU")[0]!);
    fireEvent.click(screen.getByLabelText("Regulated by the Central Bank of Egypt"));
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "financial" } });
    fireEvent.click(screen.getAllByLabelText("OTHER")[0]!);
    fireEvent.click(screen.getByRole("button", { name: "Save profile" }));
    await waitFor(() => expect(saved).toMatchObject({ jurisdictions: ["EG", "EU"], cbeRegulated: true, sector: "financial", dataSubjectRegions: ["OTHER"] }));
    expect(await screen.findByText("EU-GDPR-ART17-ERASURE")).toBeInTheDocument();
  });

  it("explains limited roles and surfaces errors", async () => {
    renderWithSession(<GrcHub />, { api: fakeApi({ "GET /grc/ruleset": ruleset }), me: meFor("member") });
    expect(await screen.findByText(/assessments are visible to tenant administrators and auditors/)).toBeInTheDocument();
    renderWithSession(<GrcHub />, { api: fakeApi({ "GET /grc/ruleset": ruleset, "GET /grc/profile": () => Promise.reject(new ApiError(404, "NOT_FOUND", "r")) }), me: meFor("auditor") });
    expect(await screen.findByText(/has not set a GRC profile yet/)).toBeInTheDocument();
    renderWithSession(<GrcHub />, { api: fakeApi({ "GET /grc/ruleset": ruleset, "GET /grc/profile": () => Promise.reject(new ApiError(503, "SERVICE_UNAVAILABLE", "r")) }), me: meFor("auditor") });
    expect(await screen.findByText(/unavailable right now/)).toBeInTheDocument();
  });
});

describe("MatrixPage", () => {
  it("renders built and mapped cells with verify badges", async () => {
    const cell = (service: string, status: "built" | "mapped", verify = false) => ({ service, responsibility: "shared", notes: "", status, verify });
    const api = fakeApi({ "GET /grc/responsibility-matrix": { version: "2026.10.0", lastReviewed: "2026-10-16", disclaimer: "Mapped only.", providers: ["aws", "azure", "gcp"], controls: [{ id: "waf", control: "Edge WAF", layer: "network", cells: { aws: cell("AWS WAF", "built"), azure: cell("Front Door WAF", "mapped", true), gcp: cell("Cloud Armor", "mapped") } }], layers: [{ layer: "Physical", owner: "Provider", notes: "always" }] } });
    renderWithSession(<MatrixPage />, { api });
    expect(await screen.findByText("AWS WAF")).toBeInTheDocument();
    expect(screen.getAllByText(/mapped, not built/)).toHaveLength(2);
    expect(screen.getByText("⚠ Verify against the official text")).toBeInTheDocument();
    renderWithSession(<MatrixPage />, { api: fakeApi({}) });
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});
