import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { fakeApi, meFor, renderWithSession } from "../test/render";
import { AuditPage } from "./AuditPage";
import { DocumentPage } from "./DocumentPage";
import { DocumentsPage } from "./DocumentsPage";
import { HomePage } from "./HomePage";
import { ACCEPTANCE_NOTE, OnboardingPage } from "./OnboardingPage";
import { downloadDocument, sha256Hex, uploadDocument } from "./upload";

const DOC = { docId: "0192b3c4-0000-7000-8000-000000000001", title: "Plan", contentType: "text/plain", sizeBytes: 5, sha256: "a".repeat(64), classification: "internal", tags: [], ownerSub: "sub-member", status: "AVAILABLE", createdAt: "t", updatedAt: "t", version: 2 } as const;
const agreement = (id: string) => ({ agreementId: id, version: "2026-10", title: `${id} title`, sha256: "f".repeat(64), effectiveDate: "2026-10-16", required: true });

describe("OnboardingPage", () => {
  it("lets only an admin accept, sending version + sha256 + authority", async () => {
    const accepted: unknown[] = [];
    let complete = false;
    const api = fakeApi({
      "GET /agreements/status": () => (complete ? { complete: true, accepted: [], pending: [] } : { complete: false, accepted: [], pending: [agreement("dpa")] }),
      "GET /agreements/dpa/2026-10/text": "LINE ONE\n<b>not html</b>",
      "POST /agreements/dpa/accept": (_p: string, body: unknown) => {
        accepted.push(body);
        complete = true;
        return {};
      },
    });
    renderWithSession(<OnboardingPage />, { api, me: meFor("admin") });
    expect(await screen.findByTestId("agreement-text-dpa")).toHaveTextContent("<b>not html</b>");
    expect(screen.getByText(ACCEPTANCE_NOTE)).toBeInTheDocument();
    const accept = screen.getByRole("button", { name: "Accept" });
    expect(accept).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(accept);
    await waitFor(() => expect(accepted).toEqual([{ version: "2026-10", sha256: "f".repeat(64), authorityConfirmed: true }]));
    expect(await screen.findByText("All required agreements accepted")).toBeInTheDocument();
    expect(screen.getByText("Next: set your GRC profile")).toBeInTheDocument();
  });

  it("shows members the waiting text and no Accept button", async () => {
    const api = fakeApi({ "GET /agreements/status": { complete: false, accepted: [{ agreementId: "sla", version: "2026-10", acceptedBy: { sub: "sub-x", groups: ["admin"] }, acceptedAt: "t" }], pending: [agreement("dpa")] }, "GET /agreements/dpa": "text" });
    renderWithSession(<OnboardingPage />, { api, me: meFor("member") });
    expect(await screen.findByText("Waiting for your tenant administrator to accept this agreement.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Accept" })).toBeNull();
    expect(screen.getByText("Action needed")).toBeInTheDocument();
  });

  it("shows errors", async () => {
    renderWithSession(<OnboardingPage />, { api: fakeApi({}) });
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});

describe("upload helpers", () => {
  it("hashes with WebCrypto and uploads in two steps", async () => {
    expect(await sha256Hex(new TextEncoder().encode("abc").buffer as ArrayBuffer)).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const api = fakeApi({ "POST /documents": { ...DOC, status: "PENDING_UPLOAD" }, "PUT /documents/": DOC });
    const file = new File(["hello"], "a.txt", { type: "text/plain" });
    await uploadDocument(api, { file, title: "T", classification: "public", tags: ["x"], description: "d" });
    expect(api.post).toHaveBeenCalledWith("/documents", expect.objectContaining({ contentType: "text/plain", sizeBytes: 5, sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", tags: ["x"], description: "d" }));
    expect(api.request).toHaveBeenCalledWith("PUT", `/documents/${DOC.docId}/content`, expect.objectContaining({ contentType: "text/plain" }));
    await expect(uploadDocument(api, { file: new File(["x"], "a.exe", { type: "application/x-msdownload" }), title: "x", classification: "public" })).rejects.toThrow("UNSUPPORTED_TYPE");
    const nav = vi.fn();
    const api2 = fakeApi({ "GET /documents/x/download": { url: "http://localhost:5000/signed", expiresAt: "t" } });
    await downloadDocument(api2, "x", nav);
    expect(nav).toHaveBeenCalledWith("http://localhost:5000/signed");
  });
});

describe("DocumentsPage", () => {
  it("lists, loads more and uploads", async () => {
    let page = 0;
    const api = fakeApi({
      "GET /documents?limit=25&cursor": { items: [{ ...DOC, docId: "0192b3c4-0000-7000-8000-000000000002", title: "Second" }] },
      "GET /documents?limit=25": () => (page++ === 0 ? { items: [DOC, { ...DOC, docId: "0192b3c4-0000-7000-8000-000000000003", title: "Pending", status: "PENDING_UPLOAD", classification: "restricted" }], nextCursor: "c1" } : { items: [DOC] }),
      "POST /documents": { ...DOC, status: "PENDING_UPLOAD" },
      "PUT /documents/": { ...DOC, title: "New" },
    });
    renderWithSession(<DocumentsPage />, { api, me: meFor("member") });
    expect(await screen.findByText("Plan")).toBeInTheDocument();
    expect(screen.getByText("pending upload")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Load more"));
    expect(await screen.findByText("Second")).toBeInTheDocument();
    const input = screen.getByLabelText("File") as HTMLInputElement;
    fireEvent.change(input, { target: { files: [new File(["hello"], "n.txt", { type: "text/plain" })] } });
    fireEvent.change(screen.getByLabelText("Tags (comma separated)"), { target: { value: "a, b, a" } });
    fireEvent.submit(screen.getByRole("form", { name: "Upload a document" }));
    expect(await screen.findByText(/SHA-256 verified by the server/)).toBeInTheDocument();
  });

  it("explains unsupported types and hides upload for auditors", async () => {
    const api = fakeApi({ "GET /documents": { items: [] } });
    const { unmount } = renderWithSession(<DocumentsPage />, { api, me: meFor("member") });
    fireEvent.change(await screen.findByLabelText("File"), { target: { files: [new File(["x"], "x.exe", { type: "application/x-msdownload" })] } });
    fireEvent.submit(screen.getByRole("form", { name: "Upload a document" }));
    expect(await screen.findByText(/Only PDF, text, PNG, JPEG and DOCX/)).toBeInTheDocument();
    unmount();
    renderWithSession(<DocumentsPage />, { api, me: meFor("auditor") });
    expect(await screen.findByText("No documents yet.")).toBeInTheDocument();
    expect(screen.queryByLabelText("File")).toBeNull();
  });

  it("surfaces agreement errors from the server", async () => {
    const api = fakeApi({ "GET /documents": { items: [] }, "POST /documents": () => Promise.reject(new ApiError(403, "AGREEMENT_REQUIRED", "r")) });
    renderWithSession(<DocumentsPage />, { api, me: meFor("member") });
    fireEvent.change(await screen.findByLabelText("File"), { target: { files: [new File(["x"], "x.txt", { type: "text/plain" })] } });
    fireEvent.submit(screen.getByRole("form", { name: "Upload a document" }));
    expect(await screen.findByText(/must accept the required agreements/)).toBeInTheDocument();
  });
});

describe("DocumentPage", () => {
  it("lets the owner edit with If-Match and delete", async () => {
    const api = fakeApi({ "GET /documents/": DOC, "PATCH /documents/": { ...DOC, title: "Renamed", version: 3 }, "DELETE /documents/": undefined });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderWithSession(<DocumentPage />, { api, me: meFor("member"), path: `/documents/${DOC.docId}`, route: "/documents/:docId" });
    fireEvent.change(await screen.findByLabelText("Title"), { target: { value: "Renamed" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.patch).toHaveBeenCalledWith(`/documents/${DOC.docId}`, { title: "Renamed", classification: "internal" }, { "If-Match": '"2"' }));
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(api.del).toHaveBeenCalledWith(`/documents/${DOC.docId}`));
  });

  it("hides editing from another member (UX only) and shows errors", async () => {
    const api = fakeApi({ "GET /documents/": { ...DOC, ownerSub: "someone-else" } });
    renderWithSession(<DocumentPage />, { api, me: meFor("member"), path: `/documents/${DOC.docId}`, route: "/documents/:docId" });
    expect(await screen.findByText("Metadata")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save" })).toBeNull();
    renderWithSession(<DocumentPage />, { api: fakeApi({}), path: "/documents/x", route: "/documents/:docId" });
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});

describe("AuditPage and HomePage", () => {
  it("renders events, untrusted IPs and paging", async () => {
    const ev = { eventKey: "k1", schemaVersion: "1", eventId: "e1", at: "2026-10-16T12:00:00.000Z", action: "ACCESS_DENIED", outcome: "DENIED", actor: { type: "user", sub: "sub-x" }, resource: { type: "route", id: "/documents" }, sourceIp: "203.0.113.1", sourceIpTrusted: false, userAgent: null, requestId: "r", details: {} };
    const api = fakeApi({ "GET /audit?limit=50&cursor": { items: [{ ...ev, eventKey: "k2", actor: { type: "anonymous" }, sourceIp: null }] }, "GET /audit?limit=50": { items: [ev], nextCursor: "n" } });
    renderWithSession(<AuditPage />, { api, me: meFor("auditor") });
    expect(await screen.findByText("ACCESS_DENIED")).toBeInTheDocument();
    expect(screen.getByText(/\(untrusted\)/)).toBeInTheDocument();
    expect(screen.getByText(/not WORM storage/)).toBeInTheDocument();
    fireEvent.click(screen.getByText("Load more"));
    expect(await screen.findByText("anonymous")).toBeInTheDocument();
  });

  it("warns about pending agreements on the home page", async () => {
    const api = fakeApi({ "GET /agreements/status": { complete: false, accepted: [], pending: [] } });
    renderWithSession(<HomePage />, { api, me: meFor("admin") });
    expect(await screen.findByText("Review and accept them")).toBeInTheDocument();
  });
});
