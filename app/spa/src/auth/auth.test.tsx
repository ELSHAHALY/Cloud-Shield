import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const amplify = vi.hoisted(() => ({
  configure: vi.fn(),
  signIn: vi.fn(),
  confirmSignIn: vi.fn(),
  fetchAuthSession: vi.fn(),
  signOut: vi.fn(),
  setKeyValueStorage: vi.fn(),
}));
vi.mock("aws-amplify", () => ({ Amplify: { configure: amplify.configure } }));
vi.mock("aws-amplify/auth", () => ({ signIn: amplify.signIn, confirmSignIn: amplify.confirmSignIn, fetchAuthSession: amplify.fetchAuthSession, signOut: amplify.signOut }));
vi.mock("aws-amplify/auth/cognito", () => ({ cognitoUserPoolsTokenProvider: { setKeyValueStorage: amplify.setKeyValueStorage } }));
vi.mock("aws-amplify/utils", () => ({ sessionStorage: { kind: "session" } }));

import { CognitoLogin, createCognitoBackend } from "./cognito";
import { localBackend, LocalLogin } from "./local";
import { loadAuthBackend } from "./backend";

beforeEach(() => vi.clearAllMocks());

describe("cognito backend (Amplify v6)", () => {
  it("stores tokens in sessionStorage and signs out globally", async () => {
    const b = createCognitoBackend();
    expect(amplify.setKeyValueStorage).toHaveBeenCalledWith({ kind: "session" });
    amplify.fetchAuthSession.mockResolvedValueOnce({ tokens: { idToken: { toString: () => "id.jwt.x" } } });
    expect(await b.getIdToken(true)).toBe("id.jwt.x");
    expect(amplify.fetchAuthSession).toHaveBeenCalledWith({ forceRefresh: true });
    amplify.fetchAuthSession.mockRejectedValueOnce(new Error("no session"));
    expect(await b.getIdToken()).toBeNull();
    await b.signOut();
    expect(amplify.signOut).toHaveBeenCalledWith({ global: true });
  });

  it("walks SRP → TOTP setup → TOTP code", async () => {
    const onSignedIn = vi.fn();
    amplify.signIn.mockResolvedValueOnce({ isSignedIn: false, nextStep: { signInStep: "CONTINUE_SIGN_IN_WITH_TOTP_SETUP", totpSetupDetails: { getSetupUri: () => new URL("otpauth://totp/CloudShield:alice?secret=ABC") } } });
    amplify.confirmSignIn.mockResolvedValueOnce({ isSignedIn: true, nextStep: { signInStep: "DONE" } });
    render(<CognitoLogin onSignedIn={onSignedIn} />);
    fireEvent.change(screen.getByLabelText("Username or email"), { target: { value: "alice" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "pw" } });
    fireEvent.submit(screen.getByRole("form", { name: "Sign in" }));
    expect(await screen.findByText(/otpauth:\/\/totp/)).toBeInTheDocument();
    expect(amplify.signIn).toHaveBeenCalledWith({ username: "alice", password: "pw", options: { authFlowType: "USER_SRP_AUTH" } });
    fireEvent.change(screen.getByLabelText("Authenticator code"), { target: { value: "123456" } });
    fireEvent.submit(screen.getByRole("form", { name: "Sign in" }));
    await waitFor(() => expect(onSignedIn).toHaveBeenCalled());
    expect(amplify.confirmSignIn).toHaveBeenCalledWith({ challengeResponse: "123456" });
  });

  it("handles the new-password step, unsupported steps and failures", async () => {
    amplify.signIn.mockResolvedValueOnce({ isSignedIn: false, nextStep: { signInStep: "CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED" } });
    amplify.confirmSignIn.mockResolvedValueOnce({ isSignedIn: false, nextStep: { signInStep: "CONFIRM_SIGN_IN_WITH_SMS_CODE" } });
    render(<CognitoLogin onSignedIn={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Username or email"), { target: { value: "a" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "p" } });
    fireEvent.submit(screen.getByRole("form", { name: "Sign in" }));
    fireEvent.change(await screen.findByLabelText("Choose a new password"), { target: { value: "new" } });
    fireEvent.submit(screen.getByRole("form", { name: "Sign in" }));
    expect(await screen.findByText(/not supported here/)).toBeInTheDocument();
  });

  it("reports a failed sign-in without detail", async () => {
    amplify.signIn.mockRejectedValueOnce(new Error("NotAuthorizedException: Incorrect username or password."));
    render(<CognitoLogin onSignedIn={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("Username or email"), { target: { value: "a" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "p" } });
    fireEvent.submit(screen.getByRole("form", { name: "Sign in" }));
    expect(await screen.findByText("Sign-in failed. Check your details and try again.")).toBeInTheDocument();
  });
});

describe("local backend (dev only)", () => {
  const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, "");
  it("lists demo users, mints a token and keeps it in sessionStorage only", async () => {
    const token = `${b64({ alg: "RS256" })}.${b64({ exp: Math.floor(Date.now() / 1000) + 3600 })}.sig`;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) =>
      String(input).endsWith("/users")
        ? new Response(JSON.stringify([{ username: "alice", tenantId: "t-acme-01", groups: ["admin"], description: "acme admin" }]))
        : new Response(JSON.stringify({ idToken: token })),
    );
    const onSignedIn = vi.fn();
    render(<LocalLogin onSignedIn={onSignedIn} />);
    fireEvent.click(await screen.findByText("alice"));
    await waitFor(() => expect(onSignedIn).toHaveBeenCalled());
    expect(await localBackend.getIdToken()).toBe(token);
    await localBackend.signOut();
    expect(await localBackend.getIdToken()).toBeNull();
    sessionStorage.setItem("cloudshield.local.idToken", `${b64({})}.${b64({ exp: 1 })}.x`);
    expect(await localBackend.getIdToken()).toBeNull();
    sessionStorage.setItem("cloudshield.local.idToken", "garbage");
    expect(await localBackend.getIdToken()).toBeNull();
  });

  it("reports an unreachable IdP or a failed mint", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response("", { status: 502 }));
    render(<LocalLogin onSignedIn={vi.fn()} />);
    expect(await screen.findByText(/local IdP is not reachable/)).toBeInTheDocument();
  });

  it("is selected only when VITE_AUTH_MODE=local", async () => {
    vi.stubEnv("VITE_AUTH_MODE", "local");
    expect((await loadAuthBackend()).mode).toBe("local");
    vi.stubEnv("VITE_AUTH_MODE", "cognito");
    expect((await loadAuthBackend()).mode).toBe("cognito");
    vi.unstubAllEnvs();
  });
});
