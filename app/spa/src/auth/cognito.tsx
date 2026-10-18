// Cognito sign-in (SRP + TOTP) with Amplify v6. Tokens live in sessionStorage,
// never localStorage (plan D20); sign-out is global (revokes refresh tokens).
import { useState, type FormEvent } from "react";
import { Amplify } from "aws-amplify";
import { confirmSignIn, fetchAuthSession, signIn, signOut, type SignInOutput } from "aws-amplify/auth";
import { cognitoUserPoolsTokenProvider } from "aws-amplify/auth/cognito";
import { sessionStorage } from "aws-amplify/utils";
import type { AuthBackend, LoginProps } from "./backend";

type Step = SignInOutput["nextStep"]["signInStep"];

export function configureCognito(env: ImportMetaEnv = import.meta.env): void {
  Amplify.configure({
    Auth: { Cognito: { userPoolId: env.VITE_COGNITO_USER_POOL_ID ?? "", userPoolClientId: env.VITE_COGNITO_CLIENT_ID ?? "" } },
  });
  cognitoUserPoolsTokenProvider.setKeyValueStorage(sessionStorage);
}

export function CognitoLogin({ onSignedIn }: LoginProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [step, setStep] = useState<Step | "START">("START");
  const [setupUri, setSetupUri] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handle(out: SignInOutput) {
    if (out.isSignedIn || out.nextStep.signInStep === "DONE") {
      onSignedIn();
      return;
    }
    if (out.nextStep.signInStep === "CONTINUE_SIGN_IN_WITH_TOTP_SETUP") {
      setSetupUri(out.nextStep.totpSetupDetails.getSetupUri("CloudShield").toString());
    }
    setStep(out.nextStep.signInStep);
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (step === "START") await handle(await signIn({ username, password, options: { authFlowType: "USER_SRP_AUTH" } }));
      else if (step === "CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED") await handle(await confirmSignIn({ challengeResponse: password }));
      else await handle(await confirmSignIn({ challengeResponse: code.trim() }));
      setCode("");
    } catch {
      setError("Sign-in failed. Check your details and try again.");
    } finally {
      setBusy(false);
    }
  }

  const needsCode = step === "CONFIRM_SIGN_IN_WITH_TOTP_CODE" || step === "CONTINUE_SIGN_IN_WITH_TOTP_SETUP";
  const unsupported = step !== "START" && !needsCode && step !== "CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED";
  return (
    <form onSubmit={submit} className="space-y-4" aria-label="Sign in">
      {step === "START" && (
      <p className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-emerald-200">SRP</span>
        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-emerald-200">TOTP MFA</span>
        Cognito checks your password by SRP without receiving it.
      </p>
      )}
      {step === "START" && (
        <>
          <label className="block text-sm font-medium text-slate-200">
            Username or email
            <input className="mt-1.5 w-full px-3 py-2" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
          </label>
          <label className="block text-sm font-medium text-slate-200">
            Password
            <input type="password" className="mt-1.5 w-full px-3 py-2" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </label>
        </>
      )}
      {step === "CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED" && (
        <label className="block text-sm font-medium text-slate-200">
          Choose a new password
          <input type="password" className="mt-1.5 w-full px-3 py-2" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </label>
      )}
      {setupUri && step === "CONTINUE_SIGN_IN_WITH_TOTP_SETUP" && (
        <div className="rounded-xl border border-amber-500/35 bg-amber-500/[0.08] p-3 text-sm text-amber-100">
          <p className="font-medium text-amber-200">Set up your authenticator app (MFA is required).</p>
          <p className="mt-1">Add this key to your app, then enter the 6-digit code:</p>
          <code className="mt-2 block rounded-lg border border-slate-700 bg-slate-950/70 p-2 font-mono text-xs break-all text-slate-200">{setupUri}</code>
        </div>
      )}
      {needsCode && (
        <label className="block text-sm font-medium text-slate-200">
          Authenticator code
          <input inputMode="numeric" pattern="[0-9]{6}" className="mt-1.5 w-full px-3 py-2 font-mono tracking-[0.3em]" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} required />
        </label>
      )}
      {unsupported && <p role="alert" className="text-sm text-rose-300">This sign-in step is not supported here ({step}). Contact your administrator.</p>}
      {error && (
        <p role="alert" className="text-sm text-rose-300">
          {error}
        </p>
      )}
      <button type="submit" disabled={busy || unsupported} className="btn-primary w-full py-2.5">
        {busy ? "Signing in…" : "Continue"}
      </button>
    </form>
  );
}

export function createCognitoBackend(): AuthBackend {
  configureCognito();
  return {
    mode: "cognito",
    async getIdToken(forceRefresh = false) {
      try {
        const session = await fetchAuthSession({ forceRefresh });
        return session.tokens?.idToken?.toString() ?? null;
      } catch {
        return null;
      }
    },
    async signOut() {
      await signOut({ global: true });
    },
    LoginForm: CognitoLogin,
  };
}
