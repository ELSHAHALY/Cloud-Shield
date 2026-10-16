import type { ComponentType } from "react";

export interface LoginProps {
  onSignedIn(): void;
}

export interface AuthBackend {
  mode: "cognito" | "local";
  /** The current ID token, refreshed when forceRefresh; null when signed out. */
  getIdToken(forceRefresh?: boolean): Promise<string | null>;
  signOut(): Promise<void>;
  LoginForm: ComponentType<LoginProps>;
}

/**
 * The ONLY switch between the two backends. Vite replaces
 * import.meta.env.VITE_AUTH_MODE with a literal at build time, so in a
 * cognito build the local branch (and its chunk) is dead code and removed;
 * CI greps the bundle for "local-idp" to prove it.
 */
export function loadAuthBackend(): Promise<AuthBackend> {
  if (import.meta.env.VITE_AUTH_MODE === "local") {
    return import("./local").then((m) => m.localBackend);
  }
  return import("./cognito").then((m) => m.createCognitoBackend());
}
