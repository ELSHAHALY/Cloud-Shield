// DEV ONLY (plan D22): sign in as a seeded demo user through the local IdP
// that docker-compose.local.yml runs. Statically removed from cognito builds.
import { useEffect, useState } from "react";
import type { AuthBackend, LoginProps } from "./backend";

const IDP = "/local-idp";
const KEY = "cloudshield.local.idToken";

interface DemoUser {
  username: string;
  tenantId: string;
  groups: string[];
  description: string;
}

function expired(token: string): boolean {
  try {
    const payload = JSON.parse(atob(token.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))) as { exp?: number };
    return typeof payload.exp !== "number" || payload.exp * 1000 < Date.now() + 30_000;
  } catch {
    return true;
  }
}

export function LocalLogin({ onSignedIn }: LoginProps) {
  const [users, setUsers] = useState<DemoUser[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(`${IDP}/users`, { cache: "no-store" })
      .then((r) => (r.ok ? (r.json() as Promise<DemoUser[]>) : Promise.reject(new Error(String(r.status)))))
      .then(setUsers)
      .catch(() => setError("The local IdP is not reachable. Is docker compose up?"));
  }, []);

  async function pick(username: string) {
    setError(null);
    const res = await fetch(`${IDP}/token`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username }), cache: "no-store" });
    if (!res.ok) {
      setError("Could not mint a token.");
      return;
    }
    const { idToken } = (await res.json()) as { idToken: string };
    sessionStorage.setItem(KEY, idToken);
    onSignedIn();
  }

  return (
    <div className="space-y-3">
      <p className="rounded border border-amber-300 bg-amber-50 p-2 text-sm">Local development mode: pick a seeded demo user. No password, no MFA. This screen never exists in a deployed build.</p>
      {error && (
        <p role="alert" className="text-sm text-red-700">
          {error}
        </p>
      )}
      <ul className="divide-y divide-slate-200 rounded border border-slate-200 bg-white">
        {users.map((u) => (
          <li key={u.username}>
            <button type="button" onClick={() => void pick(u.username)} className="flex w-full items-center justify-between px-3 py-2 text-left hover:bg-slate-50">
              <span>
                <span className="font-medium">{u.username}</span> <span className="text-sm text-slate-600">{u.description}</span>
              </span>
              <span className="font-mono text-xs text-slate-500">
                {u.tenantId} · {u.groups.join(", ")}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

export const localBackend: AuthBackend = {
  mode: "local",
  async getIdToken() {
    const token = sessionStorage.getItem(KEY);
    if (!token || expired(token)) {
      sessionStorage.removeItem(KEY);
      return null;
    }
    return token;
  },
  async signOut() {
    sessionStorage.removeItem(KEY);
  },
  LoginForm: LocalLogin,
};
