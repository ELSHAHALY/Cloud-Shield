// DEV ONLY (plan D22): sign in as a seeded demo user through the local IdP
// that docker-compose.local.yml runs. Statically removed from cognito builds.
import { useEffect, useState } from "react";
import { Icon } from "../components/ui";
import type { AuthBackend, LoginProps } from "./backend";
import { roleInfo } from "./roles";

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
    <div className="space-y-4">
      <p className="flex items-start gap-2 rounded-xl border border-amber-500/35 bg-amber-500/[0.08] p-3 text-sm text-amber-100">
        <Icon name="alert" className="mt-0.5 size-4 shrink-0 text-amber-300" />
        <span>Local development mode: pick a seeded demo user. No password, no MFA. This screen never exists in a deployed build.</span>
      </p>
      {error && (
        <p role="alert" className="text-sm text-rose-300">
          {error}
        </p>
      )}
      <ul className="grid gap-2.5 sm:grid-cols-2">
        {users.map((u) => {
          const role = roleInfo(u.groups[0] ?? "");
          return (
            <li key={u.username}>
              <button type="button" onClick={() => void pick(u.username)} className="group flex h-full w-full flex-col gap-2 rounded-xl border border-slate-700/80 bg-slate-900/60 p-3 text-left transition hover:-translate-y-0.5 hover:border-cyan-500/50 hover:bg-slate-900 hover:shadow-[0_0_24px_-10px_rgb(34_211_238/0.8)]">
                <span className="flex items-center gap-2.5">
                  <span className="grid size-8 shrink-0 place-items-center rounded-lg border border-slate-700 bg-slate-800/80 text-cyan-300 group-hover:border-cyan-500/40">
                    <Icon name={role.icon} className="size-4" />
                  </span>
                  <span className="min-w-0">
                    <span className="block font-medium text-white">{u.username}</span>
                    <span className="block text-xs text-slate-400">{u.groups.map((g) => roleInfo(g).label).join(" + ")}</span>
                  </span>
                </span>
                <span className="text-xs text-slate-400">{u.description}</span>
                <span className="flex flex-wrap gap-1">
                  {u.groups.flatMap((g) => roleInfo(g).badges).map((b) => (
                    <span key={b} className="rounded-md border border-slate-700/80 bg-slate-950/60 px-1.5 py-0.5 text-[10px] text-slate-300">
                      {b}
                    </span>
                  ))}
                </span>
                <span className="font-mono text-[11px] text-slate-500">
                  {u.tenantId} · {u.groups.join(", ")}
                </span>
              </button>
            </li>
          );
        })}
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
