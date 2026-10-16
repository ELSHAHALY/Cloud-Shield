import type { ReactNode } from "react";
import { NavLink } from "react-router";
import type { Permission } from "../api/types";
import { useSession } from "../auth/session";

const LINKS: { to: string; label: string; need?: Permission }[] = [
  { to: "/", label: "Home" },
  { to: "/documents", label: "Documents", need: "doc:read" },
  { to: "/audit", label: "Audit trail", need: "audit:read" },
  { to: "/onboarding", label: "Agreements", need: "agreement:read" },
  { to: "/grc", label: "GRC hub", need: "grc:read" },
  { to: "/soc", label: "SOC", need: "soc:read" },
];

export function Layout({ children }: { children: ReactNode }) {
  const { me, can, signOut, backend } = useSession();
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-4 px-4 py-3">
          <span className="font-semibold text-indigo-800">CloudShield</span>
          <nav aria-label="Main" className="flex flex-wrap gap-1">
            {LINKS.filter((l) => !l.need || can(l.need)).map((l) => (
              <NavLink key={l.to} to={l.to} end={l.to === "/"} className={({ isActive }) => `rounded px-2 py-1 text-sm ${isActive ? "bg-indigo-50 font-medium text-indigo-900" : "text-slate-700 hover:bg-slate-100"}`}>
                {l.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-3 text-sm">
            {backend.mode === "local" && <span className="rounded bg-amber-100 px-2 py-0.5 text-xs text-amber-900">local dev</span>}
            <span className="text-slate-600">
              {me.email ?? me.sub} · <span className="font-mono">{me.tenantId}</span>
            </span>
            <button type="button" onClick={() => void signOut()} className="rounded border border-slate-300 px-2 py-1 hover:bg-slate-50">
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl space-y-4 px-4 py-6">{children}</main>
    </div>
  );
}
