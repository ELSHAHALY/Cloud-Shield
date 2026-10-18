import { useEffect, useState, type ReactNode } from "react";
import { NavLink } from "react-router";
import type { Permission } from "../api/types";
import { roleInfo } from "../auth/roles";
import { useSession } from "../auth/session";
import { LiveContext, type LiveState } from "./live";
import { Icon, type IconName } from "./ui";

interface NavItem {
  to: string;
  label: string;
  icon: IconName;
  need?: Permission;
}

// Visible labels are the links' accessible names; keep them short and exact.
const SECTIONS: { title: string; items: NavItem[] }[] = [
  {
    title: "Tenant portal",
    items: [
      { to: "/", label: "Overview", icon: "home" },
      { to: "/documents", label: "Documents", icon: "file-lock", need: "doc:read" },
      { to: "/audit", label: "Audit trail", icon: "audit", need: "audit:read" },
      { to: "/onboarding", label: "Agreements", icon: "agreement", need: "agreement:read" },
    ],
  },
  { title: "Governance", items: [{ to: "/grc", label: "GRC hub", icon: "scale", need: "grc:read" }] },
  {
    title: "Security operations",
    items: [
      { to: "/soc", label: "SOC", icon: "radar", need: "soc:read" },
      { to: "/soc/audit", label: "Platform audit", icon: "fingerprint", need: "soc:read" },
    ],
  },
];

function LiveIndicator({ live }: { live: LiveState }) {
  // usePolling pauses while the tab is hidden; say so instead of claiming "live" (review F8c).
  const [hidden, setHidden] = useState(() => typeof document !== "undefined" && document.visibilityState === "hidden");
  useEffect(() => {
    const on = () => setHidden(document.visibilityState === "hidden");
    document.addEventListener("visibilitychange", on);
    return () => document.removeEventListener("visibilitychange", on);
  }, []);
  if (hidden) {
    return <span className="hidden items-center gap-2 rounded-full border border-slate-700/80 bg-slate-900/70 px-2.5 py-1 text-xs text-slate-400 sm:inline-flex">{live.label}: paused (tab hidden)</span>;
  }
  return (
    <span className="hidden items-center gap-2 rounded-full border border-slate-700/80 bg-slate-900/70 px-2.5 py-1 text-xs text-slate-300 sm:inline-flex" title={live.updatedAt ? `Last update ${live.updatedAt.toLocaleTimeString()}` : "Waiting for the first update"}>
      {live.failing ? <span className="size-2 rounded-full bg-rose-400" aria-hidden="true" /> : <span className="live-dot" aria-hidden="true" />}
      {live.failing ? `${live.label}: update failed` : `${live.label} · live, every ${live.intervalSeconds} s`}
    </span>
  );
}

export function Layout({ children }: { children: ReactNode }) {
  const { me, can, signOut, backend } = useSession();
  const [live, setLive] = useState<LiveState | null>(null);
  const sections = SECTIONS.map((s) => ({ ...s, items: s.items.filter((l) => !l.need || can(l.need)) })).filter((s) => s.items.length > 0);

  return (
    <LiveContext.Provider value={setLive}>
      <div className="min-h-screen lg:flex">
        <aside className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md lg:sticky lg:top-0 lg:flex lg:h-screen lg:w-64 lg:shrink-0 lg:flex-col lg:border-r lg:border-b-0">
          <div className="flex items-center gap-2.5 px-5 py-4">
            <span className="grid size-9 place-items-center rounded-xl border border-cyan-500/40 bg-gradient-to-br from-cyan-500/25 to-emerald-500/10 text-cyan-300 shadow-[0_0_24px_-8px_rgb(34_211_238/0.8)]">
              <Icon name="shield-check" className="size-5" />
            </span>
            <span className="leading-tight">
              <span className="block font-semibold tracking-tight text-white">CloudShield</span>
              <span className="block text-[11px] text-slate-400">DevSecOps · SOAR platform</span>
            </span>
          </div>
          <nav aria-label="Main" className="relative flex gap-4 overflow-x-auto px-3 pb-3 lg:flex-1 lg:flex-col lg:gap-5 lg:overflow-y-auto lg:pt-2">
            {sections.map((s) => (
              <div key={s.title} className="shrink-0">
                <p className="label-caps hidden px-2 pb-1.5 lg:block">{s.title}</p>
                <ul className="flex gap-1 lg:flex-col">
                  {s.items.map((l) => (
                    <li key={l.to}>
                      <NavLink
                        to={l.to}
                        end={l.to === "/" || l.to === "/soc"}
                        className={({ isActive }) =>
                          `group flex items-center gap-2.5 rounded-lg border px-2.5 py-2 text-sm whitespace-nowrap no-underline transition-colors ${
                            isActive ? "border-cyan-500/30 bg-cyan-500/10 text-white shadow-[inset_2px_0_0_0_rgb(34_211_238)]" : "border-transparent text-slate-400 hover:bg-slate-800/60 hover:text-slate-100"
                          }`
                        }
                      >
                        <Icon name={l.icon} className="size-4 shrink-0" />
                        {l.label}
                      </NavLink>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </nav>
          <div className="hidden border-t border-slate-800/80 px-5 py-3 text-[11px] text-slate-500 lg:block">Automated containment · human-gated eradication</div>
        </aside>

        <div className="min-w-0 flex-1">
          <header className="sticky top-0 z-10 border-b border-slate-800/80 bg-slate-950/70 backdrop-blur-md">
            <div className="flex flex-wrap items-center gap-2 px-4 py-2.5 md:px-6">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-700/80 bg-slate-900/70 px-2.5 py-1 text-xs text-slate-300">
                <Icon name="layers" className="size-3.5 text-cyan-300" />
                Tenant <span className="font-mono text-slate-100">{me.tenantId}</span>
              </span>
              {me.groups.map((g) => (
                <span key={g} className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-200">
                  {roleInfo(g).label}
                </span>
              ))}
              {live && <LiveIndicator live={live} />}
              <div className="ml-auto flex items-center gap-2 text-sm">
                {backend.mode === "local" && <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-xs font-medium text-amber-200">local dev</span>}
                <span className="hidden max-w-56 truncate text-xs text-slate-400 md:inline" title={me.email ?? me.sub}>
                  {me.email ?? me.sub}
                </span>
                {backend.mode === "local" && (
                  <button type="button" onClick={() => void signOut()} className="btn-ghost text-xs" title="Local development only: back to the seeded persona picker">
                    <Icon name="switch" className="size-3.5" />
                    Switch persona
                  </button>
                )}
                <button type="button" onClick={() => void signOut()} className="btn-secondary text-xs">
                  <Icon name="logout" className="size-3.5" />
                  Sign out
                </button>
              </div>
            </div>
          </header>
          <main className="mx-auto max-w-7xl space-y-5 px-4 py-6 md:px-6">{children}</main>
        </div>
      </div>
    </LiveContext.Provider>
  );
}
