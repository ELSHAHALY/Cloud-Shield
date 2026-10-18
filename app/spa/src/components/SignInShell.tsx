import type { ReactNode } from "react";
import { Icon, type IconName } from "./ui";

// Claims here are design facts of this repository, worded as such; none is a
// measurement (no MTTC has been measured on AWS yet).
const POINTS: { icon: IconName; title: string; text: string }[] = [
  { icon: "fingerprint", title: "Cognito with TOTP MFA", text: "Admin-created accounts, tokens kept in session storage only." },
  { icon: "lock", title: "Tenant-scoped API", text: "Every request is authorised server-side from the verified token." },
  { icon: "radar", title: "Automated containment", text: "SOAR playbooks contain behind a fail-closed guard; eradication stays human-gated." },
];

export function SignInShell({ children, local }: { children: ReactNode; local: boolean }) {
  return (
    <div className="grid min-h-screen lg:grid-cols-[1.1fr_1fr]">
      <section className="relative hidden overflow-hidden border-r border-slate-800/80 px-12 py-14 lg:flex lg:flex-col lg:justify-between" aria-label="About CloudShield">
        <span className="pointer-events-none absolute -top-24 -left-24 size-96 rounded-full bg-cyan-500/10 blur-3xl animate-glow" aria-hidden="true" />
        <span className="pointer-events-none absolute right-0 bottom-0 size-80 rounded-full bg-emerald-500/10 blur-3xl animate-glow" aria-hidden="true" />
        <div className="relative flex items-center gap-3">
          <span className="grid size-11 place-items-center rounded-2xl border border-cyan-500/40 bg-gradient-to-br from-cyan-500/25 to-emerald-500/10 text-cyan-300 shadow-[0_0_32px_-8px_rgb(34_211_238/0.9)]">
            <Icon name="shield-check" className="size-6" />
          </span>
          <span>
            <span className="block text-lg font-semibold tracking-tight text-white">CloudShield</span>
            <span className="block text-xs text-slate-400">Automated DevSecOps &amp; Cloud Incident Response</span>
          </span>
        </div>
        <div className="relative max-w-lg space-y-8">
          <h2 className="text-4xl leading-tight font-semibold tracking-tight text-white">
            Shift-left gates. <span className="bg-gradient-to-r from-cyan-300 to-emerald-300 bg-clip-text text-transparent">Shift-right response.</span>
          </h2>
          <ul className="space-y-4">
            {POINTS.map((p) => (
              <li key={p.title} className="flex gap-3">
                <span className="grid size-9 shrink-0 place-items-center rounded-xl border border-slate-700/80 bg-slate-900/70 text-cyan-300">
                  <Icon name={p.icon} className="size-4" />
                </span>
                <span>
                  <span className="block text-sm font-medium text-slate-100">{p.title}</span>
                  <span className="block text-sm text-slate-400">{p.text}</span>
                </span>
              </li>
            ))}
          </ul>
        </div>
        <p className="relative text-xs text-slate-500">DEPI AWS Cloud Security capstone · single-account build (ADR-0001)</p>
      </section>
      <div className="flex items-center justify-center px-4 py-10">
        <div className="glass accent-rim w-full max-w-lg space-y-5 p-6 md:p-8">
          <div>
            <p className="label-caps text-cyan-300/80">{local ? "Local development" : "Secure sign-in"}</p>
            <h1 className="mt-1 text-xl font-semibold tracking-tight text-white">Sign in to CloudShield</h1>
          </div>
          {children}
        </div>
      </div>
    </div>
  );
}
