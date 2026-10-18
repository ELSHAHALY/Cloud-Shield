import { useEffect, useState } from "react";
import { Link } from "react-router";
import type { AgreementStatus, Permission } from "../api/types";
import { useSession } from "../auth/session";
import { roleInfo } from "../auth/roles";
import { Card, Icon, PageHeader, type IconName } from "../components/ui";

interface Tile {
  to: string;
  label: string;
  icon: IconName;
  need: Permission;
  line: string;
}

// Each line describes what the page really does; the server's RBAC decides access.
const TILES: Tile[] = [
  { to: "/documents", label: "Documents", icon: "file-lock", need: "doc:read", line: "Your tenant's files: SHA-256 checked on upload, SSE-KMS encrypted at rest on AWS." },
  { to: "/audit", label: "Audit trail", icon: "audit", need: "audit:read", line: "Who did what, when and from where in your tenant (last 30 days)." },
  { to: "/onboarding", label: "Agreements", icon: "agreement", need: "agreement:read", line: "The required agreements, read as plain text, and their acceptance status." },
  { to: "/grc", label: "GRC hub", icon: "scale", need: "grc:read", line: "Regional readiness self-assessment for EG, EU and SA. Not legal advice." },
  { to: "/soc", label: "SOC", icon: "radar", need: "soc:read", line: "Platform incidents, automated containment and security posture." },
];

const SECURITY_FACTS: { icon: IconName; title: string; text: string }[] = [
  { icon: "fingerprint", title: "Tokens verified server-side", text: "The API re-verifies every request's ID token (signature, issuer, audience, expiry) against the identity provider's keys; it never trusts an unverified decode." },
  { icon: "layers", title: "Tenant isolation by the API", text: "Your tenant comes only from the verified token claim. Isolation is enforced by the API on every request; it is not cryptographic separation." },
  { icon: "lock", title: "Encrypted at rest", text: "On AWS, documents are stored with SSE-KMS under the data CMK. The local stack uses an emulator, not real KMS." },
  { icon: "download", title: "Short-lived downloads", text: "A download is a version-pinned pre-signed URL that expires after 300 s by default. Every issued URL is audited." },
  { icon: "audit", title: "Every change is audited", text: "Each state-changing request writes an audit event (actor, action, resource, source IP, UTC time) to an insert-only table. It is not WORM storage." },
];

export function HomePage() {
  const { me, api, can } = useSession();
  const [status, setStatus] = useState<AgreementStatus | null>(null);

  useEffect(() => {
    if (!can("agreement:read")) return;
    api.get<AgreementStatus>("/agreements/status").then(setStatus).catch(() => setStatus(null));
  }, [api, can]);

  const tiles = TILES.filter((t) => can(t.need));

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Tenant portal"
        title="Welcome"
        subtitle={
          <>
            Signed in to tenant <span className="font-mono text-slate-200">{me.tenantId}</span>
          </>
        }
      />
      {status && !status.complete && (
        <p role="status" className="flex items-start gap-2.5 rounded-xl border border-amber-500/35 bg-amber-500/[0.08] p-3 text-sm text-amber-100">
          <Icon name="alert" className="mt-0.5 size-4 shrink-0 text-amber-300" />
          <span>
            Your tenant has not accepted the required agreements yet: document uploads and changes are blocked.{" "}
            <Link to="/onboarding" className="link-inline font-medium">
              {can("agreement:accept") ? "Review and accept them" : "See status"}
            </Link>
            .
          </span>
        </p>
      )}

      {tiles.length > 0 && (
        <nav aria-label="Quick access">
          <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {tiles.map((t) => (
              <li key={t.to}>
                <Link
                  to={t.to}
                  className="glass group flex h-full items-start gap-3 p-4 no-underline transition-colors duration-150 hover:border-cyan-500/40 hover:bg-slate-900/80 animate-fade-in"
                >
                  <span className="grid size-9 shrink-0 place-items-center rounded-lg border border-slate-700/70 bg-slate-800/70 text-cyan-300 transition-colors group-hover:border-cyan-500/50">
                    <Icon name={t.icon} className="size-5" />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center justify-between gap-2 text-sm font-semibold text-slate-100">
                      {t.label}
                      <Icon name="chevron" className="size-4 text-slate-500 transition-transform group-hover:translate-x-0.5 group-hover:text-cyan-300" />
                    </span>
                    <span className="mt-1 block text-xs leading-relaxed text-slate-400">{t.line}</span>
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </nav>
      )}

      <div className="grid gap-4 lg:grid-cols-5">
        <Card title="Your access" icon="key" accent="cyan" subtitle="What the portal shows you. The server's RBAC decides every request." className="lg:col-span-2">
          <dl className="space-y-4 text-sm">
            <div>
              <dt className="label-caps">Tenant</dt>
              <dd className="mt-1 font-mono text-slate-100">{me.tenantId}</dd>
            </div>
            <div>
              <dt className="label-caps">Groups</dt>
              <dd className="mt-1.5">
                {me.groups.length === 0 ? (
                  <span className="text-slate-400">none</span>
                ) : (
                  <ul className="space-y-2">
                    {me.groups.map((g) => {
                      const r = roleInfo(g);
                      return (
                        <li key={g} className="flex items-start gap-2">
                          <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-cyan-500/35 bg-cyan-500/10 px-2.5 py-0.5 text-xs font-medium text-cyan-200">
                            <Icon name={r.icon} className="size-3.5" />
                            {r.label}
                          </span>
                          {r.summary && <span className="text-xs text-slate-400">{r.summary}</span>}
                        </li>
                      );
                    })}
                  </ul>
                )}
              </dd>
            </div>
            <div>
              <dt className="label-caps">Permissions</dt>
              <dd className="mt-1.5">
                {me.permissions.length === 0 ? (
                  <span className="text-slate-400">none</span>
                ) : (
                  <ul className="flex flex-wrap gap-1.5">
                    {me.permissions.map((p) => (
                      <li key={p} className="rounded-md border border-slate-700/80 bg-slate-950/60 px-1.5 py-0.5 font-mono text-[11px] text-slate-300">
                        {p}
                      </li>
                    ))}
                  </ul>
                )}
              </dd>
            </div>
          </dl>
        </Card>

        <Card title="Security model" icon="shield-check" accent="emerald" subtitle="How this portal protects your tenant's data." className="lg:col-span-3">
          <ul className="grid gap-3 sm:grid-cols-2">
            {SECURITY_FACTS.map((f) => (
              <li key={f.title} className="flex items-start gap-2.5 rounded-lg border border-slate-800/80 bg-slate-950/40 p-3">
                <Icon name={f.icon} className="mt-0.5 size-4 shrink-0 text-emerald-300" />
                <span>
                  <span className="block text-sm font-medium text-slate-100">{f.title}</span>
                  <span className="mt-0.5 block text-xs leading-relaxed text-slate-400">{f.text}</span>
                </span>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </div>
  );
}
