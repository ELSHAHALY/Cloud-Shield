// Regional GRC hub (plan §8, §12). The disclaimer is always rendered; every
// citation still marked "verify" carries a visible badge.
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router";
import { ApiError } from "../api/client";
import type { GrcAssessment, GrcFinding, GrcProfile, GrcProfileRecord, RulesetSummary } from "../api/types";
import { useSession } from "../auth/session";
import { Card, Chip, Disclaimer, ErrorBox, Icon, Loading, PageHeader, ProgressRing, VerifyBadge } from "../components/ui";
import { buildReadinessPackJson, buildReadinessPackMarkdown, downloadText, packFilename } from "./readinessPack";

const STATUS_TONE: Record<GrcFinding["status"], "good" | "warn" | "bad" | "info" | "neutral"> = {
  MET: "good",
  PARTIAL: "warn",
  GAP: "bad",
  CUSTOMER_ACTION: "info",
  NOT_APPLICABLE: "neutral",
  INFO: "neutral",
};

const STATUS_ORDER: GrcFinding["status"][] = ["MET", "PARTIAL", "GAP", "CUSTOMER_ACTION", "INFO", "NOT_APPLICABLE"];

const JURISDICTIONS: { id: GrcProfile["jurisdictions"][number]; description: string }[] = [
  { id: "EG", description: "Egypt PDPL (Law 151/2020) · CBE" },
  { id: "EU", description: "GDPR" },
  { id: "SA", description: "KSA PDPL · NCA ECC" },
];

const EMPTY: GrcProfile = { jurisdictions: ["EG"], sector: "general", cbeRegulated: false, processesPersonalData: true, processesSensitiveData: false, governmentData: false, dataSubjectRegions: [] };

export function FindingRow({ f }: { f: GrcFinding }) {
  return (
    <li className="space-y-1.5 border-t border-slate-800/70 py-3 text-sm first:border-t-0">
      <div className="flex flex-wrap items-center gap-2">
        <Chip tone={STATUS_TONE[f.status]} dot>
          {f.status}
        </Chip>
        <span className="font-mono text-xs text-slate-300">{f.ruleId}</span>
        {f.citationStatus === "verify" && <VerifyBadge />}
      </div>
      <p className="text-slate-100">{f.obligation}</p>
      <p className="text-slate-400">{f.rationale}</p>
      <p className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-slate-400">
        {f.citations.map((c, i) => (
          <span key={i} className="inline-flex items-center gap-1">
            <Icon name="scale" className="size-3 text-slate-500" />
            {c.source}
            {c.article ? `, ${c.article}` : ""} [{c.status}]
          </span>
        ))}
      </p>
    </li>
  );
}

const toggleBase = "relative rounded-xl border p-3 transition-colors duration-150 has-[input:focus-visible]:outline-2 has-[input:focus-visible]:outline-offset-2 has-[input:focus-visible]:outline-cyan-400";
const toggleOn = "border-cyan-400/70 bg-cyan-500/10 shadow-[0_0_24px_-8px_rgb(34_211_238/0.8)]";
const toggleOff = "border-slate-700/80 bg-slate-950/40 hover:border-slate-600";

function CheckMark({ on }: { on: boolean }) {
  return (
    <span className={`grid size-5 shrink-0 place-items-center rounded-md border transition-colors ${on ? "border-cyan-300 bg-cyan-400 text-slate-950" : "border-slate-600 bg-slate-900 text-transparent"}`}>
      <Icon name="check" className="size-3.5" />
    </span>
  );
}

function ProfileForm({ initial, onSaved }: { initial: GrcProfile; onSaved(r: GrcProfileRecord): void }) {
  const { api } = useSession();
  const [p, setP] = useState<GrcProfile>(initial);
  const [error, setError] = useState<unknown>(null);
  const toggle = <K extends "jurisdictions" | "dataSubjectRegions">(key: K, v: GrcProfile[K][number]) =>
    setP((cur) => {
      const list = cur[key] as string[];
      return { ...cur, [key]: list.includes(v) ? list.filter((x) => x !== v) : [...list, v] };
    });

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      onSaved(await api.put<GrcProfileRecord>("/grc/profile", p));
    } catch (err) {
      setError(err);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-5 text-sm" aria-label="GRC profile">
      <ErrorBox error={error} />
      <fieldset>
        <legend className="label-caps">Jurisdictions</legend>
        <div className="mt-2 grid gap-3 sm:grid-cols-3">
          {JURISDICTIONS.map(({ id: j, description }) => {
            const on = p.jurisdictions.includes(j);
            return (
              <div key={j} className={`${toggleBase} ${on ? toggleOn : toggleOff}`}>
                {/* The label text stays exactly the code; the description is linked by aria-describedby. */}
                <label className="flex cursor-pointer items-center justify-between gap-2 text-base font-semibold tracking-wide text-slate-100 after:absolute after:inset-0 after:rounded-xl">
                  <input type="checkbox" className="sr-only" aria-describedby={`jurisdiction-${j}-desc`} checked={on} onChange={() => toggle("jurisdictions", j)} />
                  {j}
                  <CheckMark on={on} />
                </label>
                <p id={`jurisdiction-${j}-desc`} className={`mt-1 text-xs ${on ? "text-cyan-100/90" : "text-slate-400"}`}>
                  {description}
                </p>
              </div>
            );
          })}
        </div>
        {p.jurisdictions.length === 0 && <p className="mt-2 text-xs text-amber-200">Select at least one jurisdiction.</p>}
      </fieldset>

      <div className="grid gap-5 lg:grid-cols-2">
        <div className="space-y-3">
          <label className="block text-slate-300">
            Sector
            <select className="mt-1.5 block w-full px-3 py-1.5" value={p.sector} onChange={(e) => setP({ ...p, sector: e.target.value as GrcProfile["sector"] })}>
              {(["general", "financial", "health", "government", "critical-infrastructure"] as const).map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
          <fieldset>
            <legend className="label-caps">Data subjects in</legend>
            <div className="mt-2 flex flex-wrap gap-2">
              {(["EG", "EU", "SA", "OTHER"] as const).map((j) => {
                const on = p.dataSubjectRegions.includes(j);
                return (
                  <label
                    key={j}
                    className={`inline-flex cursor-pointer items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition-colors has-[input:focus-visible]:outline-2 has-[input:focus-visible]:outline-offset-2 has-[input:focus-visible]:outline-cyan-400 ${on ? "border-cyan-400/70 bg-cyan-500/15 text-cyan-100" : "border-slate-700 bg-slate-950/40 text-slate-300 hover:border-slate-600"}`}
                  >
                    <input type="checkbox" className="sr-only" checked={on} onChange={() => toggle("dataSubjectRegions", j)} />
                    <Icon name={on ? "check" : "globe"} className="size-3.5" />
                    {j}
                  </label>
                );
              })}
            </div>
          </fieldset>
        </div>
        <fieldset className="space-y-2">
          <legend className="label-caps">Data and regulation</legend>
          {(
            [
              ["cbeRegulated", "Regulated by the Central Bank of Egypt"],
              ["processesPersonalData", "Processes personal data"],
              ["processesSensitiveData", "Processes sensitive personal data"],
              ["governmentData", "Holds government data"],
            ] as const
          ).map(([k, label]) => (
            <label key={k} className={`flex cursor-pointer items-center gap-2.5 rounded-lg border px-3 py-2 transition-colors ${p[k] ? "border-cyan-500/40 bg-cyan-500/[0.06] text-slate-100" : "border-slate-800 bg-slate-950/30 text-slate-300 hover:border-slate-700"}`}>
              <input type="checkbox" className="size-4" checked={p[k]} onChange={(e) => setP({ ...p, [k]: e.target.checked })} /> {label}
            </label>
          ))}
        </fieldset>
      </div>
      <button type="submit" disabled={p.jurisdictions.length === 0} className="btn-primary px-4">
        Save profile
      </button>
    </form>
  );
}

interface FrameworkReadiness {
  id: string;
  findings: GrcFinding[];
  applicable: number;
  met: number;
  counts: Partial<Record<GrcFinding["status"], number>>;
}

/** MET / applicable, where applicable = status ≠ NOT_APPLICABLE. A readiness share, not a compliance score. */
function readiness(findings: GrcFinding[], id: string): FrameworkReadiness {
  const counts: Partial<Record<GrcFinding["status"], number>> = {};
  for (const f of findings) counts[f.status] = (counts[f.status] ?? 0) + 1;
  const applicable = findings.filter((f) => f.status !== "NOT_APPLICABLE").length;
  return { id, findings, applicable, met: counts.MET ?? 0, counts };
}

function ReadinessRing({ met, applicable, size = 64 }: { met: number; applicable: number; size?: number }) {
  return (
    <div className="relative shrink-0">
      <ProgressRing value={applicable ? met / applicable : 0} size={size} stroke={6} tone="good" />
      <span className="absolute inset-0 grid place-items-center text-xs font-semibold tabular-nums text-slate-100" aria-hidden="true">
        {met}/{applicable}
      </span>
    </div>
  );
}

function readinessCaption(met: number, applicable: number): string {
  return applicable === 0 ? "No applicable rules for this profile" : `${met} of ${applicable} applicable rules MET`;
}

function FrameworkCard({ r, meta }: { r: FrameworkReadiness; meta?: { title: string; regulator: string } }) {
  const hidden = r.counts.NOT_APPLICABLE ?? 0;
  return (
    <Card title={r.id} icon="scale" accent={r.counts.GAP ? "rose" : r.applicable > 0 && r.met === r.applicable ? "emerald" : "cyan"} subtitle={meta ? `${meta.title} · ${meta.regulator}` : undefined}>
      <div className="flex flex-wrap items-center gap-4 rounded-lg border border-slate-800/80 bg-slate-950/40 p-3">
        <ReadinessRing met={r.met} applicable={r.applicable} />
        <div className="min-w-0 flex-1 space-y-2">
          <p className="text-sm font-medium text-slate-100 tabular-nums">{readinessCaption(r.met, r.applicable)}</p>
          <ul className="flex flex-wrap gap-1.5" aria-label={`${r.id} status counts`}>
            {STATUS_ORDER.filter((s) => r.counts[s]).map((s) => (
              <li key={s}>
                <Chip tone={STATUS_TONE[s]}>
                  <span className="tabular-nums">{r.counts[s]}</span> {s === "NOT_APPLICABLE" ? "not applicable (hidden)" : s}
                </Chip>
              </li>
            ))}
          </ul>
        </div>
      </div>
      <ul className="mt-2">
        {r.findings
          .filter((f) => f.status !== "NOT_APPLICABLE")
          .map((f) => (
            <FindingRow key={f.ruleId} f={f} />
          ))}
      </ul>
      {r.applicable === 0 && hidden > 0 && <p className="mt-2 text-xs text-slate-400">Every rule in this framework is not applicable to your profile.</p>}
    </Card>
  );
}

export function GrcHub() {
  const { api, can, me } = useSession();
  const [ruleset, setRuleset] = useState<RulesetSummary | null>(null);
  const [profile, setProfile] = useState<GrcProfileRecord | null | undefined>(undefined);
  const [assessment, setAssessment] = useState<GrcAssessment | null>(null);
  const [error, setError] = useState<unknown>(null);

  const loadAssessment = useCallback(() => {
    if (!can("grc:assess")) return;
    api
      .get<GrcProfileRecord>("/grc/profile")
      .then((r) => {
        setProfile(r);
        return api.get<GrcAssessment>("/grc/assessment").then(setAssessment);
      })
      .catch((e: unknown) => {
        if (e instanceof ApiError && e.code === "NOT_FOUND") setProfile(null);
        else setError(e);
      });
  }, [api, can]);

  useEffect(() => {
    api.get<RulesetSummary>("/grc/ruleset").then(setRuleset).catch(setError);
    loadAssessment();
  }, [api, loadAssessment]);

  const frameworks = assessment ? [...new Set(assessment.findings.map((f) => f.framework))] : [];
  const perFramework = assessment ? frameworks.map((fw) => readiness(assessment.findings.filter((f) => f.framework === fw), fw)) : [];
  const overall = assessment ? readiness(assessment.findings, "all") : null;

  function exportPack(format: "md" | "json") {
    if (!assessment || !ruleset) return;
    setError(null);
    try {
      const exportedAt = new Date().toISOString();
      const text = format === "md" ? buildReadinessPackMarkdown(assessment, ruleset, me.tenantId, exportedAt) : buildReadinessPackJson(assessment, ruleset, me.tenantId, exportedAt);
      downloadText(text, format === "md" ? "text/markdown;charset=utf-8" : "application/json", packFilename(me.tenantId, assessment.rulesetVersion, format));
    } catch (e) {
      setError(e);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Governance"
        title={<>Regional GRC &amp; cloud compliance advisor</>}
        subtitle="Readiness self-assessment against Egyptian, EU and Saudi data-protection rules, from your tenant profile and the platform's own facts."
        actions={
          <Link to="/grc/matrix" className="btn-secondary no-underline">
            <Icon name="grid" className="size-4" />
            Shared-responsibility matrix
          </Link>
        }
      />
      <Disclaimer text={ruleset?.disclaimer ?? "Informational mapping for an academic capstone. Items marked verify have not been checked against the official text."} />
      <ErrorBox error={error} />
      {ruleset && (
        <p className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
          <Icon name="hash" className="size-3.5 text-slate-500" />
          Ruleset {ruleset.version} · last reviewed {ruleset.lastReviewed} · SHA-256 <span className="font-mono text-slate-300">{ruleset.sha256.slice(0, 16)}…</span> · {ruleset.ruleCount} rules
        </p>
      )}
      {can("grc:profile:write") && profile !== undefined && (
        <Card title={profile ? `Tenant profile (version ${profile.version})` : "Set your tenant profile"} icon="globe" accent="cyan" subtitle="The jurisdictions and data you choose decide which rules apply.">
          <ProfileForm
            initial={profile?.profile ?? EMPTY}
            onSaved={(r) => {
              setProfile(r);
              loadAssessment();
            }}
          />
        </Card>
      )}
      {!can("grc:assess") && <p className="glass p-4 text-sm text-slate-300">Your role can read the ruleset and the matrix; assessments are visible to tenant administrators and auditors.</p>}
      {can("grc:assess") && profile === null && !can("grc:profile:write") && <p className="glass p-4 text-sm text-slate-300">Your tenant administrator has not set a GRC profile yet.</p>}
      {can("grc:assess") && profile !== null && !assessment && !error && <Loading />}
      {assessment && overall && (
        <>
          <Card title="Summary" icon="target" accent="cyan" subtitle={`Profile version ${assessment.profileVersion} · ruleset ${assessment.rulesetVersion}`}>
            <div className="flex flex-wrap items-center gap-5">
              <ReadinessRing met={overall.met} applicable={overall.applicable} size={80} />
              <div className="min-w-0 flex-1 space-y-2">
                <p className="text-base font-semibold text-slate-100 tabular-nums">{readinessCaption(overall.met, overall.applicable)}</p>
                <ul className="flex flex-wrap gap-2">
                  {(Object.keys(assessment.summary) as (keyof GrcAssessment["summary"])[]).map((k) => (
                    <li key={k}>
                      <Chip tone={STATUS_TONE[k]}>
                        {k}: {assessment.summary[k]}
                      </Chip>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
            <div className="mt-5 rounded-xl border border-cyan-500/25 bg-cyan-500/[0.05] p-4">
              <p className="flex items-center gap-2 text-sm font-semibold text-slate-100">
                <Icon name="download" className="size-4 text-cyan-300" />
                Compliance Readiness Pack
              </p>
              <p className="mt-1 text-xs text-slate-400">Compliance Readiness Pack: a self-assessment exported from this page. Not legal advice. Not an audit or certification.</p>
              {ruleset && (
                <div className="mt-3 flex flex-wrap gap-2">
                  <button type="button" onClick={() => exportPack("md")} className="btn-primary px-4">
                    <Icon name="download" className="size-4" />
                    Download readiness pack (Markdown)
                  </button>
                  <button type="button" onClick={() => exportPack("json")} className="btn-secondary px-4">
                    <Icon name="download" className="size-4" />
                    Download readiness pack (JSON)
                  </button>
                </div>
              )}
            </div>
            <p className="mt-3 text-xs text-slate-400">
              Deployed in {assessment.platformFacts.deploymentRegions?.toString()} · incident automation {String(assessment.platformFacts.incidentAutomation)} · generated {assessment.generatedAt}
            </p>
          </Card>
          <div className="grid gap-4 xl:grid-cols-2">
            {perFramework.map((r) => {
              const fw = ruleset?.frameworks.find((f) => f.id === r.id);
              return <FrameworkCard key={r.id} r={r} meta={fw ? { title: fw.title, regulator: fw.regulator } : undefined} />;
            })}
          </div>
        </>
      )}
    </div>
  );
}
