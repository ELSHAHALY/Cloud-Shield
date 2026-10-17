// Regional GRC hub (plan §8, §12). The disclaimer is always rendered; every
// citation still marked "verify" carries a visible badge.
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router";
import { ApiError } from "../api/client";
import type { GrcAssessment, GrcFinding, GrcProfile, GrcProfileRecord, RulesetSummary } from "../api/types";
import { useSession } from "../auth/session";
import { Card, Chip, Disclaimer, ErrorBox, Loading, VerifyBadge } from "../components/ui";
import { buildReadinessPackJson, buildReadinessPackMarkdown, downloadText, packFilename } from "./readinessPack";

const STATUS_TONE: Record<GrcFinding["status"], "good" | "warn" | "bad" | "info" | "neutral"> = {
  MET: "good",
  PARTIAL: "warn",
  GAP: "bad",
  CUSTOMER_ACTION: "info",
  NOT_APPLICABLE: "neutral",
  INFO: "neutral",
};

const EMPTY: GrcProfile = { jurisdictions: ["EG"], sector: "general", cbeRegulated: false, processesPersonalData: true, processesSensitiveData: false, governmentData: false, dataSubjectRegions: [] };

export function FindingRow({ f }: { f: GrcFinding }) {
  return (
    <li className="space-y-1 border-t border-slate-100 py-2 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <Chip tone={STATUS_TONE[f.status]}>{f.status}</Chip>
        <span className="font-mono text-xs">{f.ruleId}</span>
        {f.citationStatus === "verify" && <VerifyBadge />}
      </div>
      <p>{f.obligation}</p>
      <p className="text-slate-700">{f.rationale}</p>
      <p className="text-xs text-slate-600">
        {f.citations.map((c, i) => (
          <span key={i} className="mr-2">
            {c.source}
            {c.article ? `, ${c.article}` : ""} [{c.status}]
          </span>
        ))}
      </p>
    </li>
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
    <form onSubmit={submit} className="space-y-3 text-sm" aria-label="GRC profile">
      <ErrorBox error={error} />
      <fieldset>
        <legend className="font-medium">Jurisdictions</legend>
        {(["EG", "EU", "SA"] as const).map((j) => (
          <label key={j} className="mr-4 inline-flex items-center gap-1">
            <input type="checkbox" checked={p.jurisdictions.includes(j)} onChange={() => toggle("jurisdictions", j)} /> {j}
          </label>
        ))}
      </fieldset>
      <label className="block">
        Sector
        <select className="ml-2 rounded border border-slate-300 px-2 py-1" value={p.sector} onChange={(e) => setP({ ...p, sector: e.target.value as GrcProfile["sector"] })}>
          {(["general", "financial", "health", "government", "critical-infrastructure"] as const).map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
      </label>
      {(
        [
          ["cbeRegulated", "Regulated by the Central Bank of Egypt"],
          ["processesPersonalData", "Processes personal data"],
          ["processesSensitiveData", "Processes sensitive personal data"],
          ["governmentData", "Holds government data"],
        ] as const
      ).map(([k, label]) => (
        <label key={k} className="flex items-center gap-2">
          <input type="checkbox" checked={p[k]} onChange={(e) => setP({ ...p, [k]: e.target.checked })} /> {label}
        </label>
      ))}
      <fieldset>
        <legend className="font-medium">Data subjects in</legend>
        {(["EG", "EU", "SA", "OTHER"] as const).map((j) => (
          <label key={j} className="mr-4 inline-flex items-center gap-1">
            <input type="checkbox" checked={p.dataSubjectRegions.includes(j)} onChange={() => toggle("dataSubjectRegions", j)} /> {j}
          </label>
        ))}
      </fieldset>
      <button type="submit" disabled={p.jurisdictions.length === 0} className="rounded bg-indigo-700 px-4 py-2 text-white disabled:opacity-50">
        Save profile
      </button>
    </form>
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
    <div className="space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">Regional GRC &amp; cloud compliance advisor</h1>
        <Link to="/grc/matrix" className="text-sm underline">
          Shared-responsibility matrix
        </Link>
      </div>
      <Disclaimer text={ruleset?.disclaimer ?? "Informational mapping for an academic capstone. Items marked verify have not been checked against the official text."} />
      <ErrorBox error={error} />
      {ruleset && (
        <p className="text-xs text-slate-600">
          Ruleset {ruleset.version} · last reviewed {ruleset.lastReviewed} · SHA-256 <span className="font-mono">{ruleset.sha256.slice(0, 16)}…</span> · {ruleset.ruleCount} rules
        </p>
      )}
      {can("grc:profile:write") && profile !== undefined && (
        <Card title={profile ? `Tenant profile (version ${profile.version})` : "Set your tenant profile"}>
          <ProfileForm
            initial={profile?.profile ?? EMPTY}
            onSaved={(r) => {
              setProfile(r);
              loadAssessment();
            }}
          />
        </Card>
      )}
      {!can("grc:assess") && <p className="text-sm text-slate-700">Your role can read the ruleset and the matrix; assessments are visible to tenant administrators and auditors.</p>}
      {can("grc:assess") && profile === null && !can("grc:profile:write") && <p className="text-sm">Your tenant administrator has not set a GRC profile yet.</p>}
      {can("grc:assess") && profile !== null && !assessment && !error && <Loading />}
      {assessment && (
        <>
          <Card
            title="Summary"
            actions={
              ruleset && (
                <div className="flex gap-2">
                  <button type="button" onClick={() => exportPack("md")} className="rounded bg-indigo-700 px-3 py-1 text-sm text-white">
                    Download readiness pack (Markdown)
                  </button>
                  <button type="button" onClick={() => exportPack("json")} className="rounded border border-slate-300 px-3 py-1 text-sm">
                    Download readiness pack (JSON)
                  </button>
                </div>
              )
            }
          >
            <ul className="flex flex-wrap gap-2">
              {(Object.keys(assessment.summary) as (keyof GrcAssessment["summary"])[]).map((k) => (
                <li key={k}>
                  <Chip tone={STATUS_TONE[k]}>
                    {k}: {assessment.summary[k]}
                  </Chip>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-xs text-slate-600">Compliance Readiness Pack: a self-assessment exported from this page. Not legal advice. Not an audit or certification.</p>
            <p className="mt-2 text-xs text-slate-600">
              Deployed in {assessment.platformFacts.deploymentRegions?.toString()} · incident automation {String(assessment.platformFacts.incidentAutomation)} · generated {assessment.generatedAt}
            </p>
          </Card>
          {frameworks.map((fw) => (
            <Card key={fw} title={fw}>
              <ul>
                {assessment.findings
                  .filter((f) => f.framework === fw && f.status !== "NOT_APPLICABLE")
                  .map((f) => (
                    <FindingRow key={f.ruleId} f={f} />
                  ))}
              </ul>
            </Card>
          ))}
        </>
      )}
    </div>
  );
}
