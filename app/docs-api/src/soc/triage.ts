// ATT&CK triage, evaluated from the table exported by
// soar/tools/export_attack_table.py (plan D17). First matching rule wins;
// CI --check keeps the JSON equal to soar/core/attack.py.
import table from "./attack-table.generated.json";

export interface TriageEntry {
  scenario: string;
  attack_techniques: string[];
  tactic: string;
  impact: string;
  eradication: string[];
  recovery: string[];
  references: string[];
}

interface TableRule {
  match: { prefix?: string; contains?: string };
  triage: TriageEntry;
  extraTechniquesWhenContains?: { contains: string; techniques: string[] }[];
}

const RULES = (table as { rules: TableRule[] }).rules;
const DEFAULT = (table as { default: TriageEntry }).default;

function copy(t: TriageEntry, extra: string[] = []): TriageEntry {
  return {
    scenario: t.scenario,
    attack_techniques: [...t.attack_techniques, ...extra.filter((x) => !t.attack_techniques.includes(x))],
    tactic: t.tactic,
    impact: t.impact,
    eradication: [...t.eradication],
    recovery: [...t.recovery],
    references: [...t.references],
  };
}

export function triage(findingType: unknown): TriageEntry {
  if (typeof findingType !== "string") return copy(DEFAULT);
  for (const rule of RULES) {
    const hit =
      rule.match.prefix !== undefined ? findingType.startsWith(rule.match.prefix) : rule.match.contains !== undefined && findingType.includes(rule.match.contains);
    if (!hit) continue;
    const extra = (rule.extraTechniquesWhenContains ?? []).filter((e) => findingType.includes(e.contains)).flatMap((e) => e.techniques);
    return copy(rule.triage, extra);
  }
  return copy(DEFAULT);
}
