import type { IncidentSummary } from "../api/types";
import { Chip, type Tone } from "../components/ui";

export const STATUSES = ["DETECTED", "CONTAINED", "WOULD_CONTAIN_DRY_RUN", "BLOCKED_BY_GUARD", "NO_PLAYBOOK_ANALYST_REVIEW", "FAILED"] as const;

// Cyan = in progress, emerald = contained, amber = dry run / needs an analyst,
// rose = failed. The chip always writes the API's displayStatus as text.
const TONE: Record<string, Tone> = {
  DETECTED: "info",
  CONTAINED: "good",
  WOULD_CONTAIN_DRY_RUN: "warn",
  BLOCKED_BY_GUARD: "warn",
  NO_PLAYBOOK_ANALYST_REVIEW: "warn",
  FAILED: "bad",
};

export function statusTone(status: string): Tone {
  return TONE[status] ?? "neutral";
}

export function StatusChip({ incident }: { incident: Pick<IncidentSummary, "status" | "displayStatus"> }) {
  return (
    <Chip tone={statusTone(incident.status)} dot title={incident.status}>
      {incident.displayStatus}
    </Chip>
  );
}
