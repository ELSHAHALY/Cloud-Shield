import type { IncidentSummary } from "../api/types";
import { Chip } from "../components/ui";

export const STATUSES = ["DETECTED", "CONTAINED", "WOULD_CONTAIN_DRY_RUN", "BLOCKED_BY_GUARD", "NO_PLAYBOOK_ANALYST_REVIEW", "FAILED"] as const;

const TONE: Record<string, "good" | "warn" | "bad" | "info" | "neutral"> = {
  CONTAINED: "good",
  WOULD_CONTAIN_DRY_RUN: "info",
  BLOCKED_BY_GUARD: "warn",
  NO_PLAYBOOK_ANALYST_REVIEW: "warn",
  FAILED: "bad",
  DETECTED: "neutral",
};

export function StatusChip({ incident }: { incident: Pick<IncidentSummary, "status" | "displayStatus"> }) {
  return <Chip tone={TONE[incident.status] ?? "neutral"}>{incident.displayStatus}</Chip>;
}
