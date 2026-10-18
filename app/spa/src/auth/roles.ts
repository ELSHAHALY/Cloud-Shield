// Display copy for the four Cognito groups. UX only: the server's RBAC table
// (app/docs-api/src/auth/principal.ts ROLE_PERMISSIONS) is the authority.
import type { IconName } from "../components/ui";

export interface RoleInfo {
  label: string;
  icon: IconName;
  summary: string;
  badges: string[];
}

export const ROLES: Record<string, RoleInfo> = {
  // Badges mirror ROLE_PERMISSIONS one-for-one (security review F7); "own docs" reflects
  // the server's owner check: only admins may change any tenant document.
  admin: { label: "Tenant admin", icon: "key", summary: "Runs the tenant: documents, agreements, GRC profile and audit.", badges: ["docs read/write/delete (any)", "audit read", "agreements read + accept", "GRC read + assess + profile"] },
  member: { label: "Member", icon: "user", summary: "Works with the tenant's documents.", badges: ["docs read", "docs write/delete (own)", "agreements read", "GRC read"] },
  auditor: { label: "Auditor", icon: "eye", summary: "Read-only review of documents, audit trail and GRC findings.", badges: ["docs read", "audit read", "agreements read", "GRC read + assess"] },
  "secops-analyst": { label: "SecOps analyst", icon: "radar", summary: "Platform security operations; no tenant documents (separation of duties).", badges: ["SOC read", "evidence verify", "posture read", "agreements read", "GRC read"] },
};

export function roleInfo(group: string): RoleInfo {
  return ROLES[group] ?? { label: group, icon: "user", summary: "", badges: [] };
}
