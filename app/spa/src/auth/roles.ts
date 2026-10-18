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
  admin: { label: "Tenant admin", icon: "key", summary: "Runs the tenant: documents, agreements, GRC profile and audit.", badges: ["docs read/write/delete", "audit read", "accept agreements", "GRC assess + profile"] },
  member: { label: "Member", icon: "user", summary: "Works with the tenant's documents.", badges: ["docs read/write/delete", "GRC read"] },
  auditor: { label: "Auditor", icon: "eye", summary: "Read-only review of documents, audit trail and GRC findings.", badges: ["docs read", "audit read", "GRC assess"] },
  "secops-analyst": { label: "SecOps analyst", icon: "radar", summary: "Platform security operations; no tenant documents (separation of duties).", badges: ["SOC read", "evidence verify", "posture read"] },
};

export function roleInfo(group: string): RoleInfo {
  return ROLES[group] ?? { label: group, icon: "user", summary: "", badges: [] };
}
