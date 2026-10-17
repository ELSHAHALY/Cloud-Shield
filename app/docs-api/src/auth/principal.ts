// The verified caller (plan D6/D7). `TenantId` is a branded type that can only
// be built here, from a verified claim, so no handler can pass a tenant taken
// from a path, query, header or body to a repository function.
import { AppError } from "../lib/errors";

declare const tenantBrand: unique symbol;
export type TenantId = string & { readonly [tenantBrand]: true };

// eslint-disable-next-line security/detect-unsafe-regex -- bounded and unambiguous: linear time
export const TENANT_RE = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
/** Platform-scoped audit partition. The leading underscore keeps it out of TENANT_RE. */
export const PLATFORM_PARTITION = "_platform" as TenantId;

export const GROUPS = ["admin", "member", "auditor", "secops-analyst"] as const;
export type Group = (typeof GROUPS)[number];

export const PERMISSIONS = [
  "doc:read",
  "doc:write",
  "doc:delete",
  "audit:read",
  "agreement:read",
  "agreement:accept",
  "grc:read",
  "grc:assess",
  "grc:profile:write",
  "soc:read",
  "soc:evidence",
  "posture:read",
] as const;
export type Permission = (typeof PERMISSIONS)[number];

/** Plan §4.2. secops-analyst has no tenant-document access (separation of duties). */
export const ROLE_PERMISSIONS: Readonly<Record<Group, readonly Permission[]>> = {
  admin: ["doc:read", "doc:write", "doc:delete", "audit:read", "agreement:read", "agreement:accept", "grc:read", "grc:assess", "grc:profile:write"],
  member: ["doc:read", "doc:write", "doc:delete", "agreement:read", "grc:read"],
  auditor: ["doc:read", "audit:read", "agreement:read", "grc:read", "grc:assess"],
  "secops-analyst": ["agreement:read", "grc:read", "soc:read", "soc:evidence", "posture:read"],
};

export interface Principal {
  readonly sub: string;
  readonly email?: string;
  readonly tenantId: TenantId;
  readonly groups: readonly Group[];
  readonly permissions: ReadonlySet<Permission>;
  readonly jti?: string;
}

export interface VerifiedClaims {
  sub?: unknown;
  email?: unknown;
  "custom:tenant_id"?: unknown;
  "cognito:groups"?: unknown;
  jti?: unknown;
}

export function toPrincipal(claims: VerifiedClaims): Principal {
  const sub = claims.sub;
  if (typeof sub !== "string" || sub.length === 0 || sub.length > 128) {
    throw new AppError("UNAUTHENTICATED");
  }
  const tenant = claims["custom:tenant_id"];
  if (typeof tenant !== "string" || !TENANT_RE.test(tenant)) {
    throw new AppError("TENANT_INVALID");
  }
  const raw = Array.isArray(claims["cognito:groups"]) ? claims["cognito:groups"] : [];
  const groups = GROUPS.filter((g) => raw.includes(g));
  const permissions = new Set<Permission>();
  for (const g of groups) for (const p of ROLE_PERMISSIONS[g]) permissions.add(p);
  const principal: Principal = {
    sub,
    tenantId: tenant as TenantId,
    groups: Object.freeze([...groups]),
    permissions,
    ...(typeof claims.email === "string" && claims.email.length <= 256 ? { email: claims.email } : {}),
    ...(typeof claims.jti === "string" && claims.jti.length <= 128 ? { jti: claims.jti } : {}),
  };
  return Object.freeze(principal);
}

/** Members may only write documents they own (ABAC); admins may write any in the tenant. */
export function canWriteAny(p: Principal): boolean {
  return p.groups.includes("admin");
}
