import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWK, type KeyLike } from "jose";
import { LocalTokenVerifier } from "../../src/auth/verifier";

export const ISSUER = "http://local-idp:9000";
export const AUDIENCE = "cloudshield-local-spa";

export interface Keys {
  privateKey: KeyLike;
  jwk: JWK;
}

export async function makeKeys(kid = "test-key"): Promise<Keys> {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: "RS256", use: "sig" };
  return { privateKey, jwk };
}

export function verifierFor(keys: Keys): LocalTokenVerifier {
  return new LocalTokenVerifier(ISSUER, AUDIENCE, createLocalJWKSet({ keys: [keys.jwk] }));
}

export interface TokenOptions {
  sub?: string;
  tenant?: string | null;
  groups?: readonly string[];
  email?: string;
  iss?: string;
  aud?: string;
  tokenUse?: string;
  expSeconds?: number;
  kid?: string;
}

export async function mint(keys: Keys, o: TokenOptions = {}): Promise<string> {
  const claims: Record<string, unknown> = {
    token_use: o.tokenUse ?? "id",
    "cognito:groups": [...(o.groups ?? [])],
    email: o.email ?? `${o.sub ?? "user"}@example.test`,
  };
  if (o.tenant !== null) claims["custom:tenant_id"] = o.tenant ?? "t-acme-01";
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: o.kid ?? String(keys.jwk.kid) })
    .setIssuer(o.iss ?? ISSUER)
    .setAudience(o.aud ?? AUDIENCE)
    .setSubject(o.sub ?? "user-1")
    .setIssuedAt(now)
    .setExpirationTime(now + (o.expSeconds ?? 3600))
    .setJti(`jti-${Math.random().toString(36).slice(2)}`)
    .sign(keys.privateKey);
}

export const USERS = {
  alice: { sub: "sub-alice", tenant: "t-acme-01", groups: ["admin"] },
  bob: { sub: "sub-bob", tenant: "t-acme-01", groups: ["member"] },
  bea: { sub: "sub-bea", tenant: "t-acme-01", groups: ["member"] },
  carol: { sub: "sub-carol", tenant: "t-acme-01", groups: ["auditor"] },
  dina: { sub: "sub-dina", tenant: "t-nile-02", groups: ["admin"] },
  mallory: { sub: "sub-mallory", tenant: "t-nile-02", groups: ["member"] },
  sam: { sub: "sub-sam", tenant: "t-cloudshield-soc", groups: ["secops-analyst"] },
  nobody: { sub: "sub-nobody", tenant: "t-acme-01", groups: [] as string[] },
} as const;
export type UserName = keyof typeof USERS;
