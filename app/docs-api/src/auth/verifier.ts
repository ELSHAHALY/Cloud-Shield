// Token verification (plan D5/D22). Production: aws-jwt-verify's
// CognitoJwtVerifier (iss + JWKS derived from the pool id, aud = client id,
// token_use = id, never follows jku/x5u) plus an explicit iss re-check. Local:
// a generic RS256 verifier against the dev-only local IdP, which the config
// validator only allows next to a local emulator endpoint.
import { CognitoJwtVerifier } from "aws-jwt-verify";
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import type { Config } from "../config";
import type { VerifiedClaims } from "./principal";

export interface TokenVerifier {
  verify(token: string): Promise<VerifiedClaims>;
}

export class InvalidTokenError extends Error {
  constructor() {
    super("invalid token");
    this.name = "InvalidTokenError";
  }
}

type CognitoIdVerifier = ReturnType<typeof CognitoJwtVerifier.create<{ userPoolId: string; clientId: string; tokenUse: "id" }>>;

export class CognitoTokenVerifier implements TokenVerifier {
  readonly inner: CognitoIdVerifier;
  constructor(
    userPoolId: string,
    clientId: string,
    private readonly issuer: string,
  ) {
    this.inner = CognitoJwtVerifier.create({ userPoolId, clientId, tokenUse: "id" });
  }

  async verify(token: string): Promise<VerifiedClaims> {
    let payload: Record<string, unknown>;
    try {
      payload = (await this.inner.verify(token)) as unknown as Record<string, unknown>;
    } catch {
      throw new InvalidTokenError();
    }
    if (payload.iss !== this.issuer) throw new InvalidTokenError();
    return payload as VerifiedClaims;
  }
}

export class LocalTokenVerifier implements TokenVerifier {
  constructor(
    private readonly issuer: string,
    private readonly audience: string,
    private readonly keys: JWTVerifyGetKey,
  ) {}

  async verify(token: string): Promise<VerifiedClaims> {
    try {
      const { payload } = await jwtVerify(token, this.keys, {
        issuer: this.issuer,
        audience: this.audience,
        algorithms: ["RS256"],
        requiredClaims: ["exp", "iat", "sub"],
      });
      if (payload.token_use !== "id") throw new InvalidTokenError();
      return payload as VerifiedClaims;
    } catch {
      throw new InvalidTokenError();
    }
  }
}

export function createVerifier(config: Config): TokenVerifier {
  if (config.mode === "aws") {
    return new CognitoTokenVerifier(config.auth.userPoolId ?? "", config.auth.clientId, config.auth.issuer);
  }
  return new LocalTokenVerifier(
    config.auth.issuer,
    config.auth.clientId,
    createRemoteJWKSet(new URL(config.auth.jwksUri ?? ""), { timeoutDuration: 3000, cooldownDuration: 30_000 }),
  );
}

const BEARER_RE = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;

/** The compact JWT from an Authorization header, or undefined. Never logged. */
export function bearer(header: unknown): string | undefined {
  if (typeof header !== "string" || header.length > 8192) return undefined;
  return BEARER_RE.exec(header)?.[1];
}
