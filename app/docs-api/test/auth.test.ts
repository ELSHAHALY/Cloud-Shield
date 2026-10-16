import { generateKeyPair, exportJWK, SignJWT, exportSPKI, UnsecuredJWT } from "jose";
import { CognitoTokenVerifier, InvalidTokenError, bearer, createVerifier } from "../src/auth/verifier";
import { toPrincipal, ROLE_PERMISSIONS, PLATFORM_PARTITION } from "../src/auth/principal";
import { AppError } from "../src/lib/errors";
import { mint, makeKeys, verifierFor } from "./helpers/tokens";
import type { Config } from "../src/config";

const POOL = "us-east-1_TestPool1";
const CLIENT = "clientidabc123";
const ISS = `https://cognito-idp.us-east-1.amazonaws.com/${POOL}`;

async function cognitoSetup() {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" };
  const v = new CognitoTokenVerifier(POOL, CLIENT, ISS);
  v.inner.cacheJwks({ keys: [jwk as never] }, POOL);
  const sign = (claims: Record<string, unknown>, o: { iss?: string; aud?: string; exp?: number; kid?: string; key?: typeof privateKey } = {}) => {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ token_use: "id", "custom:tenant_id": "t-acme-01", "cognito:groups": ["member"], ...claims })
      .setProtectedHeader({ alg: "RS256", kid: o.kid ?? "k1" })
      .setIssuer(o.iss ?? ISS)
      .setAudience(o.aud ?? CLIENT)
      .setSubject("sub-1")
      .setIssuedAt(now - 10)
      .setExpirationTime(o.exp ?? now + 600)
      .sign(o.key ?? privateKey);
  };
  return { v, sign, publicKey };
}

describe("production verifier (CognitoJwtVerifier + explicit iss)", () => {
  it("accepts a valid Cognito ID token", async () => {
    const { v, sign } = await cognitoSetup();
    const claims = await v.verify(await sign({}));
    expect(claims["custom:tenant_id"]).toBe("t-acme-01");
  });

  it("rejects every forgery and misuse with InvalidTokenError", async () => {
    const { v, sign, publicKey } = await cognitoSetup();
    const other = await generateKeyPair("RS256");
    const now = Math.floor(Date.now() / 1000);
    const hs = await new SignJWT({ token_use: "id" })
      .setProtectedHeader({ alg: "HS256", kid: "k1" })
      .setIssuer(ISS)
      .setAudience(CLIENT)
      .setExpirationTime(now + 600)
      .sign(new TextEncoder().encode(await exportSPKI(publicKey)));
    const none = new UnsecuredJWT({ token_use: "id", iss: ISS, aud: CLIENT, exp: now + 600 }).encode();
    const valid = await sign({});
    const [h, p, s] = valid.split(".");
    const payload = JSON.parse(Buffer.from(p!, "base64url").toString());
    payload["custom:tenant_id"] = "t-nile-02";
    const tampered = `${h}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${s}`;
    const cases: [string, string][] = [
      ["wrong aud", await sign({}, { aud: "another-client" })],
      ["wrong iss", await sign({}, { iss: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Other" })],
      ["access token", await sign({ token_use: "access" })],
      ["expired", await sign({}, { exp: now - 3600 })],
      ["alg none", none],
      ["HS256 with the public key", hs],
      ["tampered payload", tampered],
      ["local-idp issuer", await sign({}, { iss: "http://local-idp:9000" })],
      ["other key, right iss/kid", await sign({}, { key: other.privateKey })],
      ["garbage", "a.b.c"],
    ];
    for (const [name, token] of cases) {
      await expect(v.verify(token)).rejects.toBeInstanceOf(InvalidTokenError);
      void name;
    }
  });

  it("is what createVerifier returns in aws mode", () => {
    const v = createVerifier({ mode: "aws", auth: { userPoolId: POOL, clientId: CLIENT, issuer: ISS } } as Config);
    expect(v).toBeInstanceOf(CognitoTokenVerifier);
  });
});

describe("local verifier", () => {
  it("accepts local-idp tokens and rejects tampering, other audiences and access tokens", async () => {
    const keys = await makeKeys();
    const v = verifierFor(keys);
    expect((await v.verify(await mint(keys, { sub: "u1" }))).sub).toBe("u1");
    await expect(v.verify(await mint(keys, { aud: "other" }))).rejects.toBeInstanceOf(InvalidTokenError);
    await expect(v.verify(await mint(keys, { tokenUse: "access" }))).rejects.toBeInstanceOf(InvalidTokenError);
    await expect(v.verify(await mint(keys, { iss: ISS }))).rejects.toBeInstanceOf(InvalidTokenError);
    await expect(v.verify(await mint(keys, { kid: "unknown" }))).rejects.toBeInstanceOf(InvalidTokenError);
    await expect(v.verify(await mint(keys, { expSeconds: -60 }))).rejects.toBeInstanceOf(InvalidTokenError);
    const other = await makeKeys();
    await expect(v.verify(await mint(other, {}))).rejects.toBeInstanceOf(InvalidTokenError);
  });

  it("is what createVerifier returns in local mode", () => {
    const v = createVerifier({ mode: "local", auth: { clientId: "c", issuer: "http://local-idp:9000", jwksUri: "http://local-idp:9000/.well-known/jwks.json" } } as Config);
    expect(v).not.toBeInstanceOf(CognitoTokenVerifier);
  });
});

describe("bearer()", () => {
  it("extracts only a well-formed compact JWT", () => {
    expect(bearer("Bearer a.b.c")).toBe("a.b.c");
    expect(bearer("bearer a.b.c")).toBeUndefined();
    expect(bearer("Bearer a.b")).toBeUndefined();
    expect(bearer("Basic xyz")).toBeUndefined();
    expect(bearer(undefined)).toBeUndefined();
    expect(bearer("Bearer " + "a".repeat(9000) + ".b.c")).toBeUndefined();
  });
});

describe("principal (D6/D7)", () => {
  const tenantError = (claims: Record<string, unknown>) => {
    try {
      toPrincipal({ sub: "s", ...claims });
    } catch (e) {
      return (e as AppError).code;
    }
    return "none";
  };

  it("takes the tenant only from custom:tenant_id and enforces the format", () => {
    expect(tenantError({})).toBe("TENANT_INVALID");
    expect(tenantError({ "custom:tenant_id": "T-ACME" })).toBe("TENANT_INVALID");
    expect(tenantError({ "custom:tenant_id": "_platform" })).toBe("TENANT_INVALID");
    expect(tenantError({ "custom:tenant_id": PLATFORM_PARTITION })).toBe("TENANT_INVALID");
    expect(tenantError({ "custom:tenant_id": "-acme" })).toBe("TENANT_INVALID");
    expect(tenantError({ "custom:tenant_id": "a".repeat(65) })).toBe("TENANT_INVALID");
    expect(tenantError({ "custom:tenant_id": 7 })).toBe("TENANT_INVALID");
    expect(tenantError({ "custom:tenant_id": "t-acme-01" })).toBe("none");
    expect(() => toPrincipal({ "custom:tenant_id": "t" })).toThrow(AppError);
  });

  it("ignores unknown groups and unions permissions", () => {
    const p = toPrincipal({ sub: "s", "custom:tenant_id": "t1", "cognito:groups": ["auditor", "member", "root", "Admin"], email: "a@b.c", jti: "j" });
    expect(p.groups).toEqual(["member", "auditor"]);
    expect([...p.permissions].sort()).toEqual([...new Set([...ROLE_PERMISSIONS.member, ...ROLE_PERMISSIONS.auditor])].sort());
    expect(p.email).toBe("a@b.c");
    expect(Object.isFrozen(p)).toBe(true);
    const none = toPrincipal({ sub: "s", "custom:tenant_id": "t1", "cognito:groups": "admin" });
    expect(none.permissions.size).toBe(0);
  });

  it("gives secops-analyst no tenant-document access", () => {
    const p = toPrincipal({ sub: "s", "custom:tenant_id": "soc", "cognito:groups": ["secops-analyst"] });
    for (const perm of ["doc:read", "doc:write", "doc:delete", "audit:read"] as const) expect(p.permissions.has(perm)).toBe(false);
  });
});
