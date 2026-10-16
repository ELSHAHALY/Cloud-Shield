import type { AddressInfo } from "node:net";
import { createLocalJWKSet, jwtVerify, decodeJwt } from "jose";
import { createIdp, loadUsers, main } from "../src/idp";
import { isLocalEndpoint, requireLocalMode } from "../src/guard";

describe("local IdP", () => {
  it("refuses to start unless CLOUDSHIELD_ENV=local", async () => {
    await expect(main({})).rejects.toThrow("CLOUDSHIELD_ENV must be local");
    await expect(main({ CLOUDSHIELD_ENV: "aws" })).rejects.toThrow();
    expect(() => requireLocalMode({ CLOUDSHIELD_ENV: "local" })).not.toThrow();
  });

  it("mints tokens with exactly the Cognito ID-token claim shape, verifiable with its JWKS", async () => {
    const idp = await createIdp({ issuer: "http://local-idp:9000", audience: "cloudshield-local-spa", users: loadUsers() });
    await new Promise<void>((r) => idp.server.listen(0, r));
    const base = `http://127.0.0.1:${(idp.server.address() as AddressInfo).port}`;
    try {
      const users = (await (await fetch(`${base}/users`)).json()) as { username: string }[];
      expect(users.map((u) => u.username)).toEqual(["alice", "bob", "carol", "dina", "mallory", "omar", "sam"]);
      expect(JSON.stringify(users)).not.toMatch(/password|secret/i);
      const res = await fetch(`${base}/token`, { method: "POST", body: JSON.stringify({ username: "mallory" }) });
      const { idToken } = (await res.json()) as { idToken: string };
      const jwks = (await (await fetch(`${base}/.well-known/jwks.json`)).json()) as { keys: object[] };
      expect(JSON.stringify(jwks)).not.toContain('"d"');
      const { payload, protectedHeader } = await jwtVerify(idToken, createLocalJWKSet(jwks as never), { issuer: "http://local-idp:9000", audience: "cloudshield-local-spa" });
      expect(protectedHeader.alg).toBe("RS256");
      expect(Object.keys(payload).sort()).toEqual(["aud", "auth_time", "cognito:groups", "custom:tenant_id", "email", "exp", "iat", "iss", "jti", "sub", "token_use"]);
      expect(payload).toMatchObject({ token_use: "id", "custom:tenant_id": "t-nile-02", "cognito:groups": ["member"], sub: "local-mallory" });
      expect(decodeJwt(idToken).exp! - decodeJwt(idToken).iat!).toBe(3600);
      expect((await fetch(`${base}/token`, { method: "POST", body: JSON.stringify({ username: "root" }) })).status).toBe(404);
      expect((await fetch(`${base}/token`, { method: "POST", body: "x".repeat(2000) })).status).toBe(400);
      expect((await fetch(`${base}/token`, { method: "POST", body: "{" })).status).toBe(400);
      expect((await fetch(`${base}/healthz`)).status).toBe(200);
      expect((await fetch(`${base}/nope`)).status).toBe(404);
    } finally {
      idp.server.close();
    }
  });

  it("only treats emulator hosts as local", () => {
    expect(isLocalEndpoint("http://moto:5000")).toBe(true);
    expect(isLocalEndpoint("http://[::1]:5000")).toBe(true);
    for (const bad of [undefined, "", "https://dynamodb.us-east-1.amazonaws.com", "http://moto.evil", "http://u:p@moto:5000", "file:///x", "nope"]) expect(isLocalEndpoint(bad)).toBe(false);
  });
});
