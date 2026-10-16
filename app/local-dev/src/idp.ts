// DEV-ONLY identity provider for docker-compose.local.yml (plan D22, §10).
// Mints RS256 ID tokens shaped like Cognito's, with iss = http://local-idp:9000
// (http and not a Cognito URL, so the production verifier and config can never
// accept them). The key pair is generated at boot and lives in memory only.
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { exportJWK, generateKeyPair, SignJWT, type JWK, type KeyLike } from "jose";
import { requireLocalMode } from "./guard";

export interface DemoUser {
  username: string;
  sub: string;
  email: string;
  tenantId: string;
  groups: string[];
  description: string;
}

export function loadUsers(file = path.resolve(__dirname, "..", "fixtures", "users.json")): DemoUser[] {
  return (JSON.parse(readFileSync(file, "utf8")) as { users: DemoUser[] }).users;
}

export interface IdpOptions {
  issuer: string;
  audience: string;
  users: DemoUser[];
  ttlSeconds?: number;
}

export async function createIdp(o: IdpOptions) {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const kid = randomUUID();
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid, alg: "RS256", use: "sig" };
  const ttl = o.ttlSeconds ?? 3600;

  async function mint(u: DemoUser, key: KeyLike = privateKey): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ token_use: "id", email: u.email, "custom:tenant_id": u.tenantId, "cognito:groups": u.groups, auth_time: now })
      .setProtectedHeader({ alg: "RS256", kid, typ: "JWT" })
      .setIssuer(o.issuer)
      .setAudience(o.audience)
      .setSubject(u.sub)
      .setIssuedAt(now)
      .setExpirationTime(now + ttl)
      .setJti(randomUUID())
      .sign(key);
  }

  function send(res: ServerResponse, status: number, body: unknown) {
    res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
    res.end(JSON.stringify(body));
  }

  async function readBody(req: IncomingMessage): Promise<unknown> {
    let size = 0;
    const chunks: Buffer[] = [];
    for await (const c of req) {
      size += (c as Buffer).length;
      if (size > 1024) throw new Error("too large");
      chunks.push(c as Buffer);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  }

  const server = http.createServer((req, res) => {
    void (async () => {
      const url = (req.url ?? "/").split("?")[0];
      if (req.method === "GET" && url === "/healthz") return send(res, 200, { status: "ok" });
      if (req.method === "GET" && url === "/.well-known/jwks.json") return send(res, 200, { keys: [jwk] });
      if (req.method === "GET" && url === "/users") {
        return send(res, 200, o.users.map(({ username, tenantId, groups, description }) => ({ username, tenantId, groups, description })));
      }
      if (req.method === "POST" && url === "/token") {
        let body: unknown;
        try {
          body = await readBody(req);
        } catch {
          return send(res, 400, { error: "invalid body" });
        }
        const username = (body as { username?: unknown } | null)?.username;
        const user = o.users.find((u) => u.username === username);
        if (!user) return send(res, 404, { error: "unknown user" });
        return send(res, 200, { idToken: await mint(user), expiresIn: ttl });
      }
      return send(res, 404, { error: "not found" });
    })();
  });
  return { server, jwk, mint };
}

export async function main(env: NodeJS.ProcessEnv = process.env) {
  requireLocalMode(env);
  const idp = await createIdp({ issuer: env.LOCAL_IDP_ISSUER ?? "http://local-idp:9000", audience: env.COGNITO_CLIENT_ID ?? "cloudshield-local-spa", users: loadUsers() });
  const port = Number(env.PORT ?? 9000);
  idp.server.listen(port, () => console.log(JSON.stringify({ msg: "local-idp listening (DEV ONLY)", port })));
  process.on("SIGTERM", () => idp.server.close(() => process.exit(0)));
  return idp;
}

/* istanbul ignore next */
if (require.main === module) {
  main().catch((err: unknown) => {
    console.error(String(err instanceof Error ? err.message : err));
    process.exit(1);
  });
}
