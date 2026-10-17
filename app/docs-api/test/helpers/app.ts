import { createHash } from "node:crypto";
import { Writable } from "node:stream";
import request from "supertest";
import type { Express } from "express";
import pino from "pino";
import { buildApp } from "../../src/app";
import type { Config } from "../../src/config";
import { createDeps, type DepsOverrides } from "../../src/deps";
import type { AppDeps } from "../../src/app";
import { createLogger } from "../../src/lib/logger";
import { makeKeys, mint, USERS, verifierFor, type Keys, type TokenOptions, type UserName } from "./tokens";

export interface TestApp {
  app: Express;
  deps: AppDeps;
  keys: Keys;
  logs: string[];
  token(user: UserName, extra?: TokenOptions): Promise<string>;
  as(user: UserName): Promise<{ auth: [string, string] }>;
}

export async function makeApp(config: Config, overrides: DepsOverrides = {}): Promise<TestApp> {
  const keys = await makeKeys();
  const logs: string[] = [];
  const sink = new Writable({
    write(chunk, _enc, cb) {
      logs.push(String(chunk));
      cb();
    },
  });
  const logger = createLogger("info", sink as unknown as pino.DestinationStream);
  const deps = createDeps(config, logger, { verifier: verifierFor(keys), validateResponses: true, ...overrides });
  const app = buildApp(deps);
  const token = (user: UserName, extra: TokenOptions = {}) => mint(keys, { ...USERS[user], ...extra });
  return {
    app,
    deps,
    keys,
    logs,
    token,
    as: async (user) => ({ auth: ["Authorization", `Bearer ${await token(user)}`] }),
  };
}

export function api(t: TestApp) {
  return request(t.app);
}

export const sha256Hex = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");
