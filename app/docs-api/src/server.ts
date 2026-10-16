// Entry point. SIGTERM: stop accepting, then force-exit at 1.5 s, inside the
// task definition's stopTimeout = 2 (F11).
import type { Server } from "node:http";
import { buildApp } from "./app";
import { ConfigError, loadConfig } from "./config";
import { createDeps } from "./deps";
import { createLogger } from "./lib/logger";

export function installShutdown(server: Server, exit: (code: number) => void = (c) => process.exit(c), graceMs = 1500): () => void {
  return () => {
    server.close(() => exit(0));
    server.closeIdleConnections?.();
    setTimeout(() => exit(0), graceMs).unref();
  };
}

export function main(): Server {
  const bootLogger = createLogger(process.env.LOG_LEVEL ?? "info");
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) bootLogger.fatal({ problems: err.problems }, "refusing to start: invalid configuration");
    else bootLogger.fatal({ err }, "refusing to start");
    process.exit(1);
  }
  const logger = createLogger(config.logLevel);
  const app = buildApp(createDeps(config, logger));
  const server = app.listen(config.port, () => logger.info({ port: config.port, mode: config.mode }, "docs-api listening"));
  server.keepAliveTimeout = 65_000;
  server.headersTimeout = 66_000;
  server.requestTimeout = 30_000;
  process.on("SIGTERM", installShutdown(server));
  return server;
}

/* istanbul ignore next */
if (require.main === module) main();
