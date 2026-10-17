import pino, { type Logger } from "pino";

/** Never logs tokens, cookies, the origin secret or the viewer address. */
export function createLogger(level: string, destination?: pino.DestinationStream): Logger {
  return pino(
    {
      level,
      base: { service: "docs-api" },
      redact: {
        paths: [
          "authorization",
          "cookie",
          "*.authorization",
          "*.cookie",
          "*.headers.authorization",
          "*.headers.cookie",
          "*.headers['x-origin-verify']",
          "*.headers['cloudfront-viewer-address']",
          "token",
          "*.token",
        ],
        censor: "[redacted]",
      },
      timestamp: pino.stdTimeFunctions.isoTime,
    },
    destination,
  );
}
