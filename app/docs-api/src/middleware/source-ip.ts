// Viewer IP for audit (plan §4.1 step 4, F15). Only CloudFront-Viewer-Address
// ("<ip>:<port>", CloudFront-set; local nginx overwrites it the same way) is
// read. X-Forwarded-For is client-controlled and never read.
import { isIP } from "node:net";
import type { NextFunction, Request, Response } from "express";

export function parseViewerAddress(header: unknown): string | null {
  if (typeof header !== "string" || header.length === 0 || header.length > 64) return null;
  const cut = header.lastIndexOf(":");
  if (cut <= 0) return null;
  const port = header.slice(cut + 1);
  if (!/^\d{1,5}$/.test(port) || Number(port) > 65535) return null;
  let ip = header.slice(0, cut);
  if (ip.startsWith("[") && ip.endsWith("]")) ip = ip.slice(1, -1);
  const family = isIP(ip);
  if (family === 0) return null;
  // eslint-disable-next-line security/detect-unsafe-regex -- bounded and unambiguous: linear time
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped && isIP(mapped[1]!) === 4) return mapped[1]!;
  return family === 6 ? ip.toLowerCase() : ip;
}

export function sourceIp(req: Request, _res: Response, next: NextFunction): void {
  const ip = parseViewerAddress(req.get("cloudfront-viewer-address"));
  req.source = ip ? { ip, trusted: true } : { ip: null, trusted: false };
  next();
}
