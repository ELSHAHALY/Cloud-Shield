import { uuidv7, UUIDV7_RE } from "../src/lib/uuidv7";
import { RateLimiter } from "../src/lib/rate-limit";
import { attachmentDisposition, clean } from "../src/lib/sanitize";
import { decodeCursor, encodeCursor, parseLimit } from "../src/lib/cursor";
import { AppError, problem, statusOf } from "../src/lib/errors";
import { matchesType, mediaType } from "../src/documents/magic";

describe("uuidv7", () => {
  it("is RFC 9562 shaped and time-ordered", () => {
    const a = uuidv7(1_700_000_000_000);
    const b = uuidv7(1_700_000_000_001);
    expect(a).toMatch(UUIDV7_RE);
    expect(a < b).toBe(true);
    expect(a.slice(0, 13).replace("-", "")).toBe((1_700_000_000_000).toString(16).padStart(12, "0"));
    expect(new Set(Array.from({ length: 1000 }, () => uuidv7())).size).toBe(1000);
  });
});

describe("RateLimiter", () => {
  it("counts per window, reports retry seconds and stays bounded", () => {
    let now = 0;
    const l = new RateLimiter(2, 10_000, 3, () => now);
    expect([l.take("a"), l.take("a"), l.take("a")]).toEqual([0, 0, 10]);
    expect(l.blocked("a")).toBe(10);
    expect(l.blocked("zzz")).toBe(0);
    now = 10_000;
    expect(l.take("a")).toBe(0);
    l.take("b");
    l.take("c");
    expect(l.size).toBe(3);
    l.take("d"); // full, nothing expired: one shared overflow bucket
    l.take("f");
    expect(l.size).toBe(4);
    now = 30_000;
    l.take("e"); // sweep frees expired keys
    expect(l.size).toBeLessThanOrEqual(3);
  });
});

describe("sanitize", () => {
  it("strips control characters and caps length", () => {
    expect(clean("a\u0000b\r\nc d", 10)).toBe("abcd");
    expect(clean("x".repeat(300))).toHaveLength(256);
    expect(clean("")).toBeNull();
    expect(clean(5)).toBeNull();
  });
  it("builds a header-safe Content-Disposition", () => {
    expect(attachmentDisposition("report.pdf")).toBe("attachment; filename=\"report.pdf\"; filename*=UTF-8''report.pdf");
    const evil = attachmentDisposition('..\\"; x\r\ny.txt');
    expect(evil).not.toMatch(/[\r\n]/);
    expect(attachmentDisposition("")).toContain('filename="download"');
    expect(attachmentDisposition("ملف.txt")).toContain("filename*=UTF-8''%D9%85");
    expect(attachmentDisposition("(a)'*.txt")).toContain("%28a%29%27%2A.txt");
  });
});

describe("cursor and limit", () => {
  it("round-trips only matching fields", () => {
    const c = encodeCursor({ k: "doc#x" });
    expect(decodeCursor(c, { k: /^doc#x$/ })).toEqual({ k: "doc#x" });
    expect(decodeCursor(undefined, { k: /x/ })).toBeUndefined();
    for (const bad of [encodeCursor({ k: "other" }), encodeCursor({ k: "doc#x", tenantId: "t" }), "!!", Buffer.from("[1]").toString("base64url"), Buffer.from("null").toString("base64url"), Buffer.from("{").toString("base64url"), 5]) {
      expect(() => decodeCursor(bad, { k: /^doc#x$/ })).toThrow(AppError);
    }
  });
  it("parses limits strictly", () => {
    expect(parseLimit(undefined)).toBe(25);
    expect(parseLimit("7")).toBe(7);
    expect(parseLimit(9)).toBe(9);
    for (const bad of ["0", "101", "1e2", "-1", 1.5, "abc"]) expect(() => parseLimit(bad)).toThrow(AppError);
  });
});

describe("problems and magic bytes", () => {
  it("builds RFC 9457 bodies without inputs", () => {
    expect(statusOf("RATE_LIMITED")).toBe(429);
    const p = problem("VALIDATION_FAILED", "rid", "d".repeat(300), [{ path: "/body/x", message: "m" }]);
    expect(p.detail).toHaveLength(256);
    expect(p.errors).toEqual([{ path: "/body/x", message: "m" }]);
    expect(problem("NOT_FOUND", "rid", undefined, [])).not.toHaveProperty("errors");
  });
  it("sniffs types and media types", () => {
    expect(matchesType("text/plain", Buffer.from([0xc3, 0x28]))).toBe(false);
    expect(matchesType("image/png", Buffer.from([0x89]))).toBe(false);
    expect(mediaType("Text/Plain; charset=utf-8")).toBe("text/plain");
    expect(mediaType(undefined)).toBe("");
  });
});
