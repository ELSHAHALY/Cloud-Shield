// Fails if a production (cognito) build contains the dev-only local auth path
// or anything the edge CSP (default-src 'self') would block (plan D20/D22).
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

const dist = path.resolve(process.argv[2] ?? "dist");
const files = [];
(function walk(d) {
  for (const f of readdirSync(d)) {
    const p = path.join(d, f);
    if (statSync(p).isDirectory()) walk(p);
    else files.push(p);
  }
})(dist);

const problems = [];
for (const f of files) {
  const text = readFileSync(f, "utf8");
  const rel = path.relative(dist, f);
  if (text.includes("local-idp")) problems.push(`${rel}: contains "local-idp" (local auth branch not eliminated)`);
  if (text.includes("cloudshield.local.idToken")) problems.push(`${rel}: contains the local token key`);
  if (f.endsWith(".html")) {
    if (/<script(?![^>]*\bsrc=)[^>]*>/i.test(text)) problems.push(`${rel}: inline <script>`);
    if (/<style[\s>]/i.test(text) || /\sstyle="/i.test(text)) problems.push(`${rel}: inline style`);
  }
}
if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
console.log(`bundle ok: ${files.length} files, no local-idp, no inline script/style`);
