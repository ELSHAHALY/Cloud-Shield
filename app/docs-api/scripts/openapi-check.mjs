// Generates TypeScript types from app/openapi.yaml into both packages
// (--write), or fails if the committed files drifted (--check). Plan D12.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import openapiTS, { astToString } from "openapi-typescript";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..", "..");
const spec = path.join(appRoot, "openapi.yaml");
const targets = [path.join(appRoot, "docs-api", "src", "types", "openapi.d.ts"), path.join(appRoot, "spa", "src", "api", "openapi.d.ts")];
const header = "// GENERATED from app/openapi.yaml by docs-api/scripts/openapi-check.mjs. Do not edit; run `npm run openapi:types`.\n";

const mode = process.argv[2];
if (mode !== "--write" && mode !== "--check") {
  console.error("usage: openapi-check.mjs --write|--check");
  process.exit(2);
}

const ast = await openapiTS(pathToFileURL(spec), { alphabetize: true, immutable: false });
const text = header + astToString(ast);

let drift = false;
for (const target of targets) {
  if (!existsSync(path.dirname(target))) continue;
  if (mode === "--write") {
    writeFileSync(target, text);
    console.log(`wrote ${path.relative(appRoot, target)}`);
  } else if (!existsSync(target) || readFileSync(target, "utf8") !== text) {
    console.error(`drift: ${path.relative(appRoot, target)} differs from openapi.yaml (run npm run openapi:types)`);
    drift = true;
  }
}
if (drift) process.exit(1);
if (mode === "--check") console.log("openapi types in sync");
