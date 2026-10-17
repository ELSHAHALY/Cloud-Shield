// JSON Schema (2020-12) validation of the GRC content files (plan D23).
import { readFileSync } from "node:fs";
import path from "node:path";
import Ajv2020, { type ValidateFunction } from "ajv/dist/2020";
import addFormats from "ajv-formats";

export type SchemaName = "ruleset" | "matrix" | "agreements" | "profile" | "platform-facts";

const cache = new Map<string, ValidateFunction>();

export function compileSchema(contentRoot: string, name: SchemaName): ValidateFunction {
  const file = path.join(contentRoot, "grc", "schema", `${name}.schema.json`);
  const hit = cache.get(file);
  if (hit) return hit;
  // strictRequired is off only because `required` inside if/then names properties defined one level up.
  const ajv = new Ajv2020({ allErrors: false, strict: true, strictRequired: false, allowUnionTypes: true });
  addFormats(ajv, ["date", "date-time"]);
  const validate = ajv.compile(JSON.parse(readFileSync(file, "utf8")) as object);
  cache.set(file, validate);
  return validate;
}
