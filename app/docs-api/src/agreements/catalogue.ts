// Agreement catalogue (plan §8.4). Texts are read once at startup as UTF-8,
// LF-normalised, and hashed; the hash the admin accepts must equal this one.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { compileSchema } from "../grc/schemas";

export interface AgreementEntry {
  agreementId: string;
  version: string;
  title: string;
  effectiveDate: string;
  required: boolean;
  current: boolean;
  sha256: string;
  text: string;
}

export interface Catalogue {
  entries: AgreementEntry[];
  find(agreementId: string, version: string): AgreementEntry | undefined;
  current(): AgreementEntry[];
  required(): AgreementEntry[];
}

interface IndexFile {
  schemaVersion: "1";
  agreements: { agreementId: string; version: string; title: string; file: string; effectiveDate: string; required: boolean; current: boolean }[];
}

const FILE_RE = /^[a-z0-9][a-z0-9-]{0,62}\.txt$/;

export function normaliseText(raw: string): string {
  return raw.replace(/^\ufeff/, "").replace(/\r\n?/g, "\n");
}

export function loadCatalogue(contentRoot: string): Catalogue {
  const dir = path.join(contentRoot, "grc", "agreements");
  const index = JSON.parse(readFileSync(path.join(dir, "index.json"), "utf8")) as unknown;
  const validate = compileSchema(contentRoot, "agreements");
  if (!validate(index)) throw new Error("agreements index failed schema validation");
  const file = index as IndexFile;
  const seen = new Set<string>();
  const entries = file.agreements.map((a) => {
    if (!FILE_RE.test(a.file)) throw new Error("agreement file name is not allowed");
    const id = `${a.agreementId}#${a.version}`;
    if (seen.has(id)) throw new Error("duplicate agreement version");
    seen.add(id);
    const text = normaliseText(readFileSync(path.join(dir, a.file), "utf8"));
    return {
      agreementId: a.agreementId,
      version: a.version,
      title: a.title,
      effectiveDate: a.effectiveDate,
      required: a.required,
      current: a.current,
      sha256: createHash("sha256").update(text, "utf8").digest("hex"),
      text,
    };
  });
  const currentIds = entries.filter((e) => e.current).map((e) => e.agreementId);
  if (new Set(currentIds).size !== currentIds.length) throw new Error("more than one current version of an agreement");
  return {
    entries,
    find: (agreementId, version) => entries.find((e) => e.agreementId === agreementId && e.version === version),
    current: () => entries.filter((e) => e.current),
    required: () => entries.filter((e) => e.current && e.required),
  };
}

export function publicAgreement(e: AgreementEntry) {
  return { agreementId: e.agreementId, version: e.version, title: e.title, sha256: e.sha256, effectiveDate: e.effectiveDate, required: e.required };
}
