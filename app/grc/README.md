# app/grc — Regional GRC & Cloud Compliance Advisor (data)

> **Not legal advice.** This is an informational mapping prepared for an academic
> capstone. Every item whose citation is marked `verify` has **not** been checked
> against the official text; the UI shows a "Verify against the official text"
> badge on it. Confirm every obligation with qualified counsel and the regulator's
> own publications before relying on it. Last reviewed: **2026-10-16**.

Rules are **data**, evaluated by `app/docs-api/src/grc/engine.ts` (plan D23):

| File | What |
|---|---|
| `schema/*.schema.json` | JSON Schema 2020-12 for every file below; docs-api validates at startup and answers 503 on the GRC routes if anything fails (fail closed). |
| `rules/<YYYY.M.N>.json` | The versioned ruleset. A revision is a **new file**; the highest version is loaded. Every assessment returns the version and the SHA-256 of the file. |
| `matrix/shared-responsibility.json` | AWS (built) vs Azure / GCP (mapped equivalents, not built). |
| `platform-facts.json` | Static platform facts, reviewed against the Terraform defaults (see `reviewedAgainst`). Region, incident automation and dry-run are added at runtime. |
| `agreements/index.json` + `*.txt` | DPA and SLA **templates** (not reviewed by counsel). docs-api hashes each text (UTF-8, LF) at startup; acceptance must quote that hash. |

## Condition DSL

`appliesWhen`, `metWhen` and `partialWhen` use `all` / `any` / `not` and leaves
`{fact, op, value}`. Operators: `eq`, `neq`, `in`, `includes`, `includesAny`,
`gte`, `lte`, `exists`. Facts are an allow-listed enumeration (`tenant.*`,
`platform.*`, `derived.crossBorder`, `derived.residencyCountries`); depth ≤ 8.
There is no eval, no regex from data and no dynamic property path.

Finding status: `MET`, `PARTIAL`, `GAP`, `CUSTOMER_ACTION`, `NOT_APPLICABLE`,
`INFO`. Residency and transfer rules report **GAP** for EG, SA and EU tenants
by construction: everything is deployed in `us-east-1` (multi-region is out of
scope). That is the honest output, not a bug.

## Sources and marks

| Framework | Status |
|---|---|
| EU GDPR, Regulation (EU) 2016/679 | Article numbers `doc` (EUR-Lex). Whether AWS participates in the EU–US DPF: `verify`. |
| Egypt PDPL, Law No. 151 of 2020 | Law identity `doc`; **all article-level content `verify`**; Executive Regulations status `verify`. |
| Central Bank of Egypt rules | **All `verify`**: instrument names and dates still to be identified from CBE publications. No article numbers until then. |
| Saudi PDPL, Royal Decree M/19 (1443H) | Decree `doc`; amendments (M/148, 1444H), dates, transfer and breach rules `verify`. |
| NCA ECC-2:2024, CCC; NDMO / Cloud First | **All `verify`**. |

`app/docs-api/test/grc-content.test.ts` fails if a non-GDPR citation is marked
`doc` without being on its reviewed allow-list.

## Agreements

Acceptance is click-through logging bound to an MFA-authenticated Cognito
identity (plan D25): who, when, the text hash, source IP and request id. It is
**not** a qualified or advanced electronic signature (eIDAS QES; Egypt
E-Signature Law No. 15 of 2004 [verify]).

## Adding or changing a rule

1. Copy the latest `rules/<version>.json` to the next version (never edit a
   released file: assessments cite the version and hash).
2. Add the rule with at least one citation; mark it `verify` unless you checked
   the official text yourself, and record the check in the review log below.
3. `cd app/docs-api && npm test -- grc` (schema, content and engine tests).

## Review log

| Date | Version | Reviewer | Change |
|---|---|---|---|
| 2026-10-16 | 2026.10.0 | S2 (capstone) | First ruleset: EG-PDPL, EG-CBE, EU-GDPR, SA-PDPL, SA-NCA. GDPR articles checked against EUR-Lex; everything else marked verify. |
