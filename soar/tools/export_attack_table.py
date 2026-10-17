"""Export the ATT&CK triage table (core/attack.py) as declarative JSON for docs-api.

    python -m tools.export_attack_table --out ../app/docs-api/src/soc/attack-table.generated.json
    python -m tools.export_attack_table --check ../app/docs-api/src/soc/attack-table.generated.json

core/attack.py matches finding types with lambdas, which TypeScript cannot
import (Phase E F18, D17). This tool keeps a DECLARATIVE mirror of those rules
(`prefix` / `contains` matchers, first match wins, plus
`extraTechniquesWhenContains`) and fills each rule's triage entry from
core.attack.triage() itself, so the texts can never drift. The mirror is
proven equal to triage() over a corpus (tests/test_export_attack_table.py,
tests/fixtures/triage_corpus.json); CI runs --check so the committed JSON
cannot drift from the Python table.

Exit codes: 0 written / in sync; 1 drift (--check) or the mirror disagrees
with triage() on its own samples.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from core.attack import triage

SCHEMA_VERSION = "1"

# The declarative mirror of core.attack._RULES, in the same order. `sample` is
# a finding type that this rule (and no earlier one) matches: its triage()
# result becomes the rule's entry. `extraTechniquesWhenContains` reproduces
# the runtime rule's conditional technique.
MIRROR: tuple[dict[str, Any], ...] = (
    {
        "match": {"prefix": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"},
        "sample": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
    },
    {"match": {"prefix": "Recon:"}, "sample": "Recon:EC2/Portscan"},
    {
        "match": {"prefix": "UnauthorizedAccess:IAMUser/"},
        "sample": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
    },
    {"match": {"prefix": "Policy:S3/"}, "sample": "Policy:S3/BucketBlockPublicAccessDisabled"},
    {
        "match": {"contains": ":Runtime/"},
        "sample": "Execution:Runtime/NewBinaryExecuted",
        "extraTechniquesWhenContains": [
            {
                "contains": "CryptoCurrency",
                "sample": "CryptoCurrency:Runtime/BitcoinTool.B",
            }
        ],
    },
    {
        "match": {"prefix": "CloudShield:IPAddress/"},
        "sample": "CloudShield:IPAddress/WafRateLimitExceeded",
    },
)

_DEFAULT_SAMPLE = None  # triage(None) is the default entry


def _matches(match: dict[str, str], finding_type: str) -> bool:
    if "prefix" in match:
        return finding_type.startswith(match["prefix"])
    return match["contains"] in finding_type


def build_table() -> dict[str, Any]:
    """The JSON document docs-api evaluates (deterministic)."""
    rules: list[dict[str, Any]] = []
    for rule in MIRROR:
        entry = triage(rule["sample"]).to_dict()
        out: dict[str, Any] = {"match": dict(rule["match"]), "triage": entry}
        extras = []
        for extra in rule.get("extraTechniquesWhenContains", []):
            base = entry["attack_techniques"]
            with_extra = triage(extra["sample"]).to_dict()["attack_techniques"]
            added = [t for t in with_extra if t not in base]
            extras.append({"contains": extra["contains"], "techniques": added})
        if extras:
            out["extraTechniquesWhenContains"] = extras
        rules.append(out)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "generatedBy": "soar/tools/export_attack_table.py (from core/attack.py)",
        "semantics": "first matching rule wins; prefix = startsWith, contains = substring; "
        "a non-string or unmatched type gets `default`",
        "rules": rules,
        "default": triage(_DEFAULT_SAMPLE).to_dict(),
    }


def evaluate(table: dict[str, Any], finding_type: Any) -> dict[str, Any]:
    """The mirror's answer for a finding type: what docs-api computes."""
    if isinstance(finding_type, str):
        for rule in table["rules"]:
            if _matches(rule["match"], finding_type):
                entry = json.loads(json.dumps(rule["triage"]))
                for extra in rule.get("extraTechniquesWhenContains", []):
                    if extra["contains"] in finding_type:
                        entry["attack_techniques"] += extra["techniques"]
                return dict(entry)
    return dict(table["default"])


def render(table: dict[str, Any]) -> str:
    return json.dumps(table, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def self_check(table: dict[str, Any]) -> list[str]:
    """Every sample (and every extra's sample) must evaluate to triage()."""
    samples: list[Any] = [_DEFAULT_SAMPLE]
    for rule in MIRROR:
        samples.append(rule["sample"])
        samples += [e["sample"] for e in rule.get("extraTechniquesWhenContains", [])]
    return [repr(s) for s in samples if evaluate(table, s) != triage(s).to_dict()]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export the ATT&CK triage table as JSON")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--out", help="write the table here")
    group.add_argument("--check", help="exit 1 unless this file equals a fresh export")
    args = parser.parse_args(argv)

    table = build_table()
    disagreements = self_check(table)
    if disagreements:
        print(f"error: the mirror disagrees with triage() for {disagreements}", file=sys.stderr)
        return 1
    text = render(table)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
        return 0
    try:
        current = Path(args.check).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot read {args.check}: {exc.strerror}", file=sys.stderr)
        return 1
    if current.replace("\r\n", "\n") != text:
        print(
            f"drift: {args.check} differs from core/attack.py; "
            "run python -m tools.export_attack_table --out <file>",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
