"""ATT&CK table export (tools/export_attack_table.py, Phase E D17).

The declarative mirror docs-api evaluates must equal core.attack.triage() for
every finding type in the shared corpus; --check must detect drift; the
output must be deterministic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from core.attack import triage
from tools import export_attack_table as exporter

FIXTURES = Path(__file__).parent / "fixtures"
CORPUS = json.loads((FIXTURES / "triage_corpus.json").read_text(encoding="utf-8"))
COMMITTED = (
    Path(__file__).resolve().parents[2]
    / "app"
    / "docs-api"
    / "src"
    / "soc"
    / "attack-table.generated.json"
)


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: repr(c["findingType"])[:60])
def test_corpus_expected_values_are_current(case: dict[str, Any]) -> None:
    # The corpus is shared with Jest: it must state what triage() says today.
    assert triage(case["findingType"]).to_dict() == case["expected"]


@pytest.mark.parametrize("case", CORPUS["cases"], ids=lambda c: repr(c["findingType"])[:60])
def test_mirror_equals_triage_for_the_corpus(case: dict[str, Any]) -> None:
    table = exporter.build_table()
    assert exporter.evaluate(table, case["findingType"]) == triage(case["findingType"]).to_dict()


def test_corpus_covers_every_rule_extra_and_default() -> None:
    table = exporter.build_table()
    scenarios = {c["expected"]["scenario"] for c in CORPUS["cases"]}
    assert scenarios == {r["triage"]["scenario"] for r in table["rules"]} | {"default"}
    types = [c["findingType"] for c in CORPUS["cases"]]
    assert None in types
    assert any(isinstance(t, str) and "CryptoCurrency" in t and ":Runtime/" in t for t in types)
    assert "CloudShield:IPAddress/DecoyRouteHit" in types


@pytest.mark.parametrize("value", [None, 7, ["Recon:EC2/Portscan"], {"type": "x"}])
def test_non_string_types_get_the_default(value: Any) -> None:
    table = exporter.build_table()
    assert exporter.evaluate(table, value) == triage(None).to_dict()


def test_output_is_deterministic_and_sorted() -> None:
    first = exporter.render(exporter.build_table())
    second = exporter.render(exporter.build_table())
    assert first == second
    assert first.endswith("}\n")
    assert json.loads(first) == json.loads(json.dumps(json.loads(first), sort_keys=True))
    assert exporter.self_check(exporter.build_table()) == []


def test_committed_table_is_in_sync() -> None:
    assert exporter.main(["--check", str(COMMITTED)]) == 0


def test_out_then_check_round_trips(tmp_path: Path) -> None:
    target = tmp_path / "table.json"
    assert exporter.main(["--out", str(target)]) == 0
    assert exporter.main(["--check", str(target)]) == 0
    assert target.read_bytes().count(b"\r\n") == 0


def test_check_detects_drift(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "table.json"
    assert exporter.main(["--out", str(target)]) == 0
    doc = json.loads(target.read_text(encoding="utf-8"))
    doc["rules"][0]["triage"]["tactic"] = "Tampered"
    target.write_text(json.dumps(doc), encoding="utf-8")
    assert exporter.main(["--check", str(target)]) == 1
    assert "drift" in capsys.readouterr().err


def test_check_tolerates_crlf_checkouts(tmp_path: Path) -> None:
    target = tmp_path / "table.json"
    text = exporter.render(exporter.build_table()).replace("\n", "\r\n")
    target.write_bytes(text.encode("utf-8"))
    assert exporter.main(["--check", str(target)]) == 0


def test_check_missing_file_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert exporter.main(["--check", str(tmp_path / "absent.json")]) == 1
    assert "cannot read" in capsys.readouterr().err


def test_a_wrong_mirror_refuses_to_export(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Swap two rules: the B prefix now shadows scenario A's exfiltration type.
    mirror = list(exporter.MIRROR)
    mirror[0], mirror[2] = mirror[2], mirror[0]
    monkeypatch.setattr(exporter, "MIRROR", tuple(mirror))
    assert exporter.main(["--out", str(tmp_path / "t.json")]) == 1
    assert "disagrees" in capsys.readouterr().err
    assert not (tmp_path / "t.json").exists()


def test_arguments_are_required() -> None:
    with pytest.raises(SystemExit):
        exporter.main([])
