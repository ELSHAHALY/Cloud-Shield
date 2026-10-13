"""Hunt queries (detection/athena-queries/*.sql) are safe and catalogued (FR-8)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

QUERIES_DIR = Path(__file__).resolve().parents[2] / "detection" / "athena-queries"
CATALOGUED_TABLES = {"cloudtrail", "vpc_flow_logs", "guardduty_findings"}
FORBIDDEN = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|MSCK|TRUNCATE|GRANT|REVOKE|UNLOAD)\b", re.IGNORECASE
)

SQL_FILES = sorted(QUERIES_DIR.glob("*.sql"))


def test_there_are_queries() -> None:
    assert len(SQL_FILES) >= 3


@pytest.mark.parametrize("path", SQL_FILES, ids=lambda p: p.name)
def test_query_is_a_single_read_only_statement(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    body = "\n".join(line for line in text.splitlines() if not line.strip().startswith("--"))
    assert body.strip(), f"{path.name} has no statement"
    assert not FORBIDDEN.search(body), f"{path.name} contains a non-SELECT keyword"
    # One statement: no semicolon except an optional trailing one.
    assert body.rstrip().rstrip(";").count(";") == 0, f"{path.name} has more than one statement"
    assert re.match(r"^\s*(WITH|SELECT)\b", body, re.IGNORECASE), f"{path.name} is not a SELECT"


@pytest.mark.parametrize("path", SQL_FILES, ids=lambda p: p.name)
def test_placeholder_count_matches_header(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    header = re.search(r"--\s*Parameters:\s*(\d+)", text)
    assert header, f"{path.name} header must declare a parameter count"
    declared = int(header.group(1))
    body = "\n".join(line for line in text.splitlines() if not line.strip().startswith("--"))
    assert body.count("?") == declared, (
        f"{path.name}: {body.count('?')} placeholders, header says {declared}"
    )


@pytest.mark.parametrize("path", SQL_FILES, ids=lambda p: p.name)
def test_header_names_attack_and_scenario(path: Path) -> None:
    head = path.read_text(encoding="utf-8")[:600]
    assert "ATT&CK:" in head, f"{path.name} header must map to MITRE ATT&CK"
    assert re.search(r"Scenario:", head), f"{path.name} header must name the scenario"


@pytest.mark.parametrize("path", SQL_FILES, ids=lambda p: p.name)
def test_only_catalogued_tables(path: Path) -> None:
    body = "\n".join(
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if not line.strip().startswith("--")
    )
    # "IS [NOT] DISTINCT FROM" is an operator, not a table source: drop it first.
    body_no_op = re.sub(r"(?i)\bdistinct\s+from\b", " ", body)
    referenced = set(re.findall(r"\b(?:FROM|JOIN)\s+([a-z_][a-z0-9_]*)", body_no_op, re.IGNORECASE))
    # CTE names are allowed; subtract names defined by WITH ... AS.
    ctes = set(re.findall(r"(?:WITH|,)\s+([a-z_][a-z0-9_]*)\s+AS\s*\(", body, re.IGNORECASE))
    unknown = referenced - CATALOGUED_TABLES - ctes
    assert not unknown, f"{path.name} references unknown tables: {unknown}"


def test_each_query_filters_on_partition_columns() -> None:
    """Cost guard: every query must constrain at least one partition key."""
    partitions = ("timestamp", "year", "month", "day", "hour", "dt")
    for path in SQL_FILES:
        body = path.read_text(encoding="utf-8").lower()
        assert any(
            f'"{p}"' in body
            or f"\n    {p} " in body
            or f" {p} =" in body
            or f" {p} between" in body
            for p in partitions
        ), f"{path.name} does not filter on a partition column"
