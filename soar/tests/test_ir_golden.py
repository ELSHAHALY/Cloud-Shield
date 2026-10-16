"""Chain-of-custody golden cases (Phase E D17).

tests/fixtures/coc_golden.json is shared with docs-api: Jest asserts that the
live verification view computes the SAME evidence[], chain_of_custody_ok and
mttc_seconds as tools/generate_ir_report.build_report does here. The Python
tool stays authoritative; this test pins it to the fixture.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import boto3
import pytest
from moto import mock_aws

from core.incidents import IncidentRepository
from tools.generate_ir_report import build_report

GOLDEN = json.loads(
    (Path(__file__).parent / "fixtures" / "coc_golden.json").read_text(encoding="utf-8")
)
BUCKET = GOLDEN["evidenceBucket"]
TABLE = "cs-golden-soar-incidents"


@pytest.fixture
def aws() -> Iterator[tuple[Any, Any]]:
    with mock_aws():
        s3, ddb = boto3.client("s3"), boto3.client("dynamodb")
        s3.create_bucket(Bucket=BUCKET)
        s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})
        ddb.create_table(
            TableName=TABLE,
            KeySchema=[{"AttributeName": "incidentId", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "incidentId", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield s3, ddb


def _attr(value: Any) -> dict[str, Any]:
    if value is None:
        return {"NULL": True}
    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, int | float):
        return {"N": str(value)}
    if isinstance(value, list):
        return {"L": [_attr(v) for v in value]}
    if isinstance(value, dict):
        return {"M": {k: _attr(v) for k, v in value.items()}}
    return {"S": str(value)}


def load_case(case: dict[str, Any], s3: Any, ddb: Any) -> dict[str, list[str]]:
    """Upload the case's objects and its row. Returns key -> version ids."""
    versions: dict[str, list[str]] = {}
    for obj in case["objects"]:
        for body in obj["versions"]:
            put = s3.put_object(Bucket=BUCKET, Key=obj["key"], Body=body.encode("utf-8"))
            versions.setdefault(obj["key"], []).append(put["VersionId"])
    records = []
    for record in case["records"]:
        version = record["version"]
        records.append(
            {
                "bucket": BUCKET,
                "key": record["key"],
                "versionId": None if version is None else versions[record["key"]][version],
                "sha256": record["sha256"],
                "sha256Base64": record["sha256Base64"],
            }
        )
    item = {k: _attr(v) for k, v in case["row"].items()}
    if records:
        item["evidenceRecords"] = _attr(records)
    ddb.put_item(TableName=TABLE, Item=item)
    return versions


def expected_for(case: dict[str, Any], versions: dict[str, list[str]]) -> dict[str, Any]:
    expected = json.loads(json.dumps(case["expected"]))
    for entry in expected["evidence"]:
        marker = entry["version_id"]
        if isinstance(marker, str) and marker.startswith("$version:"):
            entry["version_id"] = versions[entry["key"]][int(marker.split(":")[1])]
    return expected


@pytest.mark.parametrize("case", GOLDEN["cases"], ids=lambda c: c["name"])
def test_build_report_matches_golden(case: dict[str, Any], aws: tuple[Any, Any]) -> None:
    s3, ddb = aws
    versions = load_case(case, s3, ddb)
    report = build_report(case["row"]["incidentId"], IncidentRepository(TABLE, ddb), s3).to_dict()
    expected = expected_for(case, versions)
    assert report["evidence"] == expected["evidence"]
    assert report["chain_of_custody_ok"] == expected["chain_of_custody_ok"]
    assert report["mttc_seconds"] == expected["mttc_seconds"]


def test_golden_covers_the_required_cases() -> None:
    names = {c["name"] for c in GOLDEN["cases"]}
    assert {
        "intact",
        "tampered",
        "missing-object",
        "base64-mismatch",
        "versioned",
        "not-contained",
    } <= names


@pytest.mark.parametrize("case", GOLDEN["cases"], ids=lambda c: c["name"])
def test_golden_hashes_are_self_consistent(case: dict[str, Any]) -> None:
    # Recorded hex digests are SHA-256 of a real body or deliberately foreign;
    # the base64 field is the encoding of the hex unless the case is about it.
    bodies = {
        hashlib.sha256(body.encode("utf-8")).hexdigest()
        for obj in case["objects"]
        for body in obj["versions"]
    }
    for record in case["records"]:
        b64 = base64.b64encode(bytes.fromhex(record["sha256"])).decode()
        assert (record["sha256Base64"] == b64) is (case["name"] != "base64-mismatch")
        if case["name"] in {"intact", "versioned", "not-contained", "base64-mismatch"}:
            assert record["sha256"] in bodies
        if case["name"] in {"tampered", "missing-object"}:
            assert record["sha256"] not in bodies
