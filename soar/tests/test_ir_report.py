"""IR report generator (tools/generate_ir_report.py)."""

from __future__ import annotations

import json
from typing import Any

import boto3
import pytest

from core.incidents import IncidentRepository
from tests.conftest import EVIDENCE_BUCKET, INCIDENTS_TABLE
from tools import generate_ir_report as ir
from tools.generate_ir_report import build_report, main


def repo() -> IncidentRepository:
    return IncidentRepository(INCIDENTS_TABLE, boto3.client("dynamodb"))


def put_evidence(key: str, body: bytes) -> dict[str, Any]:
    import base64
    import hashlib

    boto3.client("s3").put_object(Bucket=EVIDENCE_BUCKET, Key=key, Body=body)
    digest = hashlib.sha256(body).digest()
    return {
        "bucket": EVIDENCE_BUCKET,
        "key": key,
        "versionId": None,
        "sha256": digest.hex(),
        "sha256Base64": base64.b64encode(digest).decode(),
    }


def contained_row(world: Any, **extra: Any) -> str:
    incident_id = "f-report-contained"
    world.seed_incident(
        incident_id,
        status={"S": "CONTAINED"},
        findingType={"S": "Recon:EC2/Portscan"},
        severity={"N": "5"},
        resourceType={"S": "Instance"},
        findingCreatedAt={"S": "2026-10-14T09:59:58.000Z"},
        eventTime={"S": "2026-10-14T10:00:00.000Z"},
        containedAt={"S": "2026-10-14T10:00:12.500Z"},
        containmentVerified={"BOOL": True},
    )
    r = repo()
    r.append_action(
        incident_id,
        {
            "playbook": "pb01-ec2-isolate",
            "step": "nacl-deny",
            "at": "2026-10-14T10:00:05.000Z",
            "networkAclId": "acl-1",
        },
    )
    for k, v in extra.items():
        r.set_fields(incident_id, {k: v})
    return incident_id


def test_contained_report_computes_mttc(world: Any) -> None:
    incident_id = contained_row(world)
    report = build_report(incident_id, repo(), boto3.client("s3"))
    assert report.status == "CONTAINED"
    assert report.mttc_seconds == 12.5
    assert report.mttc_target_met is True
    assert report.detection_latency_seconds == 2.0
    assert report.chain_of_custody_ok is None  # no evidence recorded
    md = report.to_markdown()
    assert "12.500 s (meets" in md
    assert "nacl-deny" in md


def test_evidence_hash_match_passes(world: Any) -> None:
    incident_id = contained_row(world)
    record = put_evidence("incidents/f-report-contained/manifest.json", b'{"ok":1}')
    repo().add_evidence(incident_id, record)
    report = build_report(incident_id, repo(), boto3.client("s3"))
    assert report.chain_of_custody_ok is True
    assert report.evidence[0].ok is True
    assert main([incident_id, "--table", INCIDENTS_TABLE]) == 0


def test_tampered_evidence_fails_and_exits_2(world: Any, capsys: Any) -> None:
    incident_id = contained_row(world)
    record = put_evidence("incidents/f-report-contained/m.json", b'{"original":1}')
    repo().add_evidence(incident_id, record)
    # Tamper: overwrite the object after the hash was recorded.
    boto3.client("s3").put_object(Bucket=EVIDENCE_BUCKET, Key=record["key"], Body=b'{"tampered":1}')

    report = build_report(incident_id, repo(), boto3.client("s3"))
    assert report.chain_of_custody_ok is False
    assert report.evidence[0].ok is False
    assert "BROKEN" in report.to_markdown()
    assert main([incident_id, "--table", INCIDENTS_TABLE]) == 2


def test_missing_evidence_object_is_marked(world: Any) -> None:
    incident_id = contained_row(world)
    repo().add_evidence(
        incident_id, {"bucket": EVIDENCE_BUCKET, "key": "incidents/gone.json", "sha256": "deadbeef"}
    )
    report = build_report(incident_id, repo(), boto3.client("s3"))
    assert report.evidence[0].ok is False
    assert report.evidence[0].error == "NoSuchKey"


def test_not_contained_has_no_mttc(world: Any) -> None:
    world.seed_incident(
        "f-failed",
        status={"S": "FAILED"},
        eventTime={"S": "2026-10-14T10:00:00Z"},
        failure={"S": "PlaybookDidNotContain"},
    )
    report = build_report("f-failed", repo(), boto3.client("s3"))
    assert report.mttc_seconds is None
    assert report.mttc_target_met is None
    assert "not contained" in report.to_markdown()


def test_json_output(world: Any, tmp_path: Any) -> None:
    incident_id = contained_row(world)
    out = tmp_path / "r.json"
    assert (
        main([incident_id, "--table", INCIDENTS_TABLE, "--format", "json", "--output", str(out)])
        == 0
    )
    data = json.loads(out.read_text())
    assert data["mttc_seconds"] == 12.5
    assert data["chain_of_custody_ok"] is None


def test_unknown_incident_exits_1(world: Any) -> None:
    assert main(["does-not-exist", "--table", INCIDENTS_TABLE]) == 1


def test_table_required(monkeypatch: Any) -> None:
    monkeypatch.delenv("INCIDENTS_TABLE", raising=False)
    with pytest.raises(SystemExit):
        main(["f-1"])


def test_mttc_target_missed(world: Any) -> None:
    world.seed_incident(
        "f-slow",
        status={"S": "CONTAINED"},
        eventTime={"S": "2026-10-14T10:00:00Z"},
        containedAt={"S": "2026-10-14T10:02:00Z"},
    )
    report = build_report("f-slow", repo(), boto3.client("s3"))
    assert report.mttc_seconds == 120.0
    assert report.mttc_target_met is False
    assert "MISSES" in report.to_markdown()


def test_target_constant() -> None:
    assert ir.MTTC_TARGET_SECONDS == 60.0
