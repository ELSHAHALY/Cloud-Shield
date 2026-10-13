"""Finding parsing, incident repository, evidence collector."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import boto3
import pytest

from core.evidence import EvidenceCollector, EvidenceIntegrityError
from core.finding import (
    Ec2Target,
    Finding,
    IamUserTarget,
    MalformedFindingError,
    S3BucketTarget,
    UnknownTarget,
)
from core.incidents import IncidentRepository
from core.playbook import is_revoke_policy, session_revoke_policy
from tests import events
from tests.conftest import INCIDENTS_TABLE

INSTANCE = "i-0123456789abcdef0"


def test_finding_records_both_mttc_times() -> None:
    finding = Finding.from_event(events.portscan(INSTANCE))
    assert finding.event_time == datetime(2026, 10, 14, 10, 0, 0, tzinfo=UTC)
    assert finding.created_at == datetime(2026, 10, 14, 9, 59, 58, 123000, tzinfo=UTC)
    assert finding.seconds_since_event(datetime(2026, 10, 14, 10, 0, 42, tzinfo=UTC)) == 42
    assert finding.target == Ec2Target(INSTANCE)
    assert finding.is_sample is False


def test_created_at_is_optional() -> None:
    event = events.portscan(INSTANCE)
    del event["detail"]["createdAt"]
    assert Finding.from_event(event).created_at is None


@pytest.mark.parametrize(
    ("event", "target"),
    [
        (
            events.exfiltration("i-0123abcd"),
            Ec2Target("i-0123abcd", session_role_id="AROAEXAMPLEFAKEROLEID"),
        ),
        (
            events.leaked_key("bob", "FAKEKEYID00000000001"),
            IamUserTarget("bob", "FAKEKEYID00000000001"),
        ),
        (events.public_bucket("cs-dev-docs"), S3BucketTarget("cs-dev-docs")),
    ],
)
def test_targets(event: dict[str, Any], target: Any) -> None:
    assert Finding.from_event(event).target == target


def _resource(event: dict[str, Any], **changes: Any) -> dict[str, Any]:
    event["detail"]["resource"].update(changes)
    return event


@pytest.mark.parametrize(
    "event",
    [
        _resource(events.portscan(INSTANCE), instanceDetails={"instanceId": "i-xyz"}),
        _resource(events.portscan(INSTANCE), instanceDetails=None),
        _resource(events.exfiltration(INSTANCE), accessKeyDetails={"principalId": "nocolon"}),
        _resource(events.exfiltration(INSTANCE), accessKeyDetails=None),
        _resource(
            events.leaked_key("bob", "FAKEKEYID00000000001"),
            accessKeyDetails={
                "userType": "IAMUser",
                "userName": "b o b",
                "accessKeyId": "FAKEKEYID00000000001",
            },
        ),
        _resource(
            events.leaked_key("bob", "FAKEKEYID00000000001"),
            accessKeyDetails={"userType": "IAMUser", "userName": "bob", "accessKeyId": "short"},
        ),
        _resource(
            events.public_bucket("cs-dev-docs"), s3BucketDetails=[{"name": "a"}, {"name": "b"}]
        ),
        _resource(events.public_bucket("cs-dev-docs"), s3BucketDetails=[{"name": "Bad_Name"}]),
    ],
)
def test_unresolvable_targets_are_unknown(event: dict[str, Any]) -> None:
    assert isinstance(Finding.from_event(event).target, UnknownTarget)


@pytest.mark.parametrize(
    "detail_change",
    [
        {"severity": True},
        {"severity": "8"},
        {"id": "bad id with spaces"},
        {"createdAt": 5},
    ],
)
def test_malformed_details(detail_change: dict[str, Any]) -> None:
    event = events.portscan(INSTANCE)
    event["detail"].update(detail_change)
    with pytest.raises(MalformedFindingError):
        Finding.from_event(event)


def test_incident_repository_refuses_router_owned_fields(world: Any) -> None:
    repo = IncidentRepository(INCIDENTS_TABLE, boto3.client("dynamodb"))
    world.seed_incident("f-1")
    for field in ("status", "containedAt", "eventTime"):
        with pytest.raises(ValueError, match="router-owned"):
            repo.set_fields("f-1", {field: "x"})
    repo.set_fields("f-1", {})
    assert repo.get("f-1")["status"] == "DETECTED"


def test_incident_writes_require_an_existing_row(world: Any) -> None:
    repo = IncidentRepository(INCIDENTS_TABLE, boto3.client("dynamodb"))
    with pytest.raises(Exception, match="ConditionalCheckFailed"):
        repo.append_action("no-such-incident", {"step": "x"})


def test_evidence_checksum_mismatch_raises() -> None:
    class S3:
        def put_object(self, **_: Any) -> dict[str, Any]:
            return {"ChecksumSHA256": "AAAA", "VersionId": "1"}

    with pytest.raises(EvidenceIntegrityError):
        EvidenceCollector("bucket", S3()).put_json("k", {"a": 1})


def test_exfiltration_target_carries_the_stolen_role() -> None:
    target = Finding.from_event(
        events.exfiltration("i-0123abcd", role_id="AROAFAKEROLEID0001")
    ).target
    assert target == Ec2Target("i-0123abcd", session_role_id="AROAFAKEROLEID0001")


def test_exfiltration_with_bad_role_id_is_unknown() -> None:
    event = events.exfiltration("i-0123abcd", role_id="AIDANOTAROLE00000")
    assert isinstance(Finding.from_event(event).target, UnknownTarget)


@pytest.mark.parametrize(
    ("now", "cutoff"),
    [
        (datetime(2026, 10, 14, 10, 0, 7, tzinfo=UTC), "2026-10-14T10:00:07Z"),
        (datetime(2026, 10, 14, 10, 0, 7, 1, tzinfo=UTC), "2026-10-14T10:00:08Z"),
        (datetime(2026, 10, 14, 23, 59, 59, 500000, tzinfo=UTC), "2026-10-15T00:00:00Z"),
    ],
)
def test_session_revoke_cutoff_rounds_up_to_whole_seconds(now: datetime, cutoff: str) -> None:
    document = json.loads(session_revoke_policy(now))
    assert document["Statement"][0]["Condition"] == {"DateLessThan": {"aws:TokenIssueTime": cutoff}}
    assert is_revoke_policy(document) is True
    assert is_revoke_policy(json.dumps(document)) is True
    assert is_revoke_policy({"Statement": [{"Sid": "Other", "Effect": "Deny"}]}) is False


def test_add_evidence_keeps_the_first_hash(world: Any) -> None:
    repo = IncidentRepository(INCIDENTS_TABLE, boto3.client("dynamodb"))
    world.seed_incident("f-2")
    repo.add_evidence("f-2", {"key": "a", "sha256": "first"})
    repo.add_evidence("f-2", {"key": "b", "sha256": "second"})
    row = repo.get("f-2")
    assert row["evidenceSha256"] == "first"
    assert [r["key"] for r in row["evidenceRecords"]] == ["a", "b"]
