"""PB-03: public S3 exposure."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError

from core.config import Settings
from core.playbook import PlaybookError
from playbooks.pb03_s3_restore_bpa import BPA_FLAGS, Pb03S3RestoreBpa, lambda_handler
from tests import events
from tests.conftest import EVIDENCE_BUCKET, EXECUTION_ARN, NOW

PUBLIC_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Public",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::cs-dev-public-docs/*",
        }
    ],
}


def expose(bucket: str) -> None:
    s3 = boto3.client("s3")
    s3.put_public_access_block(
        Bucket=bucket, PublicAccessBlockConfiguration=dict.fromkeys(BPA_FLAGS, False)
    )
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(PUBLIC_POLICY))


def failing(method: str, code: str) -> Any:
    def clients(service: str, **kw: Any) -> Any:
        real = boto3.client(service, **kw)
        if service != "s3":
            return real

        def fail(**_: Any) -> Any:
            raise ClientError({"Error": {"Code": code}}, method)

        class S3:
            def __getattr__(self, name: str) -> Any:
                return fail if name == method else getattr(real, name)

        return S3()

    return clients


def pb03(world: Any, clock: Any, clients: Any = None) -> Pb03S3RestoreBpa:
    return Pb03S3RestoreBpa(world.settings, clients or boto3.client, clock, sleep=lambda _: None)


def restore_then_evidence(world: Any, clock: Any, event: dict[str, Any]) -> tuple[Any, Any]:
    """Run both router steps, passing $.containment like cs-ir-router does."""
    restored = pb03(world, clock).handle(events.payload("restore", event))
    state = events.router_state(event)
    state["containment"] = {"result": restored}
    evidence = pb03(world, clock).handle({"action": "evidence", "event": state})
    return restored, evidence


def test_restore_contains_and_returns_prestate(world: Any, clock: Any) -> None:
    expose(world.bucket)
    event = events.public_bucket(world.bucket)
    world.seed_incident(event["detail"]["id"])

    result = pb03(world, clock).handle(events.payload("restore", event))

    assert result["contained"] is True
    assert result["verified"] == dict.fromkeys(BPA_FLAGS, True)
    after = boto3.client("s3").get_public_access_block(Bucket=world.bucket)
    assert after["PublicAccessBlockConfiguration"] == dict.fromkeys(BPA_FLAGS, True)
    # Captured BEFORE the restore: the old flags were all false.
    prestate = result["prestate"]
    assert prestate["publicAccessBlock"]["PublicAccessBlockConfiguration"] == dict.fromkeys(
        BPA_FLAGS, False
    )
    assert prestate["policy"]["Policy"] == PUBLIC_POLICY
    assert "Owner" in prestate["acl"]
    # No evidence write inside the MTTC window (audit A4).
    listed = boto3.client("s3").list_objects_v2(Bucket=EVIDENCE_BUCKET)
    assert listed.get("KeyCount", 0) == 0
    row = world.incident(event["detail"]["id"])
    assert [a["step"] for a in row["actions"]] == ["capture-prestate", "restore-bpa"]


def test_evidence_step_stores_hashed_prestate(world: Any, clock: Any) -> None:
    expose(world.bucket)
    event = events.public_bucket(world.bucket)
    world.seed_incident(event["detail"]["id"])

    _, evidence = restore_then_evidence(world, clock, event)

    key = evidence["evidence"]["key"]
    assert key == "incidents/f-pb03-bucket/pb03-s3-prestate-20261014T100007Z.json"
    raw = boto3.client("s3").get_object(Bucket=EVIDENCE_BUCKET, Key=key)["Body"].read()
    document = json.loads(raw)
    assert document["actor"] == EXECUTION_ARN
    assert document["policy"]["Policy"] == PUBLIC_POLICY
    assert (
        world.incident(event["detail"]["id"])["evidenceSha256"] == hashlib.sha256(raw).hexdigest()
    )


def test_evidence_without_prestate_raises(world: Any, clock: Any) -> None:
    event = events.public_bucket(world.bucket)
    with pytest.raises(PlaybookError, match="no pre-state"):
        pb03(world, clock).handle(events.payload("evidence", event))


def test_bucket_without_policy_or_bpa(world: Any, clock: Any) -> None:
    event = events.public_bucket(world.bucket)
    world.seed_incident(event["detail"]["id"])
    result = pb03(world, clock).handle(events.payload("restore", event))
    assert result["contained"] is True
    assert result["prestate"]["policy"] is None
    assert result["prestate"]["publicAccessBlock"] is None


def test_unparsable_policy_is_kept_raw() -> None:
    class S3:
        def get_bucket_policy(self, **_: Any) -> dict[str, Any]:
            return {"Policy": "{not json"}

        def __getattr__(self, name: str) -> Any:
            def missing(**_: Any) -> Any:
                raise ClientError({"Error": {"Code": "Throttling"}}, name)

            return missing

    playbook = Pb03S3RestoreBpa(
        Settings.from_env(
            {
                "DRY_RUN_PARAM": "/p",
                "SCOPE_TAG_KEY": "k",
                "SCOPE_TAG_VALUE": "v",
                "INCIDENTS_TABLE": "t",
                "EVIDENCE_BUCKET": "b",
                "QUARANTINE_SG_ID": "sg-1",
                "BUCKET_NAME_PREFIX": "cs-dev-",
            }
        ),
        clients=lambda *_, **__: None,
        clock=lambda: NOW,
    )
    prestate = playbook._prestate(S3(), "cs-dev-x")
    assert prestate["policy"] == {"Policy": "{not json"}
    assert prestate["acl"] == {"captureError": "Throttling"}


def test_prestate_read_error_does_not_block_containment(world: Any, clock: Any) -> None:
    event = events.public_bucket(world.bucket)
    world.seed_incident(event["detail"]["id"])
    result = pb03(world, clock, failing("get_bucket_acl", "AccessDenied")).handle(
        events.payload("restore", event)
    )
    assert result["contained"] is True
    assert result["prestate"]["acl"] == {"captureError": "AccessDenied"}


def test_restore_failure_propagates(world: Any, clock: Any) -> None:
    event = events.public_bucket(world.bucket)
    world.seed_incident(event["detail"]["id"])
    with pytest.raises(ClientError):
        pb03(world, clock, failing("put_public_access_block", "AccessDenied")).handle(
            events.payload("restore", event)
        )


@pytest.mark.parametrize(
    "finding_type", ["Exfiltration:S3/AnomalousBehavior", "Impact:S3/MaliciousIPCaller"]
)
def test_non_exposure_finding_is_refused(world: Any, clock: Any, finding_type: str) -> None:
    # Audit A1: BPA does not stop an authenticated principal.
    event = events.public_bucket(world.bucket)
    event["detail"]["type"] = finding_type
    with pytest.raises(PlaybookError, match="not a public-exposure finding"):
        pb03(world, clock).handle(events.payload("restore", event))


def test_untagged_bucket_is_refused(world: Any, clock: Any) -> None:
    expose(world.untagged_bucket)
    with pytest.raises(PlaybookError, match="scope tag"):
        pb03(world, clock).handle(
            events.payload("restore", events.public_bucket(world.untagged_bucket))
        )


def test_bucket_outside_prefix_is_refused(world: Any, clock: Any) -> None:
    with pytest.raises(PlaybookError, match="prefix"):
        pb03(world, clock).handle(
            events.payload("restore", events.public_bucket("someone-elses-bucket"))
        )


def test_non_bucket_target_is_refused(world: Any, clock: Any) -> None:
    with pytest.raises(PlaybookError, match="S3 bucket"):
        pb03(world, clock).handle(events.payload("restore", events.portscan(world.instance_id)))


def test_dry_run_leaves_bucket_exposed(world: Any, clock: Any) -> None:
    expose(world.bucket)
    result = pb03(world, clock).handle(
        events.payload("restore", events.public_bucket(world.bucket), dry_run=True)
    )
    assert result["contained"] is False
    after = boto3.client("s3").get_public_access_block(Bucket=world.bucket)
    assert after["PublicAccessBlockConfiguration"] == dict.fromkeys(BPA_FLAGS, False)


def test_lambda_handler_entry_point(world: Any) -> None:
    event = events.public_bucket(world.bucket)
    world.seed_incident(event["detail"]["id"])
    assert lambda_handler(events.payload("restore", event), None)["contained"] is True
