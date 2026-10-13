"""PB-03: public S3 exposure."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError

from core.playbook import PlaybookError
from playbooks.pb03_s3_restore_bpa import BPA_FLAGS, Pb03S3RestoreBpa, lambda_handler
from tests import events
from tests.conftest import EVIDENCE_BUCKET

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


def s3_with(override: str, code: str) -> Any:
    def clients(service: str) -> Any:
        real = boto3.client(service)
        if service != "s3":
            return real

        class S3:
            def __getattr__(self, name: str) -> Any:
                if name == override:

                    def fail(**_: Any) -> Any:
                        raise ClientError({"Error": {"Code": code}}, name)

                    return fail
                return getattr(real, name)

        return S3()

    return clients


def test_restore_contains_and_keeps_prestate(world: Any, clock: Any) -> None:
    expose(world.bucket)
    event = events.public_bucket(world.bucket)
    world.seed_incident(event["detail"]["id"])

    result = Pb03S3RestoreBpa(world.settings, boto3.client, clock).handle(
        events.payload("restore", event)
    )

    assert result["contained"] is True
    assert result["verified"] == dict.fromkeys(BPA_FLAGS, True)
    after = boto3.client("s3").get_public_access_block(Bucket=world.bucket)
    assert after["PublicAccessBlockConfiguration"] == dict.fromkeys(BPA_FLAGS, True)

    body = boto3.client("s3").get_object(
        Bucket=EVIDENCE_BUCKET, Key="incidents/f-pb03-bucket/pb03-s3-prestate.json"
    )
    raw = body["Body"].read()
    prestate = json.loads(raw)
    # Captured BEFORE the restore: the old flags were all false.
    assert prestate["publicAccessBlock"]["PublicAccessBlockConfiguration"] == dict.fromkeys(
        BPA_FLAGS, False
    )
    assert prestate["policy"]["Policy"] == PUBLIC_POLICY
    assert "Owner" in prestate["acl"]

    row = world.incident(event["detail"]["id"])
    assert row["evidenceSha256"] == hashlib.sha256(raw).hexdigest()
    assert [a["step"] for a in row["actions"]] == ["capture-prestate", "restore-bpa"]


def test_bucket_without_policy_or_bpa(world: Any, clock: Any) -> None:
    event = events.public_bucket(world.bucket)
    world.seed_incident(event["detail"]["id"])
    result = Pb03S3RestoreBpa(world.settings, boto3.client, clock).handle(
        events.payload("restore", event)
    )
    assert result["contained"] is True
    raw = (
        boto3.client("s3")
        .get_object(Bucket=EVIDENCE_BUCKET, Key="incidents/f-pb03-bucket/pb03-s3-prestate.json")[
            "Body"
        ]
        .read()
    )
    prestate = json.loads(raw)
    assert prestate["policy"] is None
    assert prestate["publicAccessBlock"] is None


def test_prestate_read_error_does_not_block_containment(world: Any, clock: Any) -> None:
    event = events.public_bucket(world.bucket)
    world.seed_incident(event["detail"]["id"])
    result = Pb03S3RestoreBpa(
        world.settings, s3_with("get_bucket_acl", "AccessDenied"), clock
    ).handle(events.payload("restore", event))
    assert result["contained"] is True
    raw = (
        boto3.client("s3")
        .get_object(Bucket=EVIDENCE_BUCKET, Key="incidents/f-pb03-bucket/pb03-s3-prestate.json")[
            "Body"
        ]
        .read()
    )
    assert json.loads(raw)["acl"] == {"captureError": "AccessDenied"}


def test_evidence_write_failure_is_recorded_not_fatal(world: Any, clock: Any) -> None:
    event = events.public_bucket(world.bucket)
    world.seed_incident(event["detail"]["id"])
    result = Pb03S3RestoreBpa(world.settings, s3_with("put_object", "AccessDenied"), clock).handle(
        events.payload("restore", event)
    )
    assert result["contained"] is True
    assert result["evidence"] is None
    assert result["evidenceError"] == "ClientError"
    assert world.incident(event["detail"]["id"])["actions"][-1]["step"] == "evidence-failed"


def test_restore_failure_propagates(world: Any, clock: Any) -> None:
    event = events.public_bucket(world.bucket)
    world.seed_incident(event["detail"]["id"])
    with pytest.raises(ClientError):
        Pb03S3RestoreBpa(
            world.settings, s3_with("put_public_access_block", "AccessDenied"), clock
        ).handle(events.payload("restore", event))


def test_bucket_outside_prefix_is_refused(world: Any, clock: Any) -> None:
    event = events.public_bucket("someone-elses-bucket")
    with pytest.raises(PlaybookError, match="prefix"):
        Pb03S3RestoreBpa(world.settings, boto3.client, clock).handle(
            events.payload("restore", event)
        )


def test_non_bucket_target_is_refused(world: Any, clock: Any) -> None:
    with pytest.raises(PlaybookError, match="S3 bucket"):
        Pb03S3RestoreBpa(world.settings, boto3.client, clock).handle(
            events.payload("restore", events.portscan(world.instance_id))
        )


def test_dry_run_leaves_bucket_exposed(world: Any, clock: Any) -> None:
    expose(world.bucket)
    result = Pb03S3RestoreBpa(world.settings, boto3.client, clock).handle(
        events.payload("restore", events.public_bucket(world.bucket), dry_run=True)
    )
    assert result["contained"] is False
    after = boto3.client("s3").get_public_access_block(Bucket=world.bucket)
    assert after["PublicAccessBlockConfiguration"] == dict.fromkeys(BPA_FLAGS, False)


def test_lambda_handler_entry_point(world: Any) -> None:
    event = events.public_bucket(world.bucket)
    world.seed_incident(event["detail"]["id"])
    assert lambda_handler(events.payload("restore", event), None)["contained"] is True
