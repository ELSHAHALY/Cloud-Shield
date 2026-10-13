"""PB-02: leaked IAM user access key."""

from __future__ import annotations

from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError

from core.playbook import PlaybookError
from playbooks.pb02_iam_key_revoke import REVOKE_POLICY_NAME, Pb02IamKeyRevoke, lambda_handler
from tests import events


def key_status(user: str, key_id: str) -> str:
    keys = boto3.client("iam").list_access_keys(UserName=user)["AccessKeyMetadata"]
    return next(k["Status"] for k in keys if k["AccessKeyId"] == key_id)


def with_iam(override: str, code: str) -> Any:
    def clients(service: str) -> Any:
        real = boto3.client(service)
        if service != "iam":
            return real

        class Iam:
            def __getattr__(self, name: str) -> Any:
                if name == override:

                    def fail(**_: Any) -> Any:
                        raise ClientError({"Error": {"Code": code}}, name)

                    return fail
                return getattr(real, name)

        return Iam()

    return clients


def test_revoke_contains(world: Any, clock: Any) -> None:
    event = events.leaked_key(world.user_name, world.access_key_id)
    world.seed_incident(event["detail"]["id"])

    result = Pb02IamKeyRevoke(world.settings, boto3.client, clock).handle(
        events.payload("revoke", event)
    )

    assert result["contained"] is True
    assert result["sessionRevoke"] == "applied"
    assert key_status(world.user_name, world.access_key_id) == "Inactive"
    names = boto3.client("iam").list_user_policies(UserName=world.user_name)["PolicyNames"]
    assert names == [REVOKE_POLICY_NAME]
    row = world.incident(event["detail"]["id"])
    assert [a["step"] for a in row["actions"]] == ["deactivate-key", "revoke-user-sessions"]


def test_boundary_guardrail_denial_is_recorded_not_fatal(world: Any, clock: Any) -> None:
    event = events.leaked_key(world.user_name, world.access_key_id)
    world.seed_incident(event["detail"]["id"])

    result = Pb02IamKeyRevoke(
        world.settings, with_iam("put_user_policy", "AccessDenied"), clock
    ).handle(events.payload("revoke", event))

    assert result["contained"] is True
    assert result["sessionRevoke"] == "denied-by-permissions-boundary-guardrail"
    assert world.incident(event["detail"]["id"])["actions"][1]["result"] == result["sessionRevoke"]


def test_other_session_revoke_errors_propagate(world: Any, clock: Any) -> None:
    event = events.leaked_key(world.user_name, world.access_key_id)
    world.seed_incident(event["detail"]["id"])
    with pytest.raises(ClientError):
        Pb02IamKeyRevoke(
            world.settings, with_iam("put_user_policy", "ServiceFailure"), clock
        ).handle(events.payload("revoke", event))


def test_deactivation_failure_propagates(world: Any, clock: Any) -> None:
    event = events.leaked_key(world.user_name, world.access_key_id)
    world.seed_incident(event["detail"]["id"])
    with pytest.raises(ClientError):
        Pb02IamKeyRevoke(
            world.settings, with_iam("update_access_key", "AccessDenied"), clock
        ).handle(events.payload("revoke", event))


def test_key_not_on_user_raises(world: Any, clock: Any) -> None:
    event = events.leaked_key(world.user_name, "FAKEKEYID00000000000")
    world.seed_incident(event["detail"]["id"])
    with pytest.raises(ClientError):
        Pb02IamKeyRevoke(world.settings, boto3.client, clock).handle(
            events.payload("revoke", event)
        )


def test_key_missing_after_update_is_failed(world: Any, clock: Any) -> None:
    event = events.leaked_key(world.user_name, world.access_key_id)
    world.seed_incident(event["detail"]["id"])

    def clients(service: str) -> Any:
        real = boto3.client(service)
        if service != "iam":
            return real

        class Iam:
            def __getattr__(self, name: str) -> Any:
                return getattr(real, name)

            def get_paginator(self, name: str) -> Any:
                class Pages:
                    def paginate(self, **_: Any) -> list[dict[str, Any]]:
                        return [{"AccessKeyMetadata": []}]

                return Pages()

        return Iam()

    with pytest.raises(PlaybookError, match="not found"):
        Pb02IamKeyRevoke(world.settings, clients, clock).handle(events.payload("revoke", event))


def test_non_iam_user_target_is_refused(world: Any, clock: Any) -> None:
    event = events.portscan(world.instance_id)
    with pytest.raises(PlaybookError, match="IAM user"):
        Pb02IamKeyRevoke(world.settings, boto3.client, clock).handle(
            events.payload("revoke", event)
        )


def test_dry_run_leaves_key_active(world: Any, clock: Any) -> None:
    event = events.leaked_key(world.user_name, world.access_key_id)
    result = Pb02IamKeyRevoke(world.settings, boto3.client, clock).handle(
        events.payload("revoke", event, dry_run=True)
    )
    assert result == {
        "contained": False,
        "would": "revoke",
        "dry_run": True,
        "plan": result["plan"],
    }
    assert key_status(world.user_name, world.access_key_id) == "Active"


def test_lambda_handler_entry_point(world: Any) -> None:
    event = events.leaked_key(world.user_name, world.access_key_id)
    world.seed_incident(event["detail"]["id"])
    assert lambda_handler(events.payload("revoke", event), None)["contained"] is True
