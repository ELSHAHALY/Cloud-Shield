"""PB-02: leaked IAM user access key."""

from __future__ import annotations

from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError

from core.playbook import REVOKE_POLICY_NAME, PlaybookError
from playbooks.pb02_iam_key_revoke import Pb02IamKeyRevoke, lambda_handler
from tests import events

# "ASIA" + 12 characters: a temporary-key id shape that Gitleaks' AWS rule
# (prefix + 16) does not match.
SESSION_KEY = "ASIAFAKESESSION1"


def key_status(user: str, key_id: str) -> str:
    keys = boto3.client("iam").list_access_keys(UserName=user)["AccessKeyMetadata"]
    return next(k["Status"] for k in keys if k["AccessKeyId"] == key_id)


def failing(method: str, code: str) -> Any:
    def clients(service: str, **kw: Any) -> Any:
        real = boto3.client(service, **kw)
        if service != "iam":
            return real

        def fail(**_: Any) -> Any:
            raise ClientError({"Error": {"Code": code}}, method)

        class Iam:
            def __getattr__(self, name: str) -> Any:
                return fail if name == method else getattr(real, name)

        return Iam()

    return clients


def pb02(world: Any, clock: Any, clients: Any = None) -> Pb02IamKeyRevoke:
    return Pb02IamKeyRevoke(world.settings, clients or boto3.client, clock, sleep=lambda _: None)


def test_revoke_contains(world: Any, clock: Any) -> None:
    event = events.leaked_key(world.user_name, world.access_key_id)
    world.seed_incident(event["detail"]["id"])

    result = pb02(world, clock).handle(events.payload("revoke", event))

    assert result["contained"] is True
    assert result["verified"] == {"keysInactive": True, "sessionsRevoked": True}
    assert result["sessionRevoke"] == "applied"
    assert key_status(world.user_name, world.access_key_id) == "Inactive"
    names = boto3.client("iam").list_user_policies(UserName=world.user_name)["PolicyNames"]
    assert names == [REVOKE_POLICY_NAME]
    row = world.incident(event["detail"]["id"])
    assert [a["step"] for a in row["actions"]] == ["revoke-user-sessions", "deactivate-keys"]


def test_session_key_deactivates_the_users_long_term_keys(world: Any, clock: Any) -> None:
    iam = boto3.client("iam")
    second = iam.create_access_key(UserName=world.user_name)["AccessKey"]["AccessKeyId"]
    event = events.leaked_key(world.user_name, SESSION_KEY)
    world.seed_incident(event["detail"]["id"])

    result = pb02(world, clock).handle(events.payload("revoke", event))

    assert result["contained"] is True
    assert result["deactivatedKeys"] == sorted([world.access_key_id, second])
    assert key_status(world.user_name, world.access_key_id) == "Inactive"
    assert key_status(world.user_name, second) == "Inactive"


def test_boundary_denial_is_not_containment(world: Any, clock: Any) -> None:
    # Audit A2: a dead key does not kill sessions already minted from it.
    event = events.leaked_key(world.user_name, world.access_key_id)
    world.seed_incident(event["detail"]["id"])

    result = pb02(world, clock, failing("put_user_policy", "AccessDenied")).handle(
        events.payload("revoke", event)
    )

    assert result["contained"] is False
    assert result["verified"] == {"keysInactive": True, "sessionsRevoked": False}
    assert result["sessionRevoke"].startswith("denied")
    # The key is still deactivated: reduce harm even when not fully contained.
    assert key_status(world.user_name, world.access_key_id) == "Inactive"


def test_other_session_revoke_errors_propagate(world: Any, clock: Any) -> None:
    event = events.leaked_key(world.user_name, world.access_key_id)
    world.seed_incident(event["detail"]["id"])
    with pytest.raises(ClientError):
        pb02(world, clock, failing("put_user_policy", "ServiceFailure")).handle(
            events.payload("revoke", event)
        )


def test_deactivation_failure_propagates(world: Any, clock: Any) -> None:
    event = events.leaked_key(world.user_name, world.access_key_id)
    world.seed_incident(event["detail"]["id"])
    with pytest.raises(ClientError):
        pb02(world, clock, failing("update_access_key", "AccessDenied")).handle(
            events.payload("revoke", event)
        )


def test_readback_error_propagates(world: Any, clock: Any) -> None:
    event = events.leaked_key(world.user_name, world.access_key_id)
    world.seed_incident(event["detail"]["id"])
    with pytest.raises(ClientError):
        pb02(world, clock, failing("get_user_policy", "ServiceFailure")).handle(
            events.payload("revoke", event)
        )


def test_key_not_on_user_raises(world: Any, clock: Any) -> None:
    event = events.leaked_key(world.user_name, "FAKEKEYID00000000000")
    world.seed_incident(event["detail"]["id"])
    with pytest.raises(PlaybookError, match="not found"):
        pb02(world, clock).handle(events.payload("revoke", event))


def test_untagged_user_is_refused(world: Any, clock: Any) -> None:
    event = events.leaked_key(world.untagged_user_name, world.untagged_access_key_id)
    with pytest.raises(PlaybookError, match="scope tag"):
        pb02(world, clock).handle(events.payload("revoke", event))
    assert key_status(world.untagged_user_name, world.untagged_access_key_id) == "Active"


def test_non_iam_user_target_is_refused(world: Any, clock: Any) -> None:
    with pytest.raises(PlaybookError, match="IAM user"):
        pb02(world, clock).handle(events.payload("revoke", events.portscan(world.instance_id)))


def test_dry_run_leaves_key_active(world: Any, clock: Any) -> None:
    event = events.leaked_key(world.user_name, world.access_key_id)
    result = pb02(world, clock).handle(events.payload("revoke", event, dry_run=True))
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
