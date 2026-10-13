"""Safety guard: the R2 control. Rule order and fail-closed behaviour (soar/README.md)."""

from __future__ import annotations

import copy
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError

from core.config import Settings
from core.finding import Ec2Target
from core.guard import AwsTagReader, Decision, SafetyGuard, read_dry_run
from safety_guard.handler import lambda_handler
from tests import events

SETTINGS = Settings.from_env(
    {
        "DRY_RUN_PARAM": "/p",
        "SCOPE_TAG_KEY": "cloudshield:soar-scope",
        "SCOPE_TAG_VALUE": "in-scope",
        "INCIDENTS_TABLE": "t",
        "EVIDENCE_BUCKET": "b",
        "QUARANTINE_SG_ID": "sg-1",
        "BUCKET_NAME_PREFIX": "cs-dev-",
    }
)
IN_SCOPE = {"cloudshield:soar-scope": "in-scope"}
INSTANCE = "i-0123456789abcdef0"


class FakeTags:
    def __init__(self, tags: dict[str, str] | None) -> None:
        self.tags, self.calls = tags, 0

    def tags_for(self, target: Any) -> dict[str, str] | None:
        self.calls += 1
        return self.tags


def guard(dry_run: bool | None = False, tags: dict[str, str] | None = IN_SCOPE) -> SafetyGuard:
    return SafetyGuard(SETTINGS, FakeTags(tags), lambda: dry_run)


# ---------------------------------------------------------------- rule 1
@pytest.mark.parametrize("dry_run", [True, False])
def test_dry_run_switch_is_passed_through(dry_run: bool) -> None:
    decision = guard(dry_run).evaluate(events.portscan(INSTANCE))
    assert decision == Decision(True, dry_run, "target in scope")


def test_unreadable_switch_blocks_and_reports_dry_run() -> None:
    assert guard(None).evaluate(events.portscan(INSTANCE)) == Decision(
        False, True, "dry-run switch unreadable"
    )


def test_switch_is_read_on_every_call() -> None:
    values = iter([False, None])
    g = SafetyGuard(SETTINGS, FakeTags(IN_SCOPE), lambda: next(values))
    assert g.evaluate(events.portscan(INSTANCE)).allowed is True
    assert g.evaluate(events.portscan(INSTANCE)).allowed is False


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("true", True),
        ("false", False),
        (" FALSE ", False),
        ("yes", None),
        ("", None),
    ],
)
def test_read_dry_run_values(raw: str, expected: bool | None) -> None:
    class Ssm:
        def get_parameter(self, Name: str) -> dict[str, Any]:
            return {"Parameter": {"Value": raw}}

    assert read_dry_run(Ssm(), "/p") is expected


def test_read_dry_run_error_is_none() -> None:
    class Ssm:
        def get_parameter(self, Name: str) -> dict[str, Any]:
            raise ClientError({"Error": {"Code": "ParameterNotFound"}}, "GetParameter")

    assert read_dry_run(Ssm(), "/p") is None


# ---------------------------------------------------------------- rule 2
def test_sample_allowed_in_dry_run_without_tag_lookup() -> None:
    tags = FakeTags(None)
    g = SafetyGuard(SETTINGS, tags, lambda: True)
    decision = g.evaluate(events.portscan(INSTANCE, sample=True))
    assert decision == Decision(True, True, "sample finding (dry-run only)")
    assert tags.calls == 0


@pytest.mark.parametrize("sample", [True, "true", "TRUE"])
def test_sample_refused_live(sample: Any) -> None:
    assert guard(False).evaluate(events.portscan(INSTANCE, sample=sample)) == Decision(
        False, False, "sample finding"
    )


@pytest.mark.parametrize("sample", [False, "false", None])
def test_non_sample_values_go_through_rule_3(sample: Any) -> None:
    decision = guard(False, tags={}).evaluate(events.portscan(INSTANCE, sample=sample))
    assert decision.reason == "target lacks the SOAR scope tag"


# ---------------------------------------------------------------- rule 3
@pytest.mark.parametrize(
    "tags", [{}, {"cloudshield:soar-scope": "IN-SCOPE"}, {"cloudshield:soar-enabled": "true"}]
)
def test_missing_or_wrong_tag_blocks(tags: dict[str, str]) -> None:
    decision = guard(False, tags).evaluate(events.portscan(INSTANCE))
    assert decision == Decision(False, False, "target lacks the SOAR scope tag")


def test_missing_target_blocks() -> None:
    assert guard(False, None).evaluate(events.portscan(INSTANCE)).reason == "target not found"


def test_bucket_outside_prefix_blocked_before_tag_lookup() -> None:
    tags = FakeTags(IN_SCOPE)
    decision = SafetyGuard(SETTINGS, tags, lambda: False).evaluate(
        events.public_bucket("someone-elses-bucket")
    )
    assert decision.allowed is False
    assert decision.reason == "bucket outside the project name prefix"
    assert tags.calls == 0


def test_exfiltration_targets_the_instance() -> None:
    tags = FakeTags(IN_SCOPE)
    seen: list[Any] = []

    def record(target: Any) -> dict[str, str]:
        seen.append(target)
        return IN_SCOPE

    tags.tags_for = record  # type: ignore[method-assign]
    assert (
        SafetyGuard(SETTINGS, tags, lambda: False).evaluate(events.exfiltration(INSTANCE)).allowed
        is True
    )
    assert seen == [Ec2Target(INSTANCE)]


# ---------------------------------------------------------------- rule 4
@pytest.mark.parametrize(
    "event",
    [
        events.leaked_key("root", "FAKEKEYID00000000099", user_type="Root"),
        events.leaked_key("x", "FAKESTSKEYID00000099", user_type="AssumedRole"),
        {
            **events.portscan(INSTANCE),
            "detail": {
                **events.portscan(INSTANCE)["detail"],
                "resource": {"resourceType": "EKSCluster"},
            },
        },
    ],
)
def test_unknown_or_out_of_scope_resource_blocks(event: dict[str, Any]) -> None:
    decision = guard(False).evaluate(event)
    assert decision.allowed is False
    assert decision.reason.startswith("unknown resource")


# ------------------------------------------------- malformed payloads
def _without(path: list[str]) -> dict[str, Any]:
    event = copy.deepcopy(events.portscan(INSTANCE))
    node: Any = event
    for key in path[:-1]:
        node = node[key]
    del node[path[-1]]
    return event


@pytest.mark.parametrize(
    "event",
    [
        None,
        [],
        "x",
        {},
        {"detail": None},
        {"detail": {}},
        _without(["time"]),
        _without(["detail", "id"]),
        _without(["detail", "type"]),
        _without(["detail", "severity"]),
        _without(["detail", "resource"]),
        {**events.portscan(INSTANCE), "time": "yesterday"},
        {**events.portscan(INSTANCE), "time": "2026-10-14T10:00:00"},
    ],
)
def test_malformed_event_blocks(event: Any) -> None:
    decision = guard(False).evaluate(event)
    assert decision.allowed is False
    assert decision.reason.startswith("malformed finding")


# ------------------------------------------------- return contract
def test_to_dict_always_returns_real_booleans() -> None:
    weird = Decision("true", "false", "r")  # type: ignore[arg-type]
    assert weird.to_dict() == {"allowed": False, "dry_run": True, "reason": "r"}


# ------------------------------------------------- handler, against moto
def test_handler_allows_tagged_instance(world: Any) -> None:
    assert lambda_handler(events.portscan(world.instance_id), None) == {
        "allowed": True,
        "dry_run": False,
        "reason": "target in scope",
    }


def test_handler_blocks_untagged_instance(world: Any) -> None:
    result = lambda_handler(events.portscan(world.untagged_instance_id), None)
    assert result["allowed"] is False


def test_handler_blocks_unknown_instance(world: Any) -> None:
    result = lambda_handler(events.portscan("i-0fffffffffffffff0"), None)
    assert result == {"allowed": False, "dry_run": False, "reason": "target not found"}


def test_handler_iam_user_and_bucket_tags(world: Any) -> None:
    assert (
        lambda_handler(events.leaked_key(world.user_name, world.access_key_id), None)["allowed"]
        is True
    )
    assert (
        lambda_handler(
            events.leaked_key(world.untagged_user_name, world.untagged_access_key_id), None
        )["allowed"]
        is False
    )
    assert lambda_handler(events.public_bucket(world.bucket), None)["allowed"] is True
    assert lambda_handler(events.public_bucket(world.untagged_bucket), None)["allowed"] is False
    assert (
        lambda_handler(events.public_bucket("cs-dev-does-not-exist"), None)["reason"]
        == "target not found"
    )


def test_handler_dry_run_param_true(world: Any) -> None:
    world.set_dry_run("true")
    assert lambda_handler(events.portscan(world.instance_id), None)["dry_run"] is True


def test_handler_missing_dry_run_param_blocks(world: Any) -> None:
    boto3.client("ssm").delete_parameter(Name=world.settings.dry_run_param)
    assert lambda_handler(events.portscan(world.instance_id), None) == {
        "allowed": False,
        "dry_run": True,
        "reason": "dry-run switch unreadable",
    }


def test_handler_fails_closed_on_any_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DRY_RUN_PARAM", raising=False)
    assert lambda_handler(events.portscan(INSTANCE), None) == {
        "allowed": False,
        "dry_run": True,
        "reason": "guard error: ConfigError",
    }


def test_tag_reader_propagates_unexpected_errors() -> None:
    def clients(service: str) -> Any:
        class Ec2:
            def describe_instances(self, **_: Any) -> Any:
                raise ClientError({"Error": {"Code": "Throttling"}}, "DescribeInstances")

        return Ec2()

    with pytest.raises(ClientError):
        AwsTagReader(clients).tags_for(Ec2Target(INSTANCE))
