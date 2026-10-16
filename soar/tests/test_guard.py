"""Safety guard: the R2 control. Rule order and fail-closed behaviour (soar/README.md)."""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from core.config import Settings
from core.finding import Ec2Target, iso
from core.guard import (
    AwsTagReader,
    Decision,
    LiveTask,
    SafetyGuard,
    read_dry_run,
    read_never_block,
)
from safety_guard.handler import lambda_handler
from tests import events
from tests.conftest import NOW

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
    assert seen == [Ec2Target(INSTANCE, session_role_id="AROAEXAMPLEFAKEROLEID")]


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


# =============================================================== Phase D
# ECS branch (PB-04) and IP branch (PB-05), plan §4.1 / §4.2. Tests written
# before core/guard.py's new branches.
PHASE_D_ENV = {
    "DRY_RUN_PARAM": "/p",
    "SCOPE_TAG_KEY": "cloudshield:soar-scope",
    "SCOPE_TAG_VALUE": "in-scope",
    "INCIDENTS_TABLE": "t",
    "EVIDENCE_BUCKET": "b",
    "QUARANTINE_SG_ID": "sg-1",
    "BUCKET_NAME_PREFIX": "cs-dev-",
    "ECS_CLUSTER_ARN": events.CLUSTER_ARN,
    "ECS_SERVICE_NAMES": "docs-api",
    "NEVER_BLOCK_PARAM": "/cs-dev/soar/pb05_never_block",
    "EDGE_EVENT_SOURCE": "cloudshield.edge",
}
D_SETTINGS = Settings.from_env(PHASE_D_ENV)
LIVE_OK = LiveTask(events.CLUSTER_ARN, "service:docs-api", dict(IN_SCOPE))
NEVER_BLOCK = (ip_network("8.8.8.8/32"), ip_network("2001:4860:4860::/48"))
EVENT_AT = datetime(2026, 10, 14, 10, 0, 0, tzinfo=UTC)


class FakeEcs(FakeTags):
    def __init__(self, live: LiveTask | None) -> None:
        super().__init__(None)
        self.live, self.ecs_calls = live, 0

    def ecs_task(self, cluster_arn: str, task_arn: str) -> LiveTask | None:
        self.ecs_calls += 1
        assert cluster_arn == events.CLUSTER_ARN  # always OUR cluster, never the finding's
        return self.live


def d_guard(
    *,
    live: LiveTask | None = LIVE_OK,
    dry_run: bool | None = False,
    never_block: Any = NEVER_BLOCK,
    settings: Settings = D_SETTINGS,
    now: datetime = NOW,
) -> tuple[SafetyGuard, FakeEcs]:
    reader = FakeEcs(live)
    return (
        SafetyGuard(settings, reader, lambda: dry_run, lambda: never_block, clock=lambda: now),
        reader,
    )


# ----------------------------------------------------------------- ECS
def test_ecs_task_in_scope_is_allowed() -> None:
    guard_, reader = d_guard()
    assert guard_.evaluate(events.ecs_runtime()) == Decision(True, False, "target in scope")
    assert reader.ecs_calls == 1


def test_ecs_live_tags_missing_refuses() -> None:
    guard_, _ = d_guard(live=LiveTask(events.CLUSTER_ARN, "service:docs-api", {}))
    assert guard_.evaluate(events.ecs_runtime()) == Decision(
        False, False, "target lacks the SOAR scope tag"
    )


def test_ecs_finding_embedded_tags_are_never_trusted() -> None:
    # The finding claims the tag; the live task does not carry it.
    guard_, _ = d_guard(live=LiveTask(events.CLUSTER_ARN, "service:docs-api", {}))
    event = events.ecs_runtime(task_tags=[{"key": "cloudshield:soar-scope", "value": "in-scope"}])
    assert guard_.evaluate(event).allowed is False
    # ...and the reverse: no tag in the finding, but the live task has it.
    guard_, _ = d_guard()
    assert guard_.evaluate(events.ecs_runtime(task_tags=[])).allowed is True


def test_ecs_missing_task_refuses() -> None:
    guard_, _ = d_guard(live=None)
    assert guard_.evaluate(events.ecs_runtime()).reason == "target not found"


def test_ecs_finding_cluster_mismatch_refuses_before_lookup() -> None:
    other = f"arn:aws:ecs:us-east-1:{events.ACCOUNT}:cluster/other"
    task = f"arn:aws:ecs:us-east-1:{events.ACCOUNT}:task/other/{events.TASK_ID}"
    guard_, reader = d_guard()
    decision = guard_.evaluate(events.ecs_runtime(task, cluster_arn=other))
    assert decision == Decision(False, False, "task outside the SOAR cluster")
    assert reader.ecs_calls == 0


def test_ecs_live_cluster_mismatch_refuses() -> None:
    other = f"arn:aws:ecs:us-east-1:{events.ACCOUNT}:cluster/other"
    guard_, _ = d_guard(live=LiveTask(other, "service:docs-api", dict(IN_SCOPE)))
    assert guard_.evaluate(events.ecs_runtime()).reason == "task outside the SOAR cluster"


def test_ecs_service_not_allowed_refuses() -> None:
    guard_, reader = d_guard()
    decision = guard_.evaluate(events.ecs_runtime(group="service:billing"))
    assert decision.reason == "service billing is not allowed for PB-04"
    assert reader.ecs_calls == 0


def test_ecs_group_not_a_service_refuses() -> None:
    guard_, reader = d_guard()
    decision = guard_.evaluate(events.ecs_runtime(group="family:cs-dev-app"))
    assert decision.reason == "task was not launched by a service"
    assert reader.ecs_calls == 0


def test_ecs_forged_group_refuses_on_live_group() -> None:
    # The finding says docs-api; the live task belongs to another group.
    guard_, _ = d_guard(live=LiveTask(events.CLUSTER_ARN, "service:billing", dict(IN_SCOPE)))
    assert guard_.evaluate(events.ecs_runtime()).reason == "live task group does not match"


def test_ecs_disabled_refuses() -> None:
    guard_, reader = d_guard(settings=SETTINGS)
    assert guard_.evaluate(events.ecs_runtime()).reason == "ECS containment is not configured"
    assert reader.ecs_calls == 0


def test_ecs_bad_task_arn_is_unknown() -> None:
    guard_, _ = d_guard()
    decision = guard_.evaluate(events.ecs_runtime(events.TASK_ARN.replace("0123", "XYZ_")))
    assert decision.reason.startswith("unknown resource")


# ------------------------------------------------------------------ IP
@pytest.mark.parametrize(
    ("address", "field"),
    [
        ("1.1.1.1", None),
        ("2606:4700:4700::1111", None),
        ("::ffff:1.1.1.1", "ipAddressV6"),
    ],
)
def test_ip_global_is_allowed(address: str, field: str | None) -> None:
    guard_, reader = d_guard()
    assert guard_.evaluate(events.edge_ip(address, field=field)) == Decision(
        True, False, "address may be blocked"
    )
    assert reader.calls == 0  # an IP has no tags
    assert reader.ecs_calls == 0


@pytest.mark.parametrize(
    "address",
    [
        "10.1.2.3",  # private
        "127.0.0.1",  # loopback
        "169.254.169.254",  # link-local (IMDS)
        "100.64.0.1",  # shared
        "192.0.2.1",  # documentation
        "198.51.100.7",
        "203.0.113.9",
        "2001:db8::1",
        "224.0.0.251",  # multicast
        "ff02::1",
        "0.0.0.0",  # noqa: S104 - unspecified address under test, not a bind
        "::",
        "240.0.0.1",  # reserved
        "255.255.255.255",
        "::ffff:10.0.0.1",  # mapped private
    ],
)
def test_ip_non_global_refuses(address: str) -> None:
    field = "ipAddressV6" if ":" in address else "ipAddressV4"
    guard_, _ = d_guard()
    decision = guard_.evaluate(events.edge_ip(address, field=field))
    assert decision.allowed is False
    assert decision.reason.startswith("address ")


@pytest.mark.parametrize("value", ["1.1.1.0/24", "1.1.1.1/32", "2606:4700::/32"])
def test_ip_cidr_string_refuses(value: str) -> None:
    guard_, _ = d_guard()
    decision = guard_.evaluate(events.edge_ip(value))
    assert decision.allowed is False
    assert decision.reason.startswith("unknown resource")


@pytest.mark.parametrize("address", ["8.8.8.8", "2001:4860:4860::8888", "::ffff:8.8.8.8"])
def test_ip_never_block_hit_refuses(address: str) -> None:
    guard_, _ = d_guard()
    decision = guard_.evaluate(events.edge_ip(address))
    assert decision == Decision(False, False, "address is on the never-block list")


@pytest.mark.parametrize("never_block", [None, ()])
def test_ip_never_block_unreadable_refuses(never_block: Any) -> None:
    guard_, _ = d_guard(never_block=never_block)
    assert guard_.evaluate(events.edge_ip()) == Decision(
        False, False, "never-block list unreadable"
    )


def test_ip_never_block_read_on_every_call() -> None:
    values = iter([NEVER_BLOCK, None])
    g = SafetyGuard(
        D_SETTINGS, FakeEcs(None), lambda: False, lambda: next(values), clock=lambda: NOW
    )
    assert g.evaluate(events.edge_ip()).allowed is True
    assert g.evaluate(events.edge_ip()).allowed is False


def test_ip_wrong_source_is_unknown() -> None:
    guard_, _ = d_guard()
    decision = guard_.evaluate(events.edge_ip(source="aws.guardduty"))
    assert decision.allowed is False
    assert decision.reason.startswith("unknown resource")


def test_ip_source_must_match_configured_edge_source() -> None:
    settings = Settings.from_env({**PHASE_D_ENV, "EDGE_EVENT_SOURCE": "cloudshield.other"})
    guard_, _ = d_guard(settings=settings)
    assert guard_.evaluate(events.edge_ip()).reason == "event is not from the edge source"


@pytest.mark.parametrize(
    "finding_type",
    [
        "CloudShield:IPAddress/SomethingNew",  # right prefix, not allow-listed
        "Recon:EC2/Portscan",
        "cloudshield:ipaddress/wafratelimitexceeded",  # case matters
    ],
)
def test_ip_edge_type_must_be_allow_listed(finding_type: str) -> None:
    # Audit A1: only edge types PB-05 can corroborate (Phase E adds its own).
    event = events.edge_ip()
    event["detail"]["type"] = finding_type
    guard_, _ = d_guard()
    decision = guard_.evaluate(event)
    assert decision == Decision(False, False, "edge finding type is not allowed")


def test_ip_disabled_refuses() -> None:
    guard_, _ = d_guard(settings=SETTINGS)
    assert guard_.evaluate(events.edge_ip()).reason == "IP blocking is not configured"


@pytest.mark.parametrize(
    ("now", "allowed"),
    [
        (EVENT_AT, True),
        (EVENT_AT + timedelta(minutes=15), True),
        (EVENT_AT + timedelta(minutes=15, seconds=1), False),  # stale
        (EVENT_AT - timedelta(seconds=60), True),
        (EVENT_AT - timedelta(seconds=61), False),  # from the future
    ],
)
def test_ip_freshness_window(now: datetime, allowed: bool) -> None:
    guard_, _ = d_guard(now=now)
    decision = guard_.evaluate(events.edge_ip())
    assert decision.allowed is allowed
    if not allowed:
        assert decision.reason == "edge event outside the freshness window"


def test_ip_sample_follows_rule_2() -> None:
    sample = events.edge_ip(sample=True)
    guard_, _ = d_guard(dry_run=True, never_block=None)
    assert guard_.evaluate(sample) == Decision(True, True, "sample finding (dry-run only)")
    guard_, _ = d_guard(dry_run=False)
    assert guard_.evaluate(sample) == Decision(False, False, "sample finding")


def test_ip_dry_run_passed_through() -> None:
    guard_, _ = d_guard(dry_run=True)
    assert guard_.evaluate(events.edge_ip()) == Decision(True, True, "address may be blocked")


@pytest.mark.parametrize(
    "event",
    [events.edge_ip(), events.edge_ip("10.0.0.1"), events.ecs_runtime(), events.ecs_runtime("x")],
)
def test_phase_d_decisions_are_exact_booleans(event: dict[str, Any]) -> None:
    for dry_run in (True, False, None):
        guard_, _ = d_guard(dry_run=dry_run)
        result = guard_.evaluate(event).to_dict()
        assert type(result["allowed"]) is bool
        assert type(result["dry_run"]) is bool


# --------------------------------------------------- never-block reader
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.8.8.8/32", (ip_network("8.8.8.8/32"),)),
        (
            " 8.8.8.8/32 , 2606:4700::/32 ",
            (ip_network("8.8.8.8/32"), ip_network("2606:4700::/32")),
        ),
        ("8.8.8.9/24", (ip_network("8.8.8.0/24"),)),  # host bits tolerated, as cidrhost() does
        ("8.8.8.8/32,not-a-cidr", None),  # one bad entry -> the whole list is unreadable
        ("8.8.8.8/33", None),
        ("8.8.8.8", None),  # bare addresses must carry a prefix
        (" , ", None),  # empty list -> unreadable (fail closed)
    ],
)
def test_read_never_block(value: str, expected: Any) -> None:
    class Ssm:
        def get_parameter(self, Name: str) -> dict[str, Any]:
            assert Name == "/nb"
            return {"Parameter": {"Value": value}}

    assert read_never_block(Ssm(), "/nb") == expected


def test_read_never_block_errors_are_none() -> None:
    class Ssm:
        def get_parameter(self, Name: str) -> dict[str, Any]:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetParameter")

    class Odd:
        def get_parameter(self, Name: str) -> dict[str, Any]:
            return {"Parameter": {"Value": 5}}

    assert read_never_block(Ssm(), "/nb") is None
    assert read_never_block(Odd(), "/nb") is None
    assert read_never_block(Odd(), "") is None


# ------------------------------------------------ handler, ECS (Stubber)
# moto's ECS gives tasks UUID ids (not the 32-hex ids real ECS uses), so the
# ECS reads are stubbed with botocore's Stubber, which still validates every
# request and response against the ECS API model.
LIVE_RESPONSE = {
    "tasks": [
        {
            "taskArn": events.TASK_ARN,
            "clusterArn": events.CLUSTER_ARN,
            "group": "service:docs-api",
            "tags": [{"key": "cloudshield:soar-scope", "value": "in-scope"}],
        }
    ],
    "failures": [],
}


def _stubbed_ecs(response: dict[str, Any]) -> tuple[Any, Stubber]:
    client = boto3.client("ecs", region_name="us-east-1")
    stub = Stubber(client)
    stub.add_response(
        "describe_tasks",
        response,
        {"cluster": events.CLUSTER_ARN, "tasks": [events.TASK_ARN], "include": ["TAGS"]},
    )
    stub.activate()
    return client, stub


def test_aws_reader_live_task_and_missing() -> None:
    client, stub = _stubbed_ecs(LIVE_RESPONSE)
    live = AwsTagReader(lambda service: client).ecs_task(events.CLUSTER_ARN, events.TASK_ARN)
    assert live == LIVE_OK
    stub.assert_no_pending_responses()

    client, stub = _stubbed_ecs(
        {"tasks": [], "failures": [{"arn": events.TASK_ARN, "reason": "MISSING"}]}
    )
    reader = AwsTagReader(lambda service: client)
    assert reader.ecs_task(events.CLUSTER_ARN, events.TASK_ARN) is None


def test_aws_reader_ecs_errors_propagate() -> None:
    client = boto3.client("ecs", region_name="us-east-1")
    stub = Stubber(client)
    stub.add_client_error("describe_tasks", "AccessDeniedException")
    stub.activate()
    with pytest.raises(ClientError):
        AwsTagReader(lambda service: client).ecs_task(events.CLUSTER_ARN, events.TASK_ARN)


def test_handler_ecs_task_in_scope(world: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from core import aws

    monkeypatch.setenv("ECS_CLUSTER_ARN", events.CLUSTER_ARN)
    monkeypatch.setenv("ECS_SERVICE_NAMES", "docs-api")
    ecs, stub = _stubbed_ecs(LIVE_RESPONSE)
    real = aws.client

    def clients(service: str, config: Any = None) -> Any:
        return ecs if service == "ecs" else real(service, config)

    monkeypatch.setattr(aws, "client", clients)
    assert lambda_handler(events.ecs_runtime(), None) == {
        "allowed": True,
        "dry_run": False,
        "reason": "target in scope",
    }
    stub.assert_no_pending_responses()


# ------------------------------------------------- handler, IP (moto SSM)
def _edge_now(address: str = "1.1.1.1") -> dict[str, Any]:
    return events.edge_ip(address, time=iso(datetime.now(UTC)))


def test_handler_ip_uses_live_never_block_list(world: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEVER_BLOCK_PARAM", "/cs-dev/soar/pb05_never_block")
    monkeypatch.setenv("EDGE_EVENT_SOURCE", "cloudshield.edge")
    # Parameter absent -> unreadable -> refused (fail closed).
    assert lambda_handler(_edge_now(), None)["reason"] == "never-block list unreadable"

    boto3.client("ssm").put_parameter(
        Name="/cs-dev/soar/pb05_never_block", Value="8.8.8.8/32", Type="String"
    )
    assert lambda_handler(_edge_now(), None) == {
        "allowed": True,
        "dry_run": False,
        "reason": "address may be blocked",
    }
    assert lambda_handler(_edge_now("8.8.8.8"), None)["reason"] == (
        "address is on the never-block list"
    )


def test_handler_ip_when_pb05_is_off_refuses(world: Any) -> None:
    # No NEVER_BLOCK_PARAM / EDGE_EVENT_SOURCE in this environment.
    assert lambda_handler(_edge_now(), None)["reason"] == "IP blocking is not configured"


def test_guard_without_a_never_block_reader_refuses_ips() -> None:
    g = SafetyGuard(D_SETTINGS, FakeEcs(None), lambda: False, clock=lambda: NOW)
    assert g.evaluate(events.edge_ip()).reason == "never-block list unreadable"
