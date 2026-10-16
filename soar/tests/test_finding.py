"""Finding parsing for the Phase D targets: ECS tasks (PB-04) and edge IPs (PB-05)."""

from __future__ import annotations

from typing import Any

import pytest

from core.finding import (
    Ec2Target,
    EcsTaskTarget,
    Finding,
    IpAddressTarget,
    UnknownTarget,
    ip_refusal,
    parse_single_ip,
)
from tests import events


# ------------------------------------------------------------------ source
def test_source_is_carried() -> None:
    assert Finding.from_event(events.portscan("i-0123abcd")).source == "aws.guardduty"
    assert Finding.from_event(events.edge_ip()).source == "cloudshield.edge"


@pytest.mark.parametrize("source", [None, 5, ["cloudshield.edge"]])
def test_missing_or_odd_source_is_empty(source: Any) -> None:
    event = events.portscan("i-0123abcd")
    if source is None:
        del event["source"]
    else:
        event["source"] = source
    assert Finding.from_event(event).source == ""


# ---------------------------------------------------------------------- ECS
def test_ecs_task_target() -> None:
    assert Finding.from_event(events.ecs_runtime()).target == EcsTaskTarget(
        events.CLUSTER_ARN, events.TASK_ARN, events.SERVICE_NAME
    )


def test_ecs_task_without_service_group_has_no_service() -> None:
    for group in (None, "family:cs-dev-app", "service:", "service:a b", "service:x\n"):
        target = Finding.from_event(events.ecs_runtime(group=group)).target
        assert isinstance(target, EcsTaskTarget)
        assert target.service_name is None


@pytest.mark.parametrize(
    "task_arn",
    [
        # old short ARN format (no cluster), a UUID id, upper-case hex, a newline
        f"arn:aws:ecs:us-east-1:{events.ACCOUNT}:task/{events.TASK_ID}",
        f"arn:aws:ecs:us-east-1:{events.ACCOUNT}:task/cs-dev-cluster/c6e38bc2-d049-4ace-a7d8-b77bd0f5816e",
        f"arn:aws:ecs:us-east-1:{events.ACCOUNT}:task/cs-dev-cluster/{events.TASK_ID.upper()}",
        events.TASK_ARN + "\n",
        f"arn:aws:ecs:us-east-1:{events.ACCOUNT}:container-instance/cs-dev-cluster/{events.TASK_ID}",
        # task in another cluster than the finding's
        f"arn:aws:ecs:us-east-1:{events.ACCOUNT}:task/other-cluster/{events.TASK_ID}",
    ],
)
def test_bad_task_arn_is_unknown(task_arn: str) -> None:
    assert isinstance(Finding.from_event(events.ecs_runtime(task_arn)).target, UnknownTarget)


def test_ecs_finding_without_task_or_cluster_is_unknown() -> None:
    no_task = events.ecs_runtime()
    del no_task["detail"]["resource"]["ecsClusterDetails"]["taskDetails"]
    no_details = events.ecs_runtime()
    del no_details["detail"]["resource"]["ecsClusterDetails"]
    bad_cluster = events.ecs_runtime(cluster_arn="arn:aws:ecs:us-east-1:1:cluster/x")
    for event in (no_task, no_details, bad_cluster):
        assert isinstance(Finding.from_event(event).target, UnknownTarget)


# ----------------------------------------------------------------------- IP
@pytest.mark.parametrize(
    ("address", "field", "expected"),
    [
        ("1.1.1.1", "ipAddressV4", IpAddressTarget("1.1.1.1", 4)),
        ("2606:4700:4700::1111", "ipAddressV6", IpAddressTarget("2606:4700:4700::1111", 6)),
        # expanded IPv6 is canonicalised
        (
            "2606:4700:4700:0000:0000:0000:0000:1111",
            "ipAddressV6",
            IpAddressTarget("2606:4700:4700::1111", 6),
        ),
        # IPv4-mapped IPv6 -> IPv4, so the IPv4 rules and list apply
        ("::ffff:1.1.1.1", "ipAddressV6", IpAddressTarget("1.1.1.1", 4)),
    ],
)
def test_ip_targets(address: str, field: str, expected: IpAddressTarget) -> None:
    assert Finding.from_event(events.edge_ip(address, field=field)).target == expected


@pytest.mark.parametrize(
    ("address", "field"),
    [
        ("1.1.1.1/32", "ipAddressV4"),
        ("1.1.1.0/24", "ipAddressV4"),
        ("2606:4700::/32", "ipAddressV6"),
        (" 1.1.1.1", "ipAddressV4"),
        ("1.1.1.1\n", "ipAddressV4"),
        ("01.1.1.1", "ipAddressV4"),
        ("fe80::1%eth0", "ipAddressV6"),
        ("not-an-ip", "ipAddressV4"),
        ("", "ipAddressV4"),
        ("2606:4700:4700::1111", "ipAddressV4"),  # family mismatch
        ("1.1.1.1", "ipAddressV6"),  # family mismatch
        ("::ffff:1.1.1.1", "ipAddressV4"),  # mapped form only in the v6 field
    ],
)
def test_bad_ip_values_are_unknown(address: str, field: str) -> None:
    assert isinstance(
        Finding.from_event(events.edge_ip(address, field=field)).target, UnknownTarget
    )


def test_ip_value_must_be_a_string_and_exactly_one() -> None:
    for details in (
        {"ipAddressV4": 16843009},
        {"ipAddressV4": "1.1.1.1", "ipAddressV6": "2606:4700:4700::1111"},
        {},
    ):
        event = events.edge_ip()
        event["detail"]["resource"]["ipAddressDetails"] = details
        assert isinstance(Finding.from_event(event).target, UnknownTarget)
    event = events.edge_ip()
    event["detail"]["resource"]["ipAddressDetails"] = "1.1.1.1"
    assert isinstance(Finding.from_event(event).target, UnknownTarget)


def test_ip_target_needs_the_edge_source() -> None:
    # A GuardDuty-sourced (or any other) event naming an IP is unknown.
    for source in ("aws.guardduty", "cloudshield.edge2", ""):
        target = Finding.from_event(events.edge_ip(source=source)).target
        assert isinstance(target, UnknownTarget)


def test_edge_source_with_other_resource_is_unknown() -> None:
    # The edge bus can never reach PB-01..PB-04.
    event = events.portscan("i-0123abcd")
    event["source"] = "cloudshield.edge"
    assert isinstance(Finding.from_event(event).target, UnknownTarget)


def test_parse_single_ip_rejects_non_strings() -> None:
    assert parse_single_ip(None) is None
    assert parse_single_ip(16843009) is None
    assert parse_single_ip("1" * 46) is None


@pytest.mark.parametrize(
    ("address", "reason"),
    [
        ("10.0.0.1", "not globally routable"),
        ("127.0.0.1", "not globally routable"),
        ("169.254.169.254", "not globally routable"),
        ("100.64.0.1", "not globally routable"),
        ("192.0.2.10", "not globally routable"),
        ("198.51.100.10", "not globally routable"),
        ("203.0.113.10", "not globally routable"),
        ("2001:db8::1", "not globally routable"),
        ("fe80::1", "not globally routable"),
        ("0.0.0.0", "not globally routable"),  # noqa: S104 - an address under test, not a bind
        ("240.0.0.1", "not globally routable"),
        ("224.0.0.1", "multicast"),
        ("ff02::1", "multicast"),
    ],
)
def test_ip_refusal(address: str, reason: str) -> None:
    parsed = parse_single_ip(address)
    assert parsed is not None
    refusal = ip_refusal(parsed)
    assert refusal is not None
    assert reason in refusal


@pytest.mark.parametrize("address", ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"])
def test_global_unicast_is_blockable(address: str) -> None:
    parsed = parse_single_ip(address)
    assert parsed is not None
    assert ip_refusal(parsed) is None


@pytest.mark.parametrize(
    ("flags", "reason"),
    [
        ({"is_multicast": False, "is_unspecified": True, "is_reserved": False}, "unspecified"),
        ({"is_multicast": False, "is_unspecified": False, "is_reserved": True}, "reserved"),
    ],
)
def test_ip_refusal_checks_beyond_is_global(flags: dict[str, bool], reason: str) -> None:
    # Defence in depth: these hold even if a future Python marks such a range global.
    from types import SimpleNamespace

    fake: Any = SimpleNamespace(is_global=True, **flags)
    assert reason in (ip_refusal(fake) or "")


def test_exfiltration_type_needs_the_access_key_resource() -> None:
    # Audit A5: the router's PB01 choice needs type AND resourceType AccessKey,
    # so Finding resolves the session's instance only for that same pair.
    exfil = events.exfiltration("i-0123456789abcdef0")
    target = Finding.from_event(exfil).target
    assert target == Ec2Target("i-0123456789abcdef0", session_role_id="AROAEXAMPLEFAKEROLEID")
    exfil["detail"]["resource"] = {
        "resourceType": "Instance",
        "instanceDetails": {"instanceId": "i-0fedcba9876543210"},
    }
    assert Finding.from_event(exfil).target == Ec2Target("i-0fedcba9876543210")
    exfil["detail"]["resource"] = {"resourceType": "S3Bucket", "s3BucketDetails": []}
    assert isinstance(Finding.from_event(exfil).target, UnknownTarget)
