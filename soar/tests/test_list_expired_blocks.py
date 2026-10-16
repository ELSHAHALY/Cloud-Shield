"""tools/list_expired_blocks.py: groups by address, finds expired / lost / orphan
blocks, and never changes anything (audit A3)."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import boto3
import pytest

from core.finding import iso
from tests.conftest import INCIDENTS_TABLE, NOW
from tests.test_pb05 import make_ip_sets, put
from tools.list_expired_blocks import live_entries, main, removal_commands, still_blocked


class Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def __call__(self, service: str, **kw: Any) -> Any:
        real = boto3.client(service, **kw)
        outer = self

        class Proxy:
            def __getattr__(self, name: str) -> Any:
                attr = getattr(real, name)
                if not callable(attr):
                    return attr

                def wrapped(*a: Any, **k: Any) -> Any:
                    outer.calls.append((service, name))
                    return attr(*a, **k)

                return wrapped

        return Proxy()


@pytest.fixture
def blocks(world: Any) -> dict[str, Any]:
    sets = make_ip_sets()
    # 1.1.1.1 expired, still blocked; 9.9.9.9 has an older expired row AND a
    # newer unexpired one (latest wins: not expired); 7.7.7.7 is in the set
    # with no row (orphan); 4.4.4.4 is unexpired but gone (lost).
    put(sets["v4"], ["1.1.1.1/32", "9.9.9.9/32", "7.7.7.7/32"])
    v4 = sets["v4"]["ARN"]

    def row(incident: str, **fields: Any) -> None:
        extra = {k: {"S": v} for k, v in fields.items()}
        world.seed_incident(incident, **extra)

    row(
        "old-still",
        blockedCidr="1.1.1.1/32",
        ipSetArn=v4,
        blockExpiresAt=iso(NOW - timedelta(hours=2)),
    )
    row(
        "old-removed",
        blockedCidr="8.8.8.8/32",
        ipSetArn=v4,
        blockExpiresAt=iso(NOW - timedelta(hours=30)),
        blockLiftedAt=iso(NOW - timedelta(hours=29)),
    )
    row(
        "nine-old",
        blockedCidr="9.9.9.9/32",
        ipSetArn=v4,
        blockExpiresAt=iso(NOW - timedelta(hours=5)),
    )
    row(
        "nine-new",
        blockedCidr="9.9.9.9/32",
        ipSetArn=v4,
        blockExpiresAt=iso(NOW + timedelta(hours=1)),
    )
    row("lost", blockedCidr="4.4.4.4/32", ipSetArn=v4, blockExpiresAt=iso(NOW + timedelta(hours=3)))
    row("garbled", blockedCidr="5.5.5.5/32", ipSetArn=v4, blockExpiresAt="soon")
    row("bad-cidr", blockedCidr="not-a-cidr", ipSetArn=v4, blockExpiresAt=iso(NOW))
    row("not-a-block")
    return sets


def run(capsys: Any, *args: str) -> tuple[int, str, Recorder]:
    recorder = Recorder()
    code = main(["--table", INCIDENTS_TABLE, *args], clients=recorder, now=NOW)
    return code, capsys.readouterr().out, recorder


def test_groups_by_address_and_reports_expired_lost_and_orphans(
    blocks: dict[str, Any], capsys: Any
) -> None:
    code, out, _ = run(capsys, "--format", "json")
    result = json.loads(out)
    assert code == 0
    expired = {g["cidr"]: g for g in result["expired"]}
    # 9.9.9.9 is covered by its newer unexpired row: NOT expired.
    assert sorted(expired) == ["1.1.1.1/32", "8.8.8.8/32"]
    assert expired["1.1.1.1/32"]["stillBlocked"] is True
    assert expired["1.1.1.1/32"]["overdueSeconds"] == 7200
    assert any("update-ip-set" in c for c in expired["1.1.1.1/32"]["removal"])
    assert expired["8.8.8.8/32"]["stillBlocked"] is False
    assert "removal" not in expired["8.8.8.8/32"]
    assert [g["cidr"] for g in result["lost"]] == ["4.4.4.4/32"]
    assert result["lost"][0]["incidents"] == ["lost"]
    assert [o["entry"] for o in result["orphans"]] == ["7.7.7.7/32"]


def test_extra_ip_sets_are_checked_for_orphans(blocks: dict[str, Any], capsys: Any) -> None:
    put(blocks["v6"], ["2606:4700:4700::1111/128"])
    _, out, _ = run(capsys, "--format", "json", "--ip-set-arn", blocks["v6"]["ARN"])
    orphans = {o["entry"] for o in json.loads(out)["orphans"]}
    assert orphans == {"7.7.7.7/32", "2606:4700:4700::1111/128"}


def test_is_read_only(blocks: dict[str, Any], capsys: Any) -> None:
    _, out, recorder = run(capsys)
    assert "STILL BLOCKED" in out
    assert "lifted" in out
    assert "lost (missing before expiry) (1)" in out
    assert "orphans (in the IP set, no incident row) (1)" in out
    assert "aws wafv2 update-ip-set --scope CLOUDFRONT" in out
    mutating = [
        c for c in recorder.calls if not c[1].startswith(("get_", "scan", "describe_", "list_"))
    ]
    assert mutating == []
    assert ("wafv2", "update_ip_set") not in recorder.calls


def test_empty_table(world: Any, capsys: Any) -> None:
    code, out, _ = run(capsys)
    assert code == 0
    assert "expired (0)" in out
    assert "orphans (in the IP set, no incident row) (0)" in out


def test_unreadable_ip_set_is_unknown(world: Any, capsys: Any) -> None:
    wafv2 = boto3.client("wafv2")
    assert still_blocked(wafv2, None, "1.1.1.1/32") is None
    assert still_blocked(wafv2, "not-an-arn", "1.1.1.1/32") is None
    missing = (
        "arn:aws:wafv2:us-east-1:123456789012:global/ipset/x/fb299380-1882-4b3f-8835-dd4566c47346"
    )
    assert still_blocked(wafv2, missing, "1.1.1.1/32") is None
    assert live_entries(wafv2, missing) is None
    # A row naming an unreadable set: stillBlocked unknown, never an orphan.
    world.seed_incident(
        "gone-set",
        blockedCidr={"S": "1.1.1.1/32"},
        ipSetArn={"S": missing},
        blockExpiresAt={"S": iso(NOW - timedelta(hours=1))},
    )
    _, out, _ = run(capsys, "--format", "json")
    result = json.loads(out)
    assert result["expired"][0]["stillBlocked"] is None
    assert result["orphans"] == []


def test_still_blocked_reads_the_live_set(blocks: dict[str, Any]) -> None:
    wafv2 = boto3.client("wafv2")
    arn = blocks["v4"]["ARN"]
    assert still_blocked(wafv2, arn, "1.1.1.1/32") is True
    assert still_blocked(wafv2, arn, "8.8.8.8/32") is False


def test_removal_commands_name_the_set() -> None:
    arn = (
        "arn:aws:wafv2:us-east-1:123456789012:global/ipset/cs-dev-soar-blocked-ips-v4/"
        "fb299380-1882-4b3f-8835-dd4566c47346"
    )
    commands = removal_commands(arn, "1.1.1.1/32", "us-east-1")
    assert commands[0].startswith(
        "aws wafv2 get-ip-set --scope CLOUDFRONT --name cs-dev-soar-blocked-ips-v4"
    )
    assert "except 1.1.1.1/32" in commands[1]
