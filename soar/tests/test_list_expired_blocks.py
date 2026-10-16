"""tools/list_expired_blocks.py: lists only overdue PB-05 blocks, never changes anything."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import boto3
import pytest

from core.finding import iso
from tests.conftest import INCIDENTS_TABLE, NOW
from tests.test_pb05 import make_ip_sets, put
from tools.list_expired_blocks import main, removal_commands, still_blocked


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
    put(sets["v4"], ["1.1.1.1/32", "9.9.9.9/32"])
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
    )
    row(
        "fresh", blockedCidr="9.9.9.9/32", ipSetArn=v4, blockExpiresAt=iso(NOW + timedelta(hours=1))
    )
    row("garbled", blockedCidr="9.9.9.9/32", ipSetArn=v4, blockExpiresAt="soon")
    row("not-a-block")
    return sets


def run(capsys: Any, *args: str) -> tuple[int, str, Recorder]:
    recorder = Recorder()
    code = main(["--table", INCIDENTS_TABLE, *args], clients=recorder, now=NOW)
    return code, capsys.readouterr().out, recorder


def test_lists_only_overdue_rows(blocks: dict[str, Any], capsys: Any) -> None:
    code, out, _ = run(capsys, "--format", "json")
    rows = json.loads(out)
    assert code == 0
    assert [r["incidentId"] for r in rows] == ["old-removed", "old-still"]
    by_id = {r["incidentId"]: r for r in rows}
    assert by_id["old-still"]["stillBlocked"] is True
    assert by_id["old-still"]["overdueSeconds"] == 7200
    assert by_id["old-removed"]["stillBlocked"] is False
    assert "removal" not in by_id["old-removed"]
    assert any("update-ip-set" in c for c in by_id["old-still"]["removal"])


def test_is_read_only(blocks: dict[str, Any], capsys: Any) -> None:
    _, out, recorder = run(capsys)
    assert "STILL BLOCKED" in out
    assert "already removed" in out
    assert "aws wafv2 update-ip-set --scope CLOUDFRONT" in out
    mutating = [
        c for c in recorder.calls if not c[1].startswith(("get_", "scan", "describe_", "list_"))
    ]
    assert mutating == []
    assert ("wafv2", "update_ip_set") not in recorder.calls


def test_empty_table(world: Any, capsys: Any) -> None:
    code, out, _ = run(capsys)
    assert code == 0
    assert out.startswith("No PB-05 blocks past their expiry")


def test_unreadable_ip_set_is_unknown(world: Any) -> None:
    wafv2 = boto3.client("wafv2")
    assert still_blocked(wafv2, None, "1.1.1.1/32") is None
    assert still_blocked(wafv2, "not-an-arn", "1.1.1.1/32") is None
    missing = (
        "arn:aws:wafv2:us-east-1:123456789012:global/ipset/x/fb299380-1882-4b3f-8835-dd4566c47346"
    )
    assert still_blocked(wafv2, missing, "1.1.1.1/32") is None


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
