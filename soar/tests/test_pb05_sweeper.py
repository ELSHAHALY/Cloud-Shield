"""PB-05 auto-expiry sweeper (audit A2): lifts only row-tracked, expired,
uncovered blocks; remove-only; read-back before anything is recorded."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError

from core.config import ConfigError
from core.finding import iso
from playbooks import pb05_unblock_sweeper as sweeper_module
from playbooks.pb05_unblock_sweeper import Sweeper, SweepError, SweeperSettings, lambda_handler
from tests.conftest import INCIDENTS_TABLE, NOW
from tests.test_pb05 import addresses, make_ip_sets, put


class Waf:
    """Wraps the moto WAFv2 client: logs calls, can interfere or hide reads."""

    def __init__(self, *, interfere: int = 0, hide_removal: bool = False) -> None:
        self.real = boto3.client("wafv2")
        self.calls: list[str] = []
        self.interfere = interfere
        self.hide_removal = hide_removal
        self.updated_with: list[list[str]] = []

    def get_ip_set(self, **k: Any) -> Any:
        self.calls.append("get_ip_set")
        response = self.real.get_ip_set(**k)
        if self.hide_removal and self.updated_with:
            response["IPSet"]["Addresses"] = [*response["IPSet"]["Addresses"], "1.1.1.1/32"]
        return response

    def update_ip_set(self, **k: Any) -> Any:
        self.calls.append("update_ip_set")
        if self.interfere:
            self.interfere -= 1
            other = self.real.get_ip_set(Name=k["Name"], Scope=k["Scope"], Id=k["Id"])
            self.real.update_ip_set(
                Name=k["Name"],
                Scope=k["Scope"],
                Id=k["Id"],
                Addresses=[*other["IPSet"]["Addresses"], f"9.9.8.{self.interfere + 1}/32"],
                LockToken=other["LockToken"],
            )
        self.updated_with.append(list(k["Addresses"]))
        return self.real.update_ip_set(**k)


@pytest.fixture
def sets(world: Any) -> dict[str, dict[str, str]]:
    return make_ip_sets()


def settings(sets: dict[str, dict[str, str]]) -> SweeperSettings:
    return SweeperSettings.from_env(
        {
            "INCIDENTS_TABLE": INCIDENTS_TABLE,
            "BLOCK_IP_SET_ARNS": f"{sets['v4']['ARN']},{sets['v6']['ARN']}",
            "WAF_REGION": "us-east-1",
        }
    )


def tracked(world: Any, incident: str, cidr: str, arn: str, expires: Any, **extra: str) -> None:
    fields = {"blockedCidr": cidr, "ipSetArn": arn, "blockState": "active", **extra}
    fields["blockExpiresAt"] = expires if isinstance(expires, str) else iso(NOW + expires)
    world.seed_incident(incident, **{k: {"S": v} for k, v in fields.items()})


def sweep(sets: dict[str, dict[str, str]], waf: Waf | None = None) -> dict[str, Any]:
    return Sweeper(
        settings(sets),
        waf or Waf(),
        boto3.client("dynamodb"),
        clock=lambda: NOW,
        sleep=lambda _: None,
    ).sweep()


def test_lifts_only_expired_tracked_uncovered_blocks(world: Any, sets: Any) -> None:
    v4, v6 = sets["v4"]["ARN"], sets["v6"]["ARN"]
    put(sets["v4"], ["1.1.1.1/32", "8.8.8.8/32", "9.9.9.9/32", "7.7.7.7/32", "5.5.5.5/32"])
    put(sets["v6"], ["2606:4700:4700:0:0:0:0:1111/128"])
    tracked(world, "expired", "1.1.1.1/32", v4, -timedelta(minutes=1))
    tracked(world, "fresh", "8.8.8.8/32", v4, timedelta(hours=3))
    # 9.9.9.9: an old expired row, but a newer unexpired row covers it.
    tracked(world, "nine-old", "9.9.9.9/32", v4, -timedelta(hours=20))
    tracked(world, "nine-new", "9.9.9.9/32", v4, timedelta(hours=4))
    # 5.5.5.5: unparseable expiry -> kept (fail closed).
    tracked(world, "garbled", "5.5.5.5/32", v4, "soon")
    tracked(world, "v6-expired", "2606:4700:4700::1111/128", v6, -timedelta(hours=1))
    # 7.7.7.7 has no row: an orphan, never removed.

    waf = Waf()
    report = sweep(sets, waf)

    assert sorted(addresses(sets["v4"])) == ["5.5.5.5/32", "7.7.7.7/32", "8.8.8.8/32", "9.9.9.9/32"]
    assert addresses(sets["v6"]) == []
    assert sorted(r["cidr"] for r in report["lifted"]) == [
        "1.1.1.1/32",
        "2606:4700:4700::1111/128",
    ]
    assert report["orphans"] == [{"ipSetArn": v4, "entry": "7.7.7.7/32"}]
    assert report["kept"] == 3
    assert report["errors"] == []
    row = world.incident("expired")
    assert row["blockLiftedAt"] == iso(NOW)
    assert row["blockState"] == "lifted"
    assert row["actions"][-1]["step"] == "unblock"
    assert row["actions"][-1]["playbook"] == "pb05-unblock-sweeper"
    assert "blockLiftedAt" not in world.incident("nine-old")
    assert "blockLiftedAt" not in world.incident("fresh")
    # Remove-only: every update is a subset of what it replaced.
    assert all("7.7.7.7/32" in update for update in waf.updated_with[:1])


def test_nothing_expired_makes_no_update(world: Any, sets: Any) -> None:
    put(sets["v4"], ["1.1.1.1/32"])
    tracked(world, "fresh", "1.1.1.1/32", sets["v4"]["ARN"], timedelta(hours=1))
    waf = Waf()
    report = sweep(sets, waf)
    assert "update_ip_set" not in waf.calls
    assert report["lifted"] == []


def test_already_lifted_rows_are_not_rewritten(world: Any, sets: Any) -> None:
    v4 = sets["v4"]["ARN"]
    tracked(world, "done", "1.1.1.1/32", v4, -timedelta(hours=1), blockLiftedAt="earlier")
    waf = Waf()
    report = sweep(sets, waf)
    assert "update_ip_set" not in waf.calls
    assert report["lifted"] == []
    assert world.incident("done")["blockLiftedAt"] == "earlier"


def test_lock_exception_is_retried_and_concurrent_entries_survive(world: Any, sets: Any) -> None:
    put(sets["v4"], ["1.1.1.1/32", "7.7.7.7/32"])
    tracked(world, "expired", "1.1.1.1/32", sets["v4"]["ARN"], -timedelta(minutes=5))
    waf = Waf(interfere=2)
    report = sweep(sets, waf)
    assert waf.calls.count("update_ip_set") == 3
    assert sorted(addresses(sets["v4"])) == ["7.7.7.7/32", "9.9.8.1/32", "9.9.8.2/32"]
    assert [r["cidr"] for r in report["lifted"]] == ["1.1.1.1/32"]


def test_lock_exception_three_times_records_nothing(world: Any, sets: Any) -> None:
    put(sets["v4"], ["1.1.1.1/32"])
    tracked(world, "expired", "1.1.1.1/32", sets["v4"]["ARN"], -timedelta(minutes=5))
    with pytest.raises(SweepError, match="could not be swept"):
        sweep(sets, Waf(interfere=3))
    assert "blockLiftedAt" not in world.incident("expired")
    assert "1.1.1.1/32" in addresses(sets["v4"])


def test_read_back_is_required(world: Any, sets: Any) -> None:
    put(sets["v4"], ["1.1.1.1/32"])
    tracked(world, "expired", "1.1.1.1/32", sets["v4"]["ARN"], -timedelta(minutes=5))
    waf = Waf(hide_removal=True)
    with pytest.raises(SweepError):
        sweep(sets, waf)
    assert "blockLiftedAt" not in world.incident("expired")
    # 3 read-back attempts after the update (then the IPv6 set's own read).
    after = waf.calls[waf.calls.index("update_ip_set") :]
    assert after[:4] == ["update_ip_set", "get_ip_set", "get_ip_set", "get_ip_set"]
    assert len(after) == 5


def test_remove_only_assertion(world: Any, sets: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    put(sets["v4"], ["1.1.1.1/32", "7.7.7.7/32"])
    tracked(world, "expired", "1.1.1.1/32", sets["v4"]["ARN"], -timedelta(minutes=5))
    # A (buggy) filter that also drops an orphan must never reach UpdateIPSet.
    monkeypatch.setattr(sweeper_module, "_without", lambda addresses, expired: [])
    waf = Waf()
    with pytest.raises(SweepError):
        sweep(sets, waf)
    assert "update_ip_set" not in waf.calls
    assert sorted(addresses(sets["v4"])) == ["1.1.1.1/32", "7.7.7.7/32"]


def test_other_errors_are_reported_per_set(world: Any, sets: Any) -> None:
    class Denied(Waf):
        def update_ip_set(self, **k: Any) -> Any:
            raise ClientError({"Error": {"Code": "AccessDeniedException"}}, "UpdateIPSet")

    put(sets["v4"], ["1.1.1.1/32"])
    put(sets["v6"], ["2606:4700:4700::1111/128"])
    tracked(world, "v4", "1.1.1.1/32", sets["v4"]["ARN"], -timedelta(minutes=5))
    with pytest.raises(SweepError, match="1 IP set"):
        sweep(sets, Denied())


def test_settings_require_everything() -> None:
    with pytest.raises(ConfigError):
        SweeperSettings.from_env({"INCIDENTS_TABLE": "t", "WAF_REGION": "us-east-1"})
    with pytest.raises(ConfigError):
        SweeperSettings.from_env({"BLOCK_IP_SET_ARNS": "a,b", "WAF_REGION": "us-east-1"})


def test_lambda_handler_entry_point(world: Any, sets: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    put(sets["v4"], ["1.1.1.1/32"])
    tracked(world, "expired", "1.1.1.1/32", sets["v4"]["ARN"], -timedelta(days=400))
    monkeypatch.setenv("BLOCK_IP_SET_ARNS", f"{sets['v4']['ARN']},{sets['v6']['ARN']}")
    monkeypatch.setenv("WAF_REGION", "us-east-1")
    report = lambda_handler({}, None)
    assert [r["cidr"] for r in report["lifted"]] == ["1.1.1.1/32"]
    assert addresses(sets["v4"]) == []
