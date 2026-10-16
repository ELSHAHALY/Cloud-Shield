"""PB-05: WAF IP block (scenario E) and the rate-rule harvester.

The IP sets are moto WAFv2, which implements GetIPSet / UpdateIPSet with real
LockToken semantics (a stale token raises WAFOptimisticLockException).
moto does not implement GetRateBasedStatementManagedKeys, and its EventBridge
extra would add a package: PB-05's corroboration call is answered by the `Waf`
proxy below, and the harvester runs against botocore Stubbers. The harvester's
persistence table is moto DynamoDB.

Blockable addresses are well-known public anycast resolvers, used only inside
the mocks; documentation ranges appear only as refusals.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import boto3
import pytest
from botocore.stub import ANY, Stubber

from core.config import ConfigError, Settings
from core.finding import iso
from core.playbook import PlaybookError
from playbooks import pb05_waf_ip_block as pb05
from playbooks.pb05_waf_ip_block import (
    MAX_EVENTS,
    MAX_OBSERVED,
    HarvestError,
    HarvestSettings,
    IpSetRef,
    Pb05WafIpBlock,
    SightingStore,
    harvest,
    harvest_handler,
    lambda_handler,
)
from tests import events
from tests.conftest import NOW

SCOPE = "CLOUDFRONT"
NEVER_BLOCK_PARAM = "/cs-dev/soar/pb05_never_block"
ACL_NAME, ACL_ID = "cs-dev-cloudfront", "11111111-2222-3333-4444-555555555555"
RATE_RULE = "SoarApiRateLimit"
# What WAF reports as rate-limited unless a test says otherwise.
MANAGED = ("1.1.1.1/32", "8.8.8.8/32", "2606:4700:4700::1111/128")


# ------------------------------------------------------------------ world
def make_ip_sets() -> dict[str, dict[str, str]]:
    wafv2 = boto3.client("wafv2")
    sets = {}
    for family, version in (("v4", "IPV4"), ("v6", "IPV6")):
        summary = wafv2.create_ip_set(
            Name=f"cs-dev-soar-blocked-ips-{family}",
            Scope=SCOPE,
            IPAddressVersion=version,
            Addresses=[],
        )["Summary"]
        sets[family] = {"Name": summary["Name"], "Id": summary["Id"], "ARN": summary["ARN"]}
    return sets


def set_never_block(value: str = "198.51.100.10/32") -> None:
    boto3.client("ssm").put_parameter(
        Name=NEVER_BLOCK_PARAM, Value=value, Type="String", Overwrite=True
    )


@pytest.fixture
def ip_sets(world: Any) -> dict[str, dict[str, str]]:
    set_never_block()
    return make_ip_sets()


def addresses(ip_set: dict[str, str]) -> list[str]:
    return boto3.client("wafv2").get_ip_set(Name=ip_set["Name"], Scope=SCOPE, Id=ip_set["Id"])[
        "IPSet"
    ]["Addresses"]


def put(ip_set: dict[str, str], new: list[str]) -> None:
    wafv2 = boto3.client("wafv2")
    token = wafv2.get_ip_set(Name=ip_set["Name"], Scope=SCOPE, Id=ip_set["Id"])["LockToken"]
    wafv2.update_ip_set(
        Name=ip_set["Name"], Scope=SCOPE, Id=ip_set["Id"], Addresses=new, LockToken=token
    )


PB05_ENV = {
    "WAF_REGION": "us-east-1",
    "EDGE_EVENT_SOURCE": "cloudshield.edge",
    "NEVER_BLOCK_PARAM": NEVER_BLOCK_PARAM,
    "WAF_WEB_ACL_NAME": ACL_NAME,
    "WAF_WEB_ACL_ID": ACL_ID,
    "WAF_RATE_RULE_NAME": RATE_RULE,
}


def settings(world: Any, sets: dict[str, dict[str, str]], **extra: str) -> Settings:
    return Settings.from_env(
        {
            **world.env,
            "BLOCK_IP_SET_ARNS": f"{sets['v4']['ARN']},{sets['v6']['ARN']}",
            **PB05_ENV,
            **extra,
        }
    )


def pb05_for(
    world: Any, sets: dict[str, dict[str, str]], clients: Any = None, **extra: str
) -> Pb05WafIpBlock:
    return Pb05WafIpBlock(
        settings(world, sets, **extra), clients or Waf(), lambda: NOW, sleep=lambda _: None
    )


def seed(world: Any, event: dict[str, Any]) -> dict[str, Any]:
    world.seed_incident(event["detail"]["id"])
    return event


class Waf:
    """A client factory whose WAFv2 client misbehaves on purpose, and answers
    GetRateBasedStatementManagedKeys (which moto lacks) from `managed`."""

    def __init__(
        self,
        *,
        interfere: int = 0,
        hide_reads_after_update: bool = False,
        managed: tuple[str, ...] = MANAGED,
        on_update: Any = None,
    ) -> None:
        self.interfere = interfere  # concurrent writers before our next N updates
        self.hide = hide_reads_after_update
        self.managed = managed
        self.on_update = on_update
        self.calls: list[str] = []
        self.key_requests: list[dict[str, Any]] = []

    def __call__(self, service: str, **kw: Any) -> Any:
        real = boto3.client(service, **kw)
        if service != "wafv2":
            return real
        outer = self

        class Proxy:
            def __getattr__(self, name: str) -> Any:
                if name == "get_rate_based_statement_managed_keys":

                    def keys(**k: Any) -> Any:
                        outer.calls.append(name)
                        outer.key_requests.append(k)
                        v4 = [a for a in outer.managed if ":" not in a]
                        v6 = [a for a in outer.managed if ":" in a]
                        return {
                            "ManagedKeysIPV4": {"IPAddressVersion": "IPV4", "Addresses": v4},
                            "ManagedKeysIPV6": {"IPAddressVersion": "IPV6", "Addresses": v6},
                        }

                    return keys
                attr = getattr(real, name)

                def wrapped(**k: Any) -> Any:
                    outer.calls.append(name)
                    if name == "update_ip_set" and outer.on_update is not None:
                        outer.on_update()
                    if name == "update_ip_set" and outer.interfere:
                        outer.interfere -= 1
                        # Someone else adds an entry first: our token is stale.
                        other = real.get_ip_set(Name=k["Name"], Scope=k["Scope"], Id=k["Id"])
                        real.update_ip_set(
                            Name=k["Name"],
                            Scope=k["Scope"],
                            Id=k["Id"],
                            Addresses=[
                                *other["IPSet"]["Addresses"],
                                f"9.9.9.{outer.interfere + 1}/32",
                            ],
                            LockToken=other["LockToken"],
                        )
                    response = attr(**k)
                    if name == "get_ip_set" and outer.hide and "update_ip_set" in outer.calls:
                        response["IPSet"]["Addresses"] = []
                    return response

                return wrapped

        return Proxy()


# ------------------------------------------------------------------ block
@pytest.mark.parametrize(
    ("address", "field", "family", "cidr"),
    [
        ("1.1.1.1", None, "v4", "1.1.1.1/32"),
        ("2606:4700:4700::1111", None, "v6", "2606:4700:4700::1111/128"),
        ("::ffff:8.8.8.8", "ipAddressV6", "v4", "8.8.8.8/32"),  # mapped -> IPv4 set
    ],
)
def test_block_appends_and_verifies(
    world: Any,
    ip_sets: dict[str, dict[str, str]],
    address: str,
    field: str | None,
    family: str,
    cidr: str,
) -> None:
    put(ip_sets[family], ["9.9.9.9/32"] if family == "v4" else ["2620:fe::fe/128"])
    event = seed(world, events.edge_ip(address, field=field))

    result = pb05_for(world, ip_sets).handle(events.payload("block", event))

    assert result["contained"] is True
    assert result["verified"] == {"cidrInIpSet": True}
    assert result["cidr"] == cidr
    assert result["result"] == "added"
    after = addresses(ip_sets[family])
    assert cidr in after
    assert len(after) == 2  # add-only: the earlier entry survives
    row = world.incident(event["detail"]["id"])
    assert row["blockedCidr"] == cidr
    assert row["ipSetArn"] == ip_sets[family]["ARN"]
    assert row["blockExpiresAt"] == iso(NOW + timedelta(hours=24))
    assert row["containmentVerified"] is True
    assert row["blockState"] == "active"
    assert row["actions"][0]["step"] == "block-ip"
    assert row["actions"][0]["entriesBefore"] == 1
    assert row["actions"][0]["corroboratedBy"] == RATE_RULE


def test_block_ttl_is_configurable(world: Any, ip_sets: dict[str, dict[str, str]]) -> None:
    event = seed(world, events.edge_ip())
    result = pb05_for(world, ip_sets, BLOCK_TTL_HOURS="6").handle(events.payload("block", event))
    assert result["blockExpiresAt"] == iso(NOW + timedelta(hours=6))
    assert world.incident(event["detail"]["id"])["blockExpiresAt"] == "2026-10-14T16:00:07.000Z"


@pytest.mark.parametrize(
    "existing", ["2606:4700:4700::1111/128", "2606:4700:4700:0:0:0:0:1111/128"]
)
def test_already_present_is_idempotent(
    world: Any, ip_sets: dict[str, dict[str, str]], existing: str
) -> None:
    put(ip_sets["v6"], [existing])
    event = seed(world, events.edge_ip("2606:4700:4700::1111"))
    waf = Waf()

    result = pb05_for(world, ip_sets, waf).handle(events.payload("block", event))

    assert result["contained"] is True
    assert result["result"] == "already-present"
    assert "update_ip_set" not in waf.calls


def test_lock_exception_twice_then_success(world: Any, ip_sets: dict[str, dict[str, str]]) -> None:
    event = seed(world, events.edge_ip())
    waf = Waf(interfere=2)

    result = pb05_for(world, ip_sets, waf).handle(events.payload("block", event))

    assert result["contained"] is True
    assert waf.calls.count("update_ip_set") == 3
    # The concurrent writers' entries survive ours (add-only on the LATEST list).
    assert sorted(addresses(ip_sets["v4"])) == ["1.1.1.1/32", "9.9.9.1/32", "9.9.9.2/32"]


def test_lock_exception_three_times_raises(world: Any, ip_sets: dict[str, dict[str, str]]) -> None:
    event = seed(world, events.edge_ip())
    waf = Waf(interfere=3)
    with pytest.raises(PlaybookError, match="gave up after 3 attempts"):
        pb05_for(world, ip_sets, waf).handle(events.payload("block", event))
    assert waf.calls.count("update_ip_set") == 3
    assert "1.1.1.1/32" not in addresses(ip_sets["v4"])
    # Tracked BEFORE the first UpdateIPSet (audit A3): the row says what was
    # attempted, so a later sweep or audit never meets an untracked block.
    row = world.incident(event["detail"]["id"])
    assert row["blockState"] == "pending"
    assert row["blockedCidr"] == "1.1.1.1/32"
    assert row["blockExpiresAt"] == iso(NOW + timedelta(hours=24))


def test_block_is_tracked_before_update_ip_set(
    world: Any, ip_sets: dict[str, dict[str, str]]
) -> None:
    event = seed(world, events.edge_ip())
    seen: list[dict[str, Any]] = []
    waf = Waf(on_update=lambda: seen.append(world.incident(event["detail"]["id"])))

    pb05_for(world, ip_sets, waf).handle(events.payload("block", event))

    assert seen[0]["blockState"] == "pending"
    assert seen[0]["blockedCidr"] == "1.1.1.1/32"
    assert seen[0]["ipSetArn"] == ip_sets["v4"]["ARN"]
    assert world.incident(event["detail"]["id"])["blockState"] == "active"


def test_other_update_errors_propagate(world: Any, ip_sets: dict[str, dict[str, str]]) -> None:
    from botocore.exceptions import ClientError

    def denied() -> None:
        raise ClientError({"Error": {"Code": "AccessDeniedException"}}, "UpdateIPSet")

    event = seed(world, events.edge_ip())
    with pytest.raises(ClientError):
        pb05_for(world, ip_sets, Waf(on_update=denied)).handle(events.payload("block", event))
    assert world.incident(event["detail"]["id"])["blockState"] == "pending"


def test_cap_reached_raises(world: Any, ip_sets: dict[str, dict[str, str]]) -> None:
    put(ip_sets["v4"], ["9.9.9.9/32", "9.9.9.10/32"])
    event = seed(world, events.edge_ip())
    waf = Waf()
    with pytest.raises(PlaybookError, match="cap 2"):
        pb05_for(world, ip_sets, waf, BLOCK_IP_SET_MAX="2").handle(events.payload("block", event))
    assert "update_ip_set" not in waf.calls
    assert "blockedCidr" not in world.incident(event["detail"]["id"])


def test_add_only_assertion(
    world: Any, ip_sets: dict[str, dict[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    put(ip_sets["v4"], ["9.9.9.9/32", "9.9.9.10/32"])
    # A (buggy) merge that drops an entry must never reach UpdateIPSet.
    monkeypatch.setattr(pb05, "_append", lambda old, cidr: [old[0], cidr])
    event = seed(world, events.edge_ip())
    waf = Waf()
    with pytest.raises(PlaybookError, match="not add-only"):
        pb05_for(world, ip_sets, waf).handle(events.payload("block", event))
    assert "update_ip_set" not in waf.calls
    assert sorted(addresses(ip_sets["v4"])) == ["9.9.9.10/32", "9.9.9.9/32"]


def test_read_back_is_required(world: Any, ip_sets: dict[str, dict[str, str]]) -> None:
    event = seed(world, events.edge_ip())
    waf = Waf(hide_reads_after_update=True)

    result = pb05_for(world, ip_sets, waf).handle(events.payload("block", event))

    assert result["contained"] is False
    assert result["verified"] == {"cidrInIpSet": False}
    # 3 read-back attempts after the update.
    assert waf.calls[waf.calls.index("update_ip_set") :].count("get_ip_set") == 3
    assert world.incident(event["detail"]["id"])["containmentVerified"] is False


# --------------------------------------------------------------- refusals
def test_non_global_address_is_refused_in_code(
    world: Any, ip_sets: dict[str, dict[str, str]]
) -> None:
    # Defence in depth: even if the guard were bypassed, never a private or
    # documentation address.
    waf = Waf()
    for address in ("10.0.0.1", "203.0.113.9"):
        with pytest.raises(PlaybookError, match="refusing to block"):
            pb05_for(world, ip_sets, waf).handle(events.payload("block", events.edge_ip(address)))
    assert waf.calls == []


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ({"BLOCK_IP_SET_ARNS": ""}, "not configured"),
        ({"WAF_REGION": ""}, "not configured"),
        ({"NEVER_BLOCK_PARAM": ""}, "not configured"),
        ({"EDGE_EVENT_SOURCE": ""}, "not configured"),
        ({"WAF_WEB_ACL_NAME": ""}, "not configured"),
        ({"WAF_WEB_ACL_ID": ""}, "not configured"),
        ({"WAF_RATE_RULE_NAME": ""}, "not configured"),
        ({"BLOCK_IP_SET_ARNS": "arn:aws:wafv2:us-east-1:123456789012:global/webacl/x/y"}, "ARN"),
    ],
)
def test_misconfiguration_refuses(
    world: Any, ip_sets: dict[str, dict[str, str]], extra: dict[str, str], message: str
) -> None:
    with pytest.raises(PlaybookError, match=message):
        pb05_for(world, ip_sets, **extra).handle(events.payload("block", events.edge_ip()))


def test_no_ip_set_for_the_family_refuses(world: Any, ip_sets: dict[str, dict[str, str]]) -> None:
    only_v4 = ip_sets["v4"]["ARN"]
    with pytest.raises(PlaybookError, match="no configured PB-05 IP set for IPV6"):
        pb05_for(world, ip_sets, BLOCK_IP_SET_ARNS=only_v4).handle(
            events.payload("block", events.edge_ip("2606:4700:4700::1111"))
        )


def test_non_ip_target_is_refused(world: Any, ip_sets: dict[str, dict[str, str]]) -> None:
    with pytest.raises(PlaybookError, match="needs an IP address target"):
        pb05_for(world, ip_sets).handle(events.payload("block", events.portscan("i-0123abcd")))
    # A wrong source never resolves to an IP target either.
    with pytest.raises(PlaybookError, match="needs an IP address target"):
        pb05_for(world, ip_sets).handle(
            events.payload("block", events.edge_ip(source="aws.guardduty"))
        )


def test_ip_set_ref_parsing() -> None:
    regional = IpSetRef.parse(
        "arn:aws:wafv2:us-east-1:123456789012:regional/ipset/x/fb299380-1882-4b3f-8835-dd4566c47346"
    )
    assert regional.scope == "REGIONAL"
    assert regional.key() == {
        "Name": "x",
        "Scope": "REGIONAL",
        "Id": "fb299380-1882-4b3f-8835-dd4566c47346",
    }


# ------------------------------------------- corroboration (audit A1)
def test_refuses_an_address_waf_is_not_rate_limiting(
    world: Any, ip_sets: dict[str, dict[str, str]]
) -> None:
    # A forged "fresh edge event" (StartExecution on the router, or a direct
    # invoke with an allowed guard decision) for an address WAF is not
    # rate-limiting: refused before any IP-set read or write.
    event = seed(world, events.edge_ip("1.1.1.1"))
    waf = Waf(managed=("8.8.8.8/32",))
    with pytest.raises(PlaybookError, match="not currently rate-limited by SoarApiRateLimit"):
        pb05_for(world, ip_sets, waf).handle(events.payload("block", event))
    assert waf.calls == ["get_rate_based_statement_managed_keys"]
    assert "blockedCidr" not in world.incident(event["detail"]["id"])
    assert addresses(ip_sets["v4"]) == []


def test_corroboration_asks_the_pb05_rate_rule(
    world: Any, ip_sets: dict[str, dict[str, str]]
) -> None:
    event = seed(world, events.edge_ip("2606:4700:4700::1111"))
    waf = Waf(managed=("2606:4700:4700:0:0:0:0:1111/128",))  # textual form differs
    assert pb05_for(world, ip_sets, waf).handle(events.payload("block", event))["contained"]
    assert waf.key_requests == [
        {"Scope": "CLOUDFRONT", "WebACLName": ACL_NAME, "WebACLId": ACL_ID, "RuleName": RATE_RULE}
    ]
    first_keys = waf.calls.index("get_rate_based_statement_managed_keys")
    assert first_keys < waf.calls.index("update_ip_set")


@pytest.mark.parametrize(
    ("never_block", "message"),
    [
        ("1.1.0.0/16", "on the never-block list"),
        (" , ", "never-block list is unreadable"),  # empty
        ("1.1.1.1", "never-block list is unreadable"),  # not a CIDR: invalid list
        (None, "never-block list is unreadable"),  # parameter missing
    ],
)
def test_never_block_list_is_reread_by_pb05(
    world: Any, ip_sets: dict[str, dict[str, str]], never_block: str | None, message: str
) -> None:
    if never_block is None:
        boto3.client("ssm").delete_parameter(Name=NEVER_BLOCK_PARAM)
    else:
        set_never_block(never_block)
    event = seed(world, events.edge_ip())
    waf = Waf()
    with pytest.raises(PlaybookError, match=message):
        pb05_for(world, ip_sets, waf).handle(events.payload("block", event))
    assert waf.calls == []


def test_type_and_source_are_rechecked(world: Any, ip_sets: dict[str, dict[str, str]]) -> None:
    waf = Waf()
    other_type = events.edge_ip()
    other_type["detail"]["type"] = "CloudShield:IPAddress/SomethingElse"
    with pytest.raises(PlaybookError, match=r"type .* is not allowed"):
        pb05_for(world, ip_sets, waf).handle(events.payload("block", other_type))
    with pytest.raises(PlaybookError, match="not from the edge source"):
        pb05_for(world, ip_sets, waf, EDGE_EVENT_SOURCE="cloudshield.other").handle(
            events.payload("block", events.edge_ip())
        )
    assert waf.calls == []


# ---------------------------------------------------------------- dry run
@pytest.mark.parametrize("decision_dry_run", [True, "false", None])
def test_dry_run_makes_zero_aws_mutations(
    world: Any, ip_sets: dict[str, dict[str, str]], decision_dry_run: Any
) -> None:
    waf = Waf()
    result = pb05_for(world, ip_sets, waf).handle(
        events.payload("block", events.edge_ip(), dry_run=decision_dry_run)
    )
    assert result["contained"] is False
    assert result["would"] == "block"
    assert any("1.1.1.1/32" in step for step in result["plan"])
    assert waf.calls == []
    assert addresses(ip_sets["v4"]) == []


def test_lambda_handler_entry_point(world: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    sets = make_ip_sets()
    set_never_block()
    monkeypatch.setenv("BLOCK_IP_SET_ARNS", f"{sets['v4']['ARN']},{sets['v6']['ARN']}")
    for name, value in PB05_ENV.items():
        monkeypatch.setenv(name, value)
    # moto lacks GetRateBasedStatementManagedKeys; the call is covered above.
    monkeypatch.setattr(Pb05WafIpBlock, "_corroborate", lambda *_: None)
    event = seed(world, events.edge_ip())
    assert lambda_handler(events.payload("block", event), None)["contained"] is True
    plan = lambda_handler(events.payload("block", events.edge_ip("x"), dry_run=True), None)
    assert plan["plan"][3].startswith("add <unresolved>")


# =============================================================== harvester
HARVEST_ENV = {
    "EDGE_BUS_NAME": "cs-dev-soar-edge",
    "EDGE_EVENT_SOURCE": "cloudshield.edge",
    "WAF_WEB_ACL_NAME": ACL_NAME,
    "WAF_WEB_ACL_ID": ACL_ID,
    "WAF_RATE_RULE_NAME": RATE_RULE,
    "WAF_REGION": "us-east-1",
    "HARVEST_STATE_TABLE": "cs-dev-soar-pb05-harvest-state",
    "HARVEST_MIN_GAP_SECONDS": "60",
    "HARVEST_MAX_GAP_SECONDS": "660",
}
H_SETTINGS = HarvestSettings.from_env(HARVEST_ENV)


class FakeStore:
    """Persistence answers per address (default: persistent, streak 2)."""

    def __init__(self, streaks: dict[str, int | None] | None = None) -> None:
        self.streaks = streaks or {}
        self.seen: list[str] = []

    def observe(self, address: str, now: Any) -> int | None:
        self.seen.append(address)
        return self.streaks.get(address, 2)

    def persistent(self, address: str) -> bool:
        return (self.streaks.get(address, 2) or 0) >= 2


def stubbed(service: str) -> tuple[Any, Stubber]:
    client = boto3.client(service, region_name="us-east-1")
    return client, Stubber(client)


def keys_response(v4: list[str], v6: list[str]) -> dict[str, Any]:
    return {
        "ManagedKeysIPV4": {"IPAddressVersion": "IPV4", "Addresses": v4},
        "ManagedKeysIPV6": {"IPAddressVersion": "IPV6", "Addresses": v6},
    }


def _bare(key: str) -> str:
    address, _, prefix = key.partition("/")
    return address if prefix in {"32", "128"} else key


def run_harvest(
    v4: list[str], v6: list[str], failed: int = 0, store: FakeStore | None = None
) -> tuple[dict[str, Any], list[Any]]:
    store = store or FakeStore()
    wafv2, waf_stub = stubbed("wafv2")
    waf_stub.add_response(
        "get_rate_based_statement_managed_keys",
        keys_response(v4, v6),
        {"Scope": "CLOUDFRONT", "WebACLName": ACL_NAME, "WebACLId": ACL_ID, "RuleName": RATE_RULE},
    )
    bus, bus_stub = stubbed("events")
    sent: list[Any] = []
    observed = [_bare(k) for k in [*v4, *v6][:MAX_OBSERVED]]
    total = min(len([a for a in observed if store.persistent(a)]), MAX_EVENTS)
    for start in range(0, total, 10):
        size = min(10, total - start)
        bus_stub.add_response(
            "put_events",
            {
                "FailedEntryCount": failed if start == 0 else 0,
                "Entries": [{"EventId": f"e-{start + i}"} for i in range(size)],
            },
            {"Entries": ANY},
        )
    bus.meta.events.register(
        "provide-client-params.events.PutEvents",
        lambda params, **_: sent.append(params["Entries"]),
    )
    waf_stub.activate()
    bus_stub.activate()
    result = harvest(H_SETTINGS, wafv2, bus, store, account="123456789012", now=NOW)
    waf_stub.assert_no_pending_responses()
    bus_stub.assert_no_pending_responses()
    return result, [entry for batch in sent for entry in batch]


def test_harvest_publishes_one_event_per_key_without_time() -> None:
    result, entries = run_harvest(["1.1.1.1/32", "8.8.8.8/32"], ["2606:4700:4700::1111/128"])

    assert result == {
        "keys": 3,
        "observed": 3,
        "persistent": 3,
        "published": 3,
        "failed": 0,
        "truncated": False,
    }
    assert len(entries) == 3
    for entry in entries:
        assert "Time" not in entry  # EventBridge stamps receipt time (F24)
        assert entry["Source"] == "cloudshield.edge"
        assert entry["DetailType"] == "CloudShield Edge Finding"
        assert entry["EventBusName"] == "cs-dev-soar-edge"
    details = [json.loads(e["Detail"]) for e in entries]
    assert [d["resource"]["ipAddressDetails"] for d in details] == [
        {"ipAddressV4": "1.1.1.1"},
        {"ipAddressV4": "8.8.8.8"},
        {"ipAddressV6": "2606:4700:4700::1111"},
    ]
    first = details[0]
    assert first["id"] == "edge-waf-rate-1-1-1-1-2026101410"
    assert first["type"] == "CloudShield:IPAddress/WafRateLimitExceeded"
    assert first["accountId"] == "123456789012"
    assert first["createdAt"] == iso(NOW)
    assert first["service"]["additionalInfo"] == {
        "sample": False,
        "publisher": "waf-rate-harvester",
        "webAcl": "cs-dev-cloudfront",
        "rateRule": "SoarApiRateLimit",
    }


def test_harvested_event_round_trips_through_the_guard_shape() -> None:
    # The router's RecordDetected and Finding parse it unchanged.
    from core.finding import Finding, IpAddressTarget

    _, entries = run_harvest(["1.1.1.1/32"], [])
    envelope = {
        "source": entries[0]["Source"],
        "detail-type": entries[0]["DetailType"],
        "time": iso(NOW),
        "detail": json.loads(entries[0]["Detail"]),
    }
    finding = Finding.from_event(envelope)
    assert finding.target == IpAddressTarget("1.1.1.1", 4)
    assert finding.created_at is not None


def test_harvest_caps_at_50_and_batches_by_10() -> None:
    v4 = [f"1.1.{i // 250}.{i % 250 + 1}/32" for i in range(60)]
    result, entries = run_harvest(v4, [])
    assert result == {
        "keys": 60,
        "observed": 60,
        "persistent": 60,
        "published": 50,
        "failed": 0,
        "truncated": True,
    }
    assert len(entries) == MAX_EVENTS


def test_harvest_publishes_only_addresses_seen_in_two_consecutive_harvests() -> None:
    # Audit A2: a short burst (one sighting) never becomes a block; a lost
    # race on the state row (None) publishes nothing this run.
    store = FakeStore({"1.1.1.1": 1, "8.8.8.8": 2, "9.9.9.9": None, "2606:4700:4700::1111": 5})
    result, entries = run_harvest(
        ["1.1.1.1/32", "8.8.8.8/32", "9.9.9.9/32"], ["2606:4700:4700::1111/128"], store=store
    )
    published = [json.loads(e["Detail"])["resource"]["ipAddressDetails"] for e in entries]
    assert published == [{"ipAddressV4": "8.8.8.8"}, {"ipAddressV6": "2606:4700:4700::1111"}]
    assert (result["observed"], result["persistent"], result["published"]) == (4, 2, 2)
    assert store.seen == ["1.1.1.1", "8.8.8.8", "9.9.9.9", "2606:4700:4700::1111"]


def test_harvest_observes_at_most_max_observed_keys() -> None:
    v4 = [f"1.{i // 250}.{i % 250}.1/32" for i in range(MAX_OBSERVED + 5)]
    store = FakeStore(dict.fromkeys((_bare(k) for k in v4), 1))
    result, entries = run_harvest(v4, [], store=store)
    assert len(store.seen) == MAX_OBSERVED
    assert result["truncated"] is True
    assert entries == []


def test_harvest_does_no_address_filtering() -> None:
    # Non-host keys and private addresses go out as-is: the guard refuses them.
    _, entries = run_harvest(["10.0.0.0/24", "10.0.0.1/32"], [])
    details = [json.loads(e["Detail"])["resource"]["ipAddressDetails"] for e in entries]
    assert details == [{"ipAddressV4": "10.0.0.0/24"}, {"ipAddressV4": "10.0.0.1"}]


def test_harvest_with_no_keys_publishes_nothing() -> None:
    result, entries = run_harvest([], [])
    assert result["published"] == 0
    assert entries == []


def test_harvest_failed_entries_raise() -> None:
    with pytest.raises(HarvestError, match="1 of 2"):
        run_harvest(["1.1.1.1/32", "8.8.8.8/32"], [], failed=1)


def test_harvest_settings_validation() -> None:
    with pytest.raises(ConfigError):
        HarvestSettings.from_env({**HARVEST_ENV, "EDGE_BUS_NAME": " "})
    with pytest.raises(ConfigError):
        HarvestSettings.from_env({**HARVEST_ENV, "WAF_SCOPE": "GLOBAL"})
    with pytest.raises(ConfigError):
        HarvestSettings.from_env({**HARVEST_ENV, "HARVEST_STATE_TABLE": ""})
    with pytest.raises(ConfigError):
        HarvestSettings.from_env({**HARVEST_ENV, "HARVEST_MIN_GAP_SECONDS": "x"})
    with pytest.raises(ConfigError, match="below"):
        HarvestSettings.from_env({**HARVEST_ENV, "HARVEST_MIN_GAP_SECONDS": "700"})
    assert HarvestSettings.from_env({**HARVEST_ENV, "WAF_SCOPE": ""}).scope == "CLOUDFRONT"
    defaults = HarvestSettings.from_env(
        {k: v for k, v in HARVEST_ENV.items() if not k.startswith("HARVEST_M")}
    )
    assert (defaults.min_gap_seconds, defaults.max_gap_seconds) == (60, 660)


def test_harvest_handler_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    import time

    from core import aws

    for name, value in HARVEST_ENV.items():
        monkeypatch.setenv(name, value)
    wafv2, waf_stub = stubbed("wafv2")
    waf_stub.add_response(
        "get_rate_based_statement_managed_keys", keys_response(["1.1.1.1/32"], []), None
    )
    ddb, ddb_stub = stubbed("dynamodb")
    previous = {
        "ipAddress": {"S": "1.1.1.1"},
        "lastSeenEpoch": {"N": str(int(time.time()) - 300)},
        "streak": {"N": "1"},
    }
    ddb_stub.add_response("get_item", {"Item": previous}, None)
    ddb_stub.add_response("put_item", {}, None)
    bus, bus_stub = stubbed("events")
    bus_stub.add_response("put_events", {"FailedEntryCount": 0, "Entries": [{}]}, None)
    for stub in (waf_stub, ddb_stub, bus_stub):
        stub.activate()
    clients = {"wafv2": wafv2, "events": bus, "dynamodb": ddb}
    monkeypatch.setattr(aws, "client", lambda service, config=None: clients[service])

    class Context:
        invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:x"

    assert harvest_handler({}, Context())["published"] == 1
    assert pb05._account(None) == "unknown"


# ------------------------------------------------- persistence (audit A2)
STATE_TABLE = HARVEST_ENV["HARVEST_STATE_TABLE"]


@pytest.fixture
def state_table(world: Any) -> SightingStore:
    boto3.client("dynamodb").create_table(
        TableName=STATE_TABLE,
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "ipAddress", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "ipAddress", "AttributeType": "S"}],
    )
    return SightingStore(STATE_TABLE, boto3.client("dynamodb"), 60, 660)


def test_sighting_streaks(state_table: SightingStore) -> None:
    t0 = NOW
    assert state_table.observe("1.1.1.1", t0) == 1
    # The alarm run and the scheduled run seconds apart: one harvest window.
    assert state_table.observe("1.1.1.1", t0 + timedelta(seconds=30)) == 1
    assert state_table.observe("1.1.1.1", t0 + timedelta(minutes=5)) == 2
    assert state_table.observe("1.1.1.1", t0 + timedelta(minutes=10)) == 3
    # A gap longer than HARVEST_MAX_GAP_SECONDS starts over.
    assert state_table.observe("1.1.1.1", t0 + timedelta(minutes=30)) == 1
    item = boto3.client("dynamodb").get_item(
        TableName=STATE_TABLE, Key={"ipAddress": {"S": "1.1.1.1"}}
    )["Item"]
    epoch = int((t0 + timedelta(minutes=30)).timestamp())
    assert item["expiresAt"] == {"N": str(epoch + 660 + 3600)}  # the TTL attribute
    assert item["streak"] == {"N": "1"}


class _StaleReader:
    """Another harvest wrote the row between our read and our write."""

    def __init__(self, real: Any) -> None:
        self.real = real

    def get_item(self, **_: Any) -> dict[str, Any]:
        return {"Item": {"lastSeenEpoch": {"N": "1"}, "streak": {"N": "1"}}}

    def put_item(self, **kw: Any) -> Any:
        return self.real.put_item(**kw)


def test_sighting_lost_race_returns_none(state_table: SightingStore) -> None:
    assert state_table.observe("8.8.8.8", NOW) == 1
    racing = SightingStore(STATE_TABLE, _StaleReader(boto3.client("dynamodb")), 60, 660)
    assert racing.observe("8.8.8.8", NOW + timedelta(minutes=5)) is None
    # ...and a brand-new address racing another first sighting.
    fresh = SightingStore(STATE_TABLE, boto3.client("dynamodb"), 60, 660)
    original = fresh._ddb.get_item
    fresh._ddb.get_item = lambda **kw: {}  # type: ignore[method-assign]
    assert fresh.observe("8.8.8.8", NOW + timedelta(minutes=5)) is None
    fresh._ddb.get_item = original  # type: ignore[method-assign]


def test_sighting_other_errors_propagate(state_table: SightingStore) -> None:
    from botocore.exceptions import ClientError

    broken = SightingStore("no-such-table", boto3.client("dynamodb"), 60, 660)
    with pytest.raises(ClientError):
        broken.observe("8.8.8.8", NOW)
