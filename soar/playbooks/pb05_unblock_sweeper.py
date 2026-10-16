"""PB-05 auto-expiry sweeper (audit A2, ADR-0005 D15). Scheduled, every 15 min.

A block PB-05 adds is a containment step with a lifetime: blockExpiresAt on the
incident row (default 24 h). Behind a shared egress (a NAT, a carrier, an
office), one abusive client blocks everyone else behind the same IP, so a block
must not outlive its reason. This function lifts expired blocks and nothing
else:

  1. scan the incidents table for rows that track a block (blockedCidr,
     ipSetArn, blockExpiresAt), and group them by (IP set, address).
  2. an address is lifted only if it is ROW-TRACKED, EXPIRED, and NOT COVERED
     by a newer unexpired row for the same address (every row of the group has
     a parseable blockExpiresAt in the past). An unparseable expiry keeps the
     block (fail closed: never remove what cannot be reasoned about).
  3. per configured IP set: GetIPSet -> remove exactly those entries ->
     UpdateIPSet with the LockToken (WAFOptimisticLockException -> re-read and
     retry, at most 3 attempts) -> read back until none of them is present.
     The new list is asserted to be a SUBSET of the old one, and every dropped
     entry an expired tracked address, before every call (remove-only).
  4. only after the read-back: blockLiftedAt + blockState=lifted and an
     "unblock" action on every row of the group that was not lifted yet.

It never removes an entry no row explains (an "orphan", e.g. added by hand):
those are reported in the result and the log for an analyst. It does not read
the dry-run switch: it only undoes blocks PB-05 made while live, and the
dry-run switch never creates any. Recovery of the workload stays human; this
only ends a containment whose time is up.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from boto3.dynamodb.types import TypeDeserializer
from botocore.exceptions import ClientError

from core import aws
from core.aws import error_code
from core.config import ConfigError
from core.finding import MalformedFindingError, iso, parse_time
from core.incidents import IncidentRepository
from playbooks.pb05_waf_ip_block import UPDATE_ATTEMPTS, IpSetRef, network

logger = logging.getLogger("cloudshield.soar.pb05-sweeper")
logger.setLevel(logging.INFO)

NAME = "pb05-unblock-sweeper"
VERIFY_ATTEMPTS = 3
_FIELDS = ("incidentId", "blockedCidr", "ipSetArn", "blockExpiresAt", "blockLiftedAt")
_deserializer = TypeDeserializer()

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class SweepError(RuntimeError):
    """A set could not be swept safely; nothing was recorded as lifted for it."""


@dataclass(frozen=True)
class SweeperSettings:
    incidents_table: str
    block_ip_set_arns: tuple[str, ...]
    waf_region: str

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> SweeperSettings:
        env = os.environ if env is None else env
        arns = tuple(a.strip() for a in env.get("BLOCK_IP_SET_ARNS", "").split(",") if a.strip())
        table, region = env.get("INCIDENTS_TABLE", "").strip(), env.get("WAF_REGION", "").strip()
        if not table or not region or not arns:
            raise ConfigError("INCIDENTS_TABLE, BLOCK_IP_SET_ARNS and WAF_REGION are required")
        return cls(table, arns, region)


@dataclass
class Group:
    """Every row that tracks one address in one IP set."""

    incident_ids: list[str] = field(default_factory=list)
    unlifted: list[str] = field(default_factory=list)
    expiries: list[datetime | None] = field(default_factory=list)

    def expired(self, now: datetime) -> bool:
        return bool(self.expiries) and all(e is not None and e <= now for e in self.expiries)


def tracked_rows(dynamodb: Any, table: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    pages = dynamodb.get_paginator("scan").paginate(
        TableName=table,
        FilterExpression="attribute_exists(blockedCidr)",
        ProjectionExpression=", ".join(f"#f{i}" for i in range(len(_FIELDS))),
        ExpressionAttributeNames={f"#f{i}": name for i, name in enumerate(_FIELDS)},
    )
    for page in pages:
        rows.extend(
            {k: _deserializer.deserialize(v) for k, v in item.items()}
            for item in page.get("Items", [])
        )
    return rows


def group_rows(rows: list[dict[str, Any]]) -> dict[tuple[str, Network], Group]:
    groups: dict[tuple[str, Network], Group] = defaultdict(Group)
    for row in rows:
        net, arn = network(row.get("blockedCidr")), row.get("ipSetArn")
        if net is None or not isinstance(arn, str):
            continue
        group = groups[(arn, net)]
        group.incident_ids.append(str(row["incidentId"]))
        if "blockLiftedAt" not in row:
            group.unlifted.append(str(row["incidentId"]))
        try:
            group.expiries.append(parse_time(row.get("blockExpiresAt"), "blockExpiresAt"))
        except MalformedFindingError:
            group.expiries.append(None)  # unknown expiry: keeps the block
    return groups


def _without(addresses: list[str], expired: set[Network]) -> list[str]:
    return [a for a in addresses if network(a) not in expired]


class Sweeper:
    def __init__(
        self,
        settings: SweeperSettings,
        wafv2: Any,
        dynamodb: Any,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings
        self.wafv2 = wafv2
        self.dynamodb = dynamodb
        self.clock = clock
        self.sleep = sleep
        self.incidents = IncidentRepository(settings.incidents_table, dynamodb)

    def sweep(self) -> dict[str, Any]:
        now = self.clock()
        groups = group_rows(tracked_rows(self.dynamodb, self.settings.incidents_table))
        report: dict[str, Any] = {"lifted": [], "orphans": [], "kept": 0, "errors": []}
        for arn in self.settings.block_ip_set_arns:
            mine = {net: g for (a, net), g in groups.items() if a == arn}
            expired = {net for net, g in mine.items() if g.expired(now)}
            report["kept"] += len(mine) - len(expired)
            try:
                lifted, orphans = self._sweep_set(IpSetRef.parse(arn), set(mine), expired)
            except (ClientError, SweepError, RuntimeError) as exc:
                report["errors"].append({"ipSetArn": arn, "error": str(exc)})
                continue
            report["orphans"].extend({"ipSetArn": arn, "entry": e} for e in orphans)
            for net in lifted:
                self._record(arn, net, mine[net], now)
                report["lifted"].append({"ipSetArn": arn, "cidr": str(net)})
        logger.info(json.dumps({"sweep": report}, default=str))
        if report["errors"]:
            raise SweepError(f"{len(report['errors'])} IP set(s) could not be swept")
        return report

    def _sweep_set(
        self, ref: IpSetRef, tracked: set[Network], expired: set[Network]
    ) -> tuple[list[Network], list[str]]:
        current = self.wafv2.get_ip_set(**ref.key())
        orphans = [a for a in current["IPSet"]["Addresses"] if network(a) not in tracked]
        removed: list[Network] = []
        for attempt in range(1, UPDATE_ATTEMPTS + 1):
            addresses = list(current["IPSet"]["Addresses"])
            dropping = {network(a) for a in addresses} & expired
            if not dropping:
                break
            new = _without(addresses, expired)
            gone = set(addresses) - set(new)
            # Remove-only: a subset of the old list, and only expired tracked entries.
            if not set(new) <= set(addresses) or not {network(a) for a in gone} <= expired:
                raise SweepError("refusing an update that is not remove-only")
            try:
                self.wafv2.update_ip_set(**ref.key(), Addresses=new, LockToken=current["LockToken"])
            except ClientError as exc:
                if error_code(exc) != "WAFOptimisticLockException":
                    raise
                if attempt == UPDATE_ATTEMPTS:
                    raise SweepError(
                        f"IP set {ref.name} kept changing; gave up after {attempt} attempts"
                    ) from exc
                current = self.wafv2.get_ip_set(**ref.key())
                continue
            removed = sorted((n for n in dropping if n is not None), key=str)
            break
        if removed:
            self._verify_removed(ref, set(removed))
        return removed, orphans

    def _verify_removed(self, ref: IpSetRef, removed: set[Network]) -> None:
        for attempt in range(VERIFY_ATTEMPTS):
            present = {network(a) for a in self.wafv2.get_ip_set(**ref.key())["IPSet"]["Addresses"]}
            if not present & removed:
                return
            if attempt < VERIFY_ATTEMPTS - 1:
                self.sleep(1.0)
        raise SweepError(f"IP set {ref.name}: removed entries still read back")

    def _record(self, arn: str, net: Network, group: Group, now: datetime) -> None:
        for incident_id in group.unlifted:
            self.incidents.set_fields(
                incident_id, {"blockLiftedAt": iso(now), "blockState": "lifted"}
            )
            self.incidents.append_action(
                incident_id,
                {
                    "playbook": NAME,
                    "step": "unblock",
                    "at": iso(now),
                    "cidr": str(net),
                    "ipSetArn": arn,
                    "reason": "blockExpiresAt passed",
                },
            )


def lambda_handler(event: Any, context: Any) -> dict[str, Any]:
    settings = SweeperSettings.from_env()
    return Sweeper(
        settings,
        aws.client("wafv2", config=aws.in_region(settings.waf_region)),
        aws.client("dynamodb"),
    ).sweep()
