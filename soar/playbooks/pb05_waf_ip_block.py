"""PB-05: block an abusive client IP at the CloudFront WAF (scenario E, plan §4.2).

action "block". The guard has vetted the event, but the guard only sees what
the caller wrote: anyone allowed to start cs-ir-router (or to invoke this
Lambda with a forged guard decision) can write a "fresh edge event". So PB-05
re-checks everything itself, from sources the caller cannot write (audit A1):
  1. the event is from EDGE_EVENT_SOURCE and its type is on the edge
     allow-list; the address is global unicast (the full rule set, not just
     `is_global`).
  2. the never-block list, re-read from SSM now: unreadable, empty or invalid
     -> refuse; a hit -> refuse.
  3. corroborate with WAF itself: for CloudShield:IPAddress/WafRateLimitExceeded
     the address must CURRENTLY be a managed key of the PB-05-feeding rate
     rule (GetRateBasedStatementManagedKeys on the CloudFront ACL). Any other
     type has no corroboration and is refused. Residual risk: an address that
     WAF really is rate-limiting at block time can be blocked by whoever can
     start the router, which is exactly what the harvester does anyway.
Then:
  4. pick the IP set of the address's family from BLOCK_IP_SET_ARNS; GetIPSet.
     The /32 or /128 already there -> idempotent success.
  5. at or above BLOCK_IP_SET_MAX entries -> refuse (analyst).
  6. write blockedCidr, ipSetArn, blockExpiresAt and blockState=pending on the
     row BEFORE UpdateIPSet (audit A3), so a failure later can never leave a
     block nobody tracks.
  7. UpdateIPSet(old + [cidr], LockToken). UpdateIPSet REPLACES the whole
     list (F23), so the new list is asserted to be a superset of the old one
     before every call (add-only). A stale LockToken
     (WAFOptimisticLockException) means someone else changed the set: re-read
     and retry, at most 3 attempts.
  8. verify: the CIDR reads back (3 attempts, 1 s apart); only then
     blockState=active.

"Contained" means the block list is updated and read back. Propagation to
every CloudFront edge is not observed (it takes seconds to a minute). Blocks
are lifted automatically once blockExpiresAt has passed, by the sweeper in
playbooks/pb05_unblock_sweeper.py (audit A2, ADR-0005 D15).

`harvest_handler` is the PB-05 publisher (D13): on the rate-rule alarm, and on
its schedule, it reads the managed keys of the PB-05-feeding rate rule
(SoarApiRateLimit, /api/* only) and records each sighting in a small
DynamoDB table. An address is published only once it has been a managed key
in at least two consecutive harvests (audit A2: a short burst never becomes
a block). One event per address goes onto the dedicated edge bus, so every
address passes the guard on its own. It never sets `Time` (EventBridge stamps
receipt time, which the guard's freshness rule checks).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

from core import aws
from core.aws import error_code
from core.config import ConfigError
from core.finding import (
    EDGE_FINDING_TYPES,
    EDGE_RATE_FINDING_TYPE,
    Finding,
    IpAddressTarget,
    ip_refusal,
    iso,
    parse_single_ip,
)
from core.guard import read_never_block
from core.playbook import Playbook, PlaybookError

logger = logging.getLogger("cloudshield.soar.pb05")
logger.setLevel(logging.INFO)

UPDATE_ATTEMPTS = 3
WAF_SCOPE = "CLOUDFRONT"  # per-IP controls live on the CloudFront ACL (F3, D4)
_IP_SET_ARN = re.compile(
    r"^arn:aws[\w-]*:wafv2:[a-z0-9-]+:\d{12}:"
    r"(global|regional)/ipset/([\w-]{1,128})/([0-9a-f-]{36})\Z",
    re.ASCII,
)


@dataclass(frozen=True)
class IpSetRef:
    arn: str
    name: str
    id: str
    scope: str  # CLOUDFRONT | REGIONAL

    @classmethod
    def parse(cls, arn: str) -> IpSetRef:
        match = _IP_SET_ARN.match(arn)
        if not match:
            raise PlaybookError(f"not a WAFv2 IP set ARN: {arn!r}")
        scope = "CLOUDFRONT" if match.group(1) == "global" else "REGIONAL"
        return cls(arn, match.group(2), match.group(3), scope)

    def key(self) -> dict[str, str]:
        return {"Name": self.name, "Scope": self.scope, "Id": self.id}


def network(entry: Any) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """An IP-set entry or row CIDR as a network; None when it does not parse."""
    if not isinstance(entry, str):
        return None
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def _contains(addresses: list[str], cidr: str) -> bool:
    """Textual forms differ (expanded IPv6, host bits): compare as networks."""
    wanted = ipaddress.ip_network(cidr)
    return any(network(a) == wanted for a in addresses)


def _append(addresses: list[str], cidr: str) -> list[str]:
    return [*addresses, cidr]


def managed_keys(response: Mapping[str, Any]) -> list[str]:
    """Both address families of a GetRateBasedStatementManagedKeys response."""
    return [
        *response.get("ManagedKeysIPV4", {}).get("Addresses", []),
        *response.get("ManagedKeysIPV6", {}).get("Addresses", []),
    ]


class Pb05WafIpBlock(Playbook):
    name = "pb05-waf-ip-block"
    actions = frozenset({"block"})

    def plan(self, action: str, finding: Finding) -> list[str]:
        target = finding.target
        cidr = self._cidr(target) if isinstance(target, IpAddressTarget) else "<unresolved>"
        return [
            "re-read the never-block list and re-check the address rules",
            f"corroborate: {cidr} must be a managed key of the WAF rate rule right now",
            f"record the pending block of {cidr} on the incident (blockExpiresAt = now + "
            f"{self.settings.block_ttl_hours} h)",
            f"add {cidr} to the PB-05 WAF IP set (add-only, LockToken, <= 3 attempts)",
            "verify the address reads back; the sweeper lifts it after blockExpiresAt",
        ]

    @staticmethod
    def _cidr(target: IpAddressTarget) -> str:
        return f"{target.address}/{32 if target.version == 4 else 128}"

    def _configured(self) -> bool:
        s = self.settings
        return all(
            (
                s.block_ip_set_arns,
                s.waf_region,
                s.never_block_param,
                s.edge_event_source,
                s.waf_web_acl_name,
                s.waf_web_acl_id,
                s.waf_rate_rule_name,
            )
        )

    def run(self, action: str, finding: Finding, state: dict[str, Any]) -> dict[str, Any]:
        target = finding.target
        if not isinstance(target, IpAddressTarget):
            raise PlaybookError("PB-05 needs an IP address target")
        settings = self.settings
        if not self._configured():
            raise PlaybookError(
                "PB-05 is not configured (BLOCK_IP_SET_ARNS / WAF_REGION / NEVER_BLOCK_PARAM / "
                "EDGE_EVENT_SOURCE / WAF_WEB_ACL_NAME / WAF_WEB_ACL_ID / WAF_RATE_RULE_NAME)"
            )

        # 1. what the guard checked, re-checked from the event (defence in depth).
        if finding.source != settings.edge_event_source:
            raise PlaybookError("refusing: the event is not from the edge source")
        if finding.type not in EDGE_FINDING_TYPES:
            raise PlaybookError(f"refusing: edge finding type {finding.type!r} is not allowed")
        address = parse_single_ip(target.address)
        refusal = ip_refusal(address) if address is not None else "address does not parse"
        if refusal is not None:
            raise PlaybookError(f"refusing to block {target.address}: {refusal}")

        # 2. the never-block list, read now (fail closed).
        never_block = read_never_block(self.clients("ssm"), settings.never_block_param)
        if not never_block:
            raise PlaybookError("refusing: the never-block list is unreadable, empty or invalid")
        if any(address in net for net in never_block):
            raise PlaybookError(f"refusing to block {target.address}: on the never-block list")

        cidr = self._cidr(target)
        wafv2 = self.clients("wafv2", config=aws.in_region(settings.waf_region))

        # 3. corroborate with WAF: a source the caller cannot write.
        self._corroborate(wafv2, finding, cidr)

        # 4-5. the IP set of this family.
        ip_set, current = self._select(wafv2, target.version)
        before = len(current["IPSet"]["Addresses"])
        if not _contains(current["IPSet"]["Addresses"], cidr) and (
            before >= settings.block_ip_set_max
        ):
            raise PlaybookError(
                f"IP set {ip_set.name} holds {before} entries "
                f"(cap {settings.block_ip_set_max}); analyst review"
            )

        # 6. track BEFORE changing anything (audit A3).
        expires = self.clock() + timedelta(hours=settings.block_ttl_hours)
        self.incidents.set_fields(
            finding.id,
            {
                "blockedCidr": cidr,
                "ipSetArn": ip_set.arn,
                "blockExpiresAt": iso(expires),
                "blockState": "pending",
            },
        )

        # 7. add-only update with bounded retry.
        outcome = self._add(wafv2, ip_set, current, cidr)
        self.record(
            finding,
            "block-ip",
            cidr=cidr,
            ipSetArn=ip_set.arn,
            result=outcome,
            entriesBefore=before,
            corroboratedBy=settings.waf_rate_rule_name,
        )

        # 8. read back.
        def check() -> dict[str, bool]:
            read = wafv2.get_ip_set(**ip_set.key())["IPSet"]["Addresses"]
            return {"cidrInIpSet": _contains(read, cidr)}

        verified = self.verify_with_retry(check)
        if verified.get("cidrInIpSet") is True:
            self.incidents.set_fields(finding.id, {"blockState": "active"})
        return self.contained_result(
            finding,
            "block",
            verified,
            cidr=cidr,
            ipSetArn=ip_set.arn,
            blockExpiresAt=iso(expires),
            result=outcome,
        )

    def _corroborate(self, wafv2: Any, finding: Finding, cidr: str) -> None:
        """Refuse unless WAF itself is rate-limiting the address right now."""
        if finding.type != EDGE_RATE_FINDING_TYPE:  # pragma: no cover - allow-list above
            raise PlaybookError(f"no corroboration check for {finding.type!r}; refusing")
        settings = self.settings
        response = wafv2.get_rate_based_statement_managed_keys(
            Scope=WAF_SCOPE,
            WebACLName=settings.waf_web_acl_name,
            WebACLId=settings.waf_web_acl_id,
            RuleName=settings.waf_rate_rule_name,
        )
        if not _contains(managed_keys(response), cidr):
            raise PlaybookError(
                f"refusing: {cidr} is not currently rate-limited by "
                f"{settings.waf_rate_rule_name} (WAF does not corroborate the event)"
            )

    def _add(self, wafv2: Any, ip_set: IpSetRef, current: dict[str, Any], cidr: str) -> str:
        for attempt in range(1, UPDATE_ATTEMPTS + 1):
            addresses = list(current["IPSet"]["Addresses"])
            if _contains(addresses, cidr):
                return "already-present"
            if len(addresses) >= self.settings.block_ip_set_max:
                raise PlaybookError(
                    f"IP set {ip_set.name} holds {len(addresses)} entries "
                    f"(cap {self.settings.block_ip_set_max}); analyst review"
                )
            new = _append(addresses, cidr)
            if not set(new) >= set(addresses) or cidr not in new:
                raise PlaybookError("refusing an update that is not add-only")
            try:
                wafv2.update_ip_set(**ip_set.key(), Addresses=new, LockToken=current["LockToken"])
            except ClientError as exc:
                if error_code(exc) != "WAFOptimisticLockException":
                    raise
                if attempt == UPDATE_ATTEMPTS:
                    raise PlaybookError(
                        f"IP set {ip_set.name} kept changing; gave up after {attempt} attempts"
                    ) from exc
                current = wafv2.get_ip_set(**ip_set.key())
                continue
            return "added"
        raise PlaybookError("unreachable")  # pragma: no cover

    def _select(self, wafv2: Any, version: int) -> tuple[IpSetRef, dict[str, Any]]:
        """The configured IP set for this address family, and its current state."""
        wanted = "IPV4" if version == 4 else "IPV6"
        for arn in self.settings.block_ip_set_arns:
            ref = IpSetRef.parse(arn)
            current = wafv2.get_ip_set(**ref.key())
            if current["IPSet"].get("IPAddressVersion") == wanted:
                return ref, current
        raise PlaybookError(f"no configured PB-05 IP set for {wanted}")


lambda_handler = Pb05WafIpBlock.lambda_handler


# =============================================================== harvester
MAX_EVENTS = 50  # per invocation (plan §4.2)
MAX_OBSERVED = 200  # sightings recorded per invocation (bounded DynamoDB work)
MIN_STREAK = 2  # consecutive harvests an address must persist (audit A2)
_PUT_EVENTS_BATCH = 10  # the PutEvents API maximum
EDGE_DETAIL_TYPE = "CloudShield Edge Finding"
RATE_FINDING_TYPE = EDGE_RATE_FINDING_TYPE


class HarvestError(RuntimeError):
    """Some events were not accepted by EventBridge (the async retry re-runs
    the harvest; the router drops duplicates by finding id)."""


@dataclass(frozen=True)
class HarvestSettings:
    bus_name: str
    event_source: str
    web_acl_name: str
    web_acl_id: str
    rate_rule_name: str
    scope: str
    waf_region: str
    state_table: str
    min_gap_seconds: int = 60
    max_gap_seconds: int = 660

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> HarvestSettings:
        env = os.environ if env is None else env

        def required(name: str) -> str:
            value = env.get(name, "").strip()
            if not value:
                raise ConfigError(f"missing environment variable {name}")
            return value

        def bounded(name: str, default: int, low: int, high: int) -> int:
            raw = env.get(name, "").strip() or str(default)
            if not raw.isdigit() or not low <= int(raw) <= high:
                raise ConfigError(f"{name} must be an integer from {low} to {high}")
            return int(raw)

        scope = env.get("WAF_SCOPE", "CLOUDFRONT").strip() or "CLOUDFRONT"
        if scope not in {"CLOUDFRONT", "REGIONAL"}:
            raise ConfigError("WAF_SCOPE must be CLOUDFRONT or REGIONAL")
        min_gap = bounded("HARVEST_MIN_GAP_SECONDS", 60, 0, 3600)
        max_gap = bounded("HARVEST_MAX_GAP_SECONDS", 660, 60, 86400)
        if min_gap >= max_gap:
            raise ConfigError("HARVEST_MIN_GAP_SECONDS must be below HARVEST_MAX_GAP_SECONDS")
        return cls(
            bus_name=required("EDGE_BUS_NAME"),
            event_source=required("EDGE_EVENT_SOURCE"),
            web_acl_name=required("WAF_WEB_ACL_NAME"),
            web_acl_id=required("WAF_WEB_ACL_ID"),
            rate_rule_name=required("WAF_RATE_RULE_NAME"),
            scope=scope,
            waf_region=required("WAF_REGION"),
            state_table=required("HARVEST_STATE_TABLE"),
            min_gap_seconds=min_gap,
            max_gap_seconds=max_gap,
        )


class SightingStore:
    """Per-address persistence state (audit A2), in a dedicated DynamoDB table.

    Item: ipAddress (hash key), lastSeenEpoch, streak, expiresAt (TTL). A
    sighting less than min_gap after the last counted one belongs to the same
    harvest window (e.g. the alarm run and the scheduled run seconds apart) and
    does not extend the streak; a gap above max_gap starts a new streak. Writes
    are conditional on the row read, so two concurrent harvests can never both
    extend a streak: the loser returns None and publishes nothing this run.
    """

    def __init__(self, table: str, dynamodb: Any, min_gap: int, max_gap: int) -> None:
        self._table = table
        self._ddb = dynamodb
        self._min_gap = min_gap
        self._max_gap = max_gap

    def observe(self, address: str, now: datetime) -> int | None:
        epoch = int(now.timestamp())
        key = {"ipAddress": {"S": address}}
        item = self._ddb.get_item(TableName=self._table, Key=key, ConsistentRead=True).get("Item")
        condition: dict[str, Any]
        if item is None:
            streak = 1
            condition = {
                "ConditionExpression": "attribute_not_exists(#a)",
                "ExpressionAttributeNames": {"#a": "ipAddress"},
            }
        else:
            last, streak = int(item["lastSeenEpoch"]["N"]), int(item["streak"]["N"])
            gap = epoch - last
            if gap < self._min_gap:
                return streak
            streak = streak + 1 if gap <= self._max_gap else 1
            condition = {
                "ConditionExpression": "#l = :last",
                "ExpressionAttributeNames": {"#l": "lastSeenEpoch"},
                "ExpressionAttributeValues": {":last": {"N": str(last)}},
            }
        try:
            self._ddb.put_item(
                TableName=self._table,
                Item={
                    **key,
                    "lastSeenEpoch": {"N": str(epoch)},
                    "streak": {"N": str(streak)},
                    "expiresAt": {"N": str(epoch + self._max_gap + 3600)},
                },
                **condition,
            )
        except ClientError as exc:
            if error_code(exc) == "ConditionalCheckFailedException":
                return None
            raise
        return streak


def _key_address(key: str, host_prefix: int) -> str:
    """WAF reports keys as CIDRs (x/32, y/128). A host prefix is stripped to
    the bare address; anything else is passed through untouched for the
    guard to refuse."""
    address, sep, prefix = key.partition("/")
    return address if sep and prefix == str(host_prefix) else key


def _edge_detail(
    address: str, family: str, settings: HarvestSettings, account: str, now: datetime
) -> dict[str, Any]:
    normalised = re.sub(r"[^0-9A-Za-z]", "-", address)
    return {
        "schemaVersion": "2.0",
        "id": f"edge-waf-rate-{normalised}-{now:%Y%m%d%H}",
        "type": RATE_FINDING_TYPE,
        "severity": 5.0,
        "createdAt": iso(now),
        "accountId": account,
        "region": settings.waf_region,
        "resource": {"resourceType": "IPAddress", "ipAddressDetails": {family: address}},
        "service": {
            "serviceName": "cloudshield",
            "additionalInfo": {
                "sample": False,
                "publisher": "waf-rate-harvester",
                "webAcl": settings.web_acl_name,
                "rateRule": settings.rate_rule_name,
            },
        },
    }


def harvest(
    settings: HarvestSettings,
    wafv2: Any,
    events: Any,
    store: Any,
    *,
    account: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    keys = wafv2.get_rate_based_statement_managed_keys(
        Scope=settings.scope,
        WebACLName=settings.web_acl_name,
        WebACLId=settings.web_acl_id,
        RuleName=settings.rate_rule_name,
    )
    found = [
        ("ipAddressV4", _key_address(k, 32))
        for k in keys.get("ManagedKeysIPV4", {}).get("Addresses", [])
    ] + [
        ("ipAddressV6", _key_address(k, 128))
        for k in keys.get("ManagedKeysIPV6", {}).get("Addresses", [])
    ]
    observed = found[:MAX_OBSERVED]
    persistent = []
    for family, address in observed:
        streak = store.observe(address, now)
        if streak is not None and streak >= MIN_STREAK:
            persistent.append((family, address))
    selected = persistent[:MAX_EVENTS]
    # No `Time` on any entry: EventBridge stamps the receipt time.
    entries = [
        {
            "Source": settings.event_source,
            "DetailType": EDGE_DETAIL_TYPE,
            "Detail": json.dumps(_edge_detail(address, family, settings, account, now)),
            "EventBusName": settings.bus_name,
        }
        for family, address in selected
    ]
    failed = 0
    for start in range(0, len(entries), _PUT_EVENTS_BATCH):
        response = events.put_events(Entries=entries[start : start + _PUT_EVENTS_BATCH])
        failed += int(response.get("FailedEntryCount", 0))
    result = {
        "keys": len(found),
        "observed": len(observed),
        "persistent": len(persistent),
        "published": len(entries) - failed,
        "failed": failed,
        "truncated": len(found) > MAX_OBSERVED or len(persistent) > MAX_EVENTS,
    }
    logger.info(json.dumps({"harvest": result}))
    if failed:
        raise HarvestError(f"{failed} of {len(entries)} edge events were not accepted")
    return result


def _account(context: Any) -> str:
    arn = getattr(context, "invoked_function_arn", "")
    parts = arn.split(":") if isinstance(arn, str) else []
    return parts[4] if len(parts) > 4 and parts[4].isdigit() else "unknown"


def harvest_handler(event: Any, context: Any) -> dict[str, Any]:
    """Alarm state change or schedule -> one edge event per persistent key."""
    settings = HarvestSettings.from_env()
    return harvest(
        settings,
        aws.client("wafv2", config=aws.in_region(settings.waf_region)),
        aws.client("events"),
        SightingStore(
            settings.state_table,
            aws.client("dynamodb"),
            settings.min_gap_seconds,
            settings.max_gap_seconds,
        ),
        account=_account(context),
    )
