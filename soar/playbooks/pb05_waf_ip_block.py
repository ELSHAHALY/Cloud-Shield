"""PB-05: block an abusive client IP at the CloudFront WAF (scenario E, plan §4.2).

action "block" (the guard has already vetted the address: edge source, fresh,
global unicast, not on the never-block list):
  1. pick the IP set of the address's family from BLOCK_IP_SET_ARNS (the ARN
     names the set and its id); WAFv2 client in WAF_REGION.
  2. GetIPSet -> addresses + LockToken. The /32 or /128 already there ->
     idempotent success.
  3. at or above BLOCK_IP_SET_MAX entries -> refuse (analyst).
  4. UpdateIPSet(old + [cidr], LockToken). UpdateIPSet REPLACES the whole
     list (F23), so the new list is asserted to be a superset of the old one
     before every call (add-only). A stale LockToken
     (WAFOptimisticLockException) means someone else changed the set: re-read
     and retry, at most 3 attempts.
  5. verify: the CIDR reads back (3 attempts, 1 s apart).
  6. record blockedCidr, ipSetArn and blockExpiresAt (now + BLOCK_TTL_HOURS)
     on the row. Nothing removes blocks automatically (D15):
     tools/list_expired_blocks.py lists the overdue ones for an analyst.

"Contained" means the block list is updated and read back. Propagation to
every CloudFront edge is not observed (it takes seconds to a minute).

`harvest_handler` is the PB-05 publisher (D13): on the rate-rule alarm it
reads the rate-limited keys and puts ONE event per key on the dedicated edge
bus, so every address passes the guard on its own. It never sets `Time`
(EventBridge stamps receipt time, which the guard's freshness rule checks)
and does no filtering of its own.
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
from core.finding import Finding, IpAddressTarget, ip_refusal, iso, parse_single_ip
from core.playbook import Playbook, PlaybookError

logger = logging.getLogger("cloudshield.soar.pb05")
logger.setLevel(logging.INFO)

UPDATE_ATTEMPTS = 3
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


def _network(entry: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def _contains(addresses: list[str], cidr: str) -> bool:
    """Textual forms differ (expanded IPv6, host bits): compare as networks."""
    wanted = ipaddress.ip_network(cidr)
    return any(_network(a) == wanted for a in addresses)


def _append(addresses: list[str], cidr: str) -> list[str]:
    return [*addresses, cidr]


class Pb05WafIpBlock(Playbook):
    name = "pb05-waf-ip-block"
    actions = frozenset({"block"})

    def plan(self, action: str, finding: Finding) -> list[str]:
        target = finding.target
        cidr = self._cidr(target) if isinstance(target, IpAddressTarget) else "<unresolved>"
        return [
            f"add {cidr} to the PB-05 WAF IP set (add-only, LockToken, <= 3 attempts)",
            "verify the address reads back",
            f"record blockExpiresAt = now + {self.settings.block_ttl_hours} h on the incident",
        ]

    @staticmethod
    def _cidr(target: IpAddressTarget) -> str:
        return f"{target.address}/{32 if target.version == 4 else 128}"

    def run(self, action: str, finding: Finding, state: dict[str, Any]) -> dict[str, Any]:
        target = finding.target
        if not isinstance(target, IpAddressTarget):
            raise PlaybookError("PB-05 needs an IP address target")
        settings = self.settings
        if not settings.block_ip_set_arns or not settings.waf_region:
            raise PlaybookError("PB-05 is not configured (BLOCK_IP_SET_ARNS / WAF_REGION)")
        # Defence in depth on top of the guard: never a non-global address.
        address = parse_single_ip(target.address)
        refusal = ip_refusal(address) if address is not None else "address does not parse"
        if refusal is not None:
            raise PlaybookError(f"refusing to block {target.address}: {refusal}")

        cidr = self._cidr(target)
        wafv2 = self.clients("wafv2", config=aws.in_region(settings.waf_region))
        ip_set, current = self._select(wafv2, target.version)

        before, outcome = len(current["IPSet"]["Addresses"]), "already-present"
        for attempt in range(1, UPDATE_ATTEMPTS + 1):
            addresses = list(current["IPSet"]["Addresses"])
            if _contains(addresses, cidr):
                break
            if len(addresses) >= settings.block_ip_set_max:
                raise PlaybookError(
                    f"IP set {ip_set.name} holds {len(addresses)} entries "
                    f"(cap {settings.block_ip_set_max}); analyst review"
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
            outcome = "added"
            break

        expires = self.clock() + timedelta(hours=settings.block_ttl_hours)
        self.record(
            finding,
            "block-ip",
            cidr=cidr,
            ipSetArn=ip_set.arn,
            result=outcome,
            entriesBefore=before,
        )
        self.incidents.set_fields(
            finding.id,
            {"blockedCidr": cidr, "ipSetArn": ip_set.arn, "blockExpiresAt": iso(expires)},
        )

        def check() -> dict[str, bool]:
            read = wafv2.get_ip_set(**ip_set.key())["IPSet"]["Addresses"]
            return {"cidrInIpSet": _contains(read, cidr)}

        verified = self.verify_with_retry(check)
        return self.contained_result(
            finding,
            "block",
            verified,
            cidr=cidr,
            ipSetArn=ip_set.arn,
            blockExpiresAt=iso(expires),
            result=outcome,
        )

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
_PUT_EVENTS_BATCH = 10  # the PutEvents API maximum
EDGE_DETAIL_TYPE = "CloudShield Edge Finding"
RATE_FINDING_TYPE = "CloudShield:IPAddress/WafRateLimitExceeded"


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

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> HarvestSettings:
        env = os.environ if env is None else env

        def required(name: str) -> str:
            value = env.get(name, "").strip()
            if not value:
                raise ConfigError(f"missing environment variable {name}")
            return value

        scope = env.get("WAF_SCOPE", "CLOUDFRONT").strip() or "CLOUDFRONT"
        if scope not in {"CLOUDFRONT", "REGIONAL"}:
            raise ConfigError("WAF_SCOPE must be CLOUDFRONT or REGIONAL")
        return cls(
            bus_name=required("EDGE_BUS_NAME"),
            event_source=required("EDGE_EVENT_SOURCE"),
            web_acl_name=required("WAF_WEB_ACL_NAME"),
            web_acl_id=required("WAF_WEB_ACL_ID"),
            rate_rule_name=required("WAF_RATE_RULE_NAME"),
            scope=scope,
            waf_region=required("WAF_REGION"),
        )


def _key_address(key: str, host_prefix: int) -> str:
    """WAF reports keys as CIDRs (x/32, y/128). A host prefix is stripped to
    the bare address; anything else is passed through untouched for the
    guard to refuse (the harvester does no filtering of its own)."""
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
            },
        },
    }


def harvest(
    settings: HarvestSettings,
    wafv2: Any,
    events: Any,
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
    selected = found[:MAX_EVENTS]
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
        "published": len(entries) - failed,
        "failed": failed,
        "truncated": len(found) > MAX_EVENTS,
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
    """Alarm state change (or optional schedule) -> one edge event per key."""
    settings = HarvestSettings.from_env()
    return harvest(
        settings,
        aws.client("wafv2", config=aws.in_region(settings.waf_region)),
        aws.client("events"),
        account=_account(context),
    )
