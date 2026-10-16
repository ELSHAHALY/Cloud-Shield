"""List PB-05 IP blocks that are past their blockExpiresAt (D15). Read-only.

    python -m tools.list_expired_blocks --table cloudshield-dev-soar-incidents

Nothing removes a block automatically: a block stays until an analyst lifts
it. This tool scans the incidents table for rows whose blockExpiresAt is in
the past, checks each against the live IP set, and prints the documented
manual removal commands. It never calls UpdateIPSet (needs only
dynamodb:Scan, kms:Decrypt on the SOAR key, and wafv2:GetIPSet).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from boto3.dynamodb.types import TypeDeserializer
from botocore.exceptions import ClientError

from core import aws
from core.finding import MalformedFindingError, iso, parse_time
from playbooks.pb05_waf_ip_block import IpSetRef, _contains

_deserializer = TypeDeserializer()
_FIELDS = ("incidentId", "status", "blockedCidr", "ipSetArn", "blockExpiresAt")


def find_expired(dynamodb: Any, table: str, now: datetime) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    pages = dynamodb.get_paginator("scan").paginate(
        TableName=table,
        FilterExpression="attribute_exists(blockExpiresAt)",
        ProjectionExpression=", ".join(f"#f{i}" for i in range(len(_FIELDS))),
        ExpressionAttributeNames={f"#f{i}": name for i, name in enumerate(_FIELDS)},
    )
    for page in pages:
        for item in page.get("Items", []):
            row = {k: _deserializer.deserialize(v) for k, v in item.items()}
            try:
                expires = parse_time(row.get("blockExpiresAt"), "blockExpiresAt")
            except MalformedFindingError:
                continue  # not a PB-05 timestamp: nothing to report
            if expires < now:
                row["overdueSeconds"] = int((now - expires).total_seconds())
                rows.append(row)
    return sorted(rows, key=lambda r: r["blockExpiresAt"])


def still_blocked(wafv2: Any, ip_set_arn: Any, cidr: Any) -> bool | None:
    """True/False from the live IP set; None when it cannot be read."""
    if not isinstance(ip_set_arn, str) or not isinstance(cidr, str):
        return None
    try:
        ref = IpSetRef.parse(ip_set_arn)
        addresses = wafv2.get_ip_set(**ref.key())["IPSet"]["Addresses"]
        return _contains(addresses, cidr)
    except (ClientError, ValueError, RuntimeError):
        return None


def removal_commands(ip_set_arn: str, cidr: str, region: str) -> list[str]:
    ref = IpSetRef.parse(ip_set_arn)
    where = f"--scope {ref.scope} --name {ref.name} --id {ref.id} --region {region}"
    return [
        f"aws wafv2 get-ip-set {where}  # note LockToken and Addresses",
        f"aws wafv2 update-ip-set {where} --lock-token <LockToken> "
        f"--addresses <every address above except {cidr}>",
    ]


def report(
    clients: Callable[..., Any], table: str, region: str, now: datetime
) -> list[dict[str, Any]]:
    wafv2 = clients("wafv2", config=aws.in_region(region))
    rows = find_expired(clients("dynamodb"), table, now)
    for row in rows:
        row["stillBlocked"] = still_blocked(wafv2, row.get("ipSetArn"), row.get("blockedCidr"))
        if row["stillBlocked"]:
            row["removal"] = removal_commands(row["ipSetArn"], row["blockedCidr"], region)
    return rows


def _text(rows: list[dict[str, Any]], now: datetime) -> str:
    if not rows:
        return f"No PB-05 blocks past their expiry at {iso(now)}."
    lines = [f"PB-05 blocks past their expiry at {iso(now)}:"]
    for row in rows:
        state = {True: "STILL BLOCKED", False: "already removed", None: "unknown (unreadable)"}
        hours = row["overdueSeconds"] / 3600
        lines.append(
            f"- {row['incidentId']}  {row.get('blockedCidr')}  expired {row['blockExpiresAt']} "
            f"({hours:.1f} h ago)  {state[row['stillBlocked']]}"
        )
        lines.extend(f"    {command}" for command in row.get("removal", []))
    return "\n".join(lines)


def main(
    argv: list[str] | None = None,
    clients: Callable[..., Any] = aws.client,
    now: datetime | None = None,
) -> int:
    parser = argparse.ArgumentParser(description="List overdue PB-05 IP blocks (read-only)")
    parser.add_argument("--table", required=True, help="e.g. cloudshield-dev-soar-incidents")
    parser.add_argument("--region", default="us-east-1", help="WAF region (WAF_REGION)")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    now = now or datetime.now(UTC)
    rows = report(clients, args.table, args.region, now)
    if args.format == "json":
        print(json.dumps(rows, indent=2, default=str))
    else:
        print(_text(rows, now))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
