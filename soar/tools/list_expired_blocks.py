"""Audit PB-05 IP blocks against the incidents table (D15, audit A3). Read-only.

    python -m tools.list_expired_blocks --table cloudshield-dev-soar-incidents

The sweeper (playbooks/pb05_unblock_sweeper.py) lifts expired blocks every
15 minutes. This tool is the analyst's cross-check and never changes
anything (it needs only dynamodb:Scan, kms:Decrypt on the SOAR key and
wafv2:GetIPSet). Rows are grouped by (IP set, address); the LATEST expiry of
a group wins, so an older expired row never hides a newer unexpired block.

  expired  groups whose latest expiry has passed; "STILL BLOCKED" ones are
           what the sweeper should have lifted (manual commands are printed)
  lost     groups NOT yet expired whose address is missing from the live IP
           set: the block vanished early (removed by hand, or the IP sets were
           destroyed and recreated, e.g. enable_edge=false; ADR-0005), or the
           pending block never applied
  orphans  live IP-set entries that no row explains (added outside PB-05);
           neither the sweeper nor this tool ever removes them

The IP sets checked are those the rows name plus any --ip-set-arn given.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import ClientError

from core import aws
from core.finding import MalformedFindingError, iso, parse_time
from playbooks.pb05_unblock_sweeper import tracked_rows
from playbooks.pb05_waf_ip_block import IpSetRef, network


def _groups(rows: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    """(ipSetArn, normalised CIDR) -> the group, with its latest expiry."""
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        net, arn = network(row.get("blockedCidr")), row.get("ipSetArn")
        if net is None or not isinstance(arn, str):
            continue
        try:
            expires: datetime | None = parse_time(row.get("blockExpiresAt"), "blockExpiresAt")
        except MalformedFindingError:
            expires = None
        group = groups.setdefault(
            (arn, str(net)),
            {"ipSetArn": arn, "cidr": str(net), "incidents": [], "latestExpiry": None},
        )
        group["incidents"].append(row["incidentId"])
        if expires is None:
            group["unparseable"] = True
        elif group["latestExpiry"] is None or expires > group["latestExpiry"]:
            group["latestExpiry"] = expires
    return groups


def live_entries(wafv2: Any, ip_set_arn: str) -> list[str] | None:
    """The live addresses of an IP set; None when it cannot be read."""
    try:
        return list(wafv2.get_ip_set(**IpSetRef.parse(ip_set_arn).key())["IPSet"]["Addresses"])
    except (ClientError, ValueError, RuntimeError):
        return None


def still_blocked(wafv2: Any, ip_set_arn: Any, cidr: Any) -> bool | None:
    """True/False from the live IP set; None when it cannot be read."""
    if not isinstance(ip_set_arn, str) or network(cidr) is None:
        return None
    entries = live_entries(wafv2, ip_set_arn)
    if entries is None:
        return None
    return network(cidr) in {network(e) for e in entries}


def removal_commands(ip_set_arn: str, cidr: str, region: str) -> list[str]:
    ref = IpSetRef.parse(ip_set_arn)
    where = f"--scope {ref.scope} --name {ref.name} --id {ref.id} --region {region}"
    return [
        f"aws wafv2 get-ip-set {where}  # note LockToken and Addresses",
        f"aws wafv2 update-ip-set {where} --lock-token <LockToken> "
        f"--addresses <every address above except {cidr}>",
    ]


def report(
    clients: Callable[..., Any],
    table: str,
    region: str,
    now: datetime,
    extra_ip_sets: tuple[str, ...] = (),
) -> dict[str, list[dict[str, Any]]]:
    wafv2 = clients("wafv2", config=aws.in_region(region))
    groups = _groups(tracked_rows(clients("dynamodb"), table))
    arns = sorted({arn for arn, _ in groups} | set(extra_ip_sets))
    live = {arn: live_entries(wafv2, arn) for arn in arns}
    expired, lost, orphans = [], [], []

    for (arn, cidr), group in sorted(groups.items()):
        entries = live[arn]
        blocked = None if entries is None else network(cidr) in {network(e) for e in entries}
        latest = group["latestExpiry"]
        out = {**group, "latestExpiry": iso(latest) if latest else None, "stillBlocked": blocked}
        if group.get("unparseable") or latest is None:
            continue  # the sweeper keeps these too: nothing to say about expiry
        if latest < now:
            out["overdueSeconds"] = int((now - latest).total_seconds())
            if blocked:
                out["removal"] = removal_commands(arn, cidr, region)
            expired.append(out)
        elif blocked is False:
            lost.append(out)

    for arn in arns:
        tracked = {network(cidr) for a, cidr in groups if a == arn}
        orphans.extend(
            {"ipSetArn": arn, "entry": e} for e in live[arn] or [] if network(e) not in tracked
        )
    return {"expired": expired, "lost": lost, "orphans": orphans}


def _text(result: dict[str, list[dict[str, Any]]], now: datetime) -> str:
    lines = [f"PB-05 blocks at {iso(now)}:"]
    state = {True: "STILL BLOCKED", False: "lifted", None: "unknown (unreadable)"}
    lines.append(f"expired ({len(result['expired'])}):")
    for g in result["expired"]:
        hours = g["overdueSeconds"] / 3600
        lines.append(
            f"- {g['cidr']}  expired {g['latestExpiry']} ({hours:.1f} h ago)  "
            f"{state[g['stillBlocked']]}  incidents {', '.join(g['incidents'])}"
        )
        lines.extend(f"    {command}" for command in g.get("removal", []))
    lines.append(f"lost (missing before expiry) ({len(result['lost'])}):")
    lines.extend(
        f"- {g['cidr']}  expires {g['latestExpiry']}  incidents {', '.join(g['incidents'])}"
        for g in result["lost"]
    )
    lines.append(f"orphans (in the IP set, no incident row) ({len(result['orphans'])}):")
    lines.extend(f"- {o['entry']}  in {o['ipSetArn']}" for o in result["orphans"])
    return "\n".join(lines)


def main(
    argv: list[str] | None = None,
    clients: Callable[..., Any] = aws.client,
    now: datetime | None = None,
) -> int:
    parser = argparse.ArgumentParser(description="Audit PB-05 IP blocks (read-only)")
    parser.add_argument("--table", required=True, help="e.g. cloudshield-dev-soar-incidents")
    parser.add_argument("--region", default="us-east-1", help="WAF region (WAF_REGION)")
    parser.add_argument(
        "--ip-set-arn",
        action="append",
        default=[],
        help="also check this IP set for orphans (repeatable; e.g. both PB-05 sets)",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    now = now or datetime.now(UTC)
    result = report(clients, args.table, args.region, now, tuple(args.ip_set_arn))
    if args.format == "json":
        print(json.dumps(result, indent=2, default=str))
    else:
        print(_text(result, now))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
