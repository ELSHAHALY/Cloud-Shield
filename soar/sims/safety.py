"""Risk R4 safety gates. Every simulation passes these before any AWS call.

Rules (attack-sim/README.md):
1. the caller's account must be in the allow-list;
2. the region must be the lab region;
3. every target must carry the SOAR scope tag AND the name prefix;
4. live mode must re-confirm the account id;
5. no external hosts are ever targeted (enforced by construction: sims only
   ever name resources they looked up in this account).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


class SafetyError(RuntimeError):
    """A safety gate refused to let the simulation run."""


@dataclass(frozen=True)
class LabContext:
    account_id: str
    region: str
    name_prefix: str  # e.g. "cloudshield-dev-"
    scope_tag_key: str
    scope_tag_value: str


def require_lab(
    clients: Callable[..., Any],
    allowed_accounts: list[str],
    region: str,
    name_prefix: str,
    *,
    scope_tag_key: str = "cloudshield:soar-scope",
    scope_tag_value: str = "in-scope",
    live: bool = False,
    confirm_account: str | None = None,
) -> LabContext:
    if not allowed_accounts:
        raise SafetyError("no --allowed-account given; refusing to run anywhere")
    identity = clients("sts").get_caller_identity()
    account = identity["Account"]
    if account not in allowed_accounts:
        raise SafetyError(f"account {account} is not in the allow-list {allowed_accounts}")

    caller_region = clients("sts").meta.region_name
    # Fail closed: an unresolved region must not pass the gate (audit A2).
    if not caller_region:
        raise SafetyError("client has no resolved region; set AWS_REGION to the lab region")
    if caller_region != region:
        raise SafetyError(f"client region {caller_region} is not the lab region {region}")

    if live and confirm_account != account:
        raise SafetyError("live mode requires --confirm-live <account-id> matching the caller")

    if not name_prefix:
        raise SafetyError("a name prefix is required so targets can't be account-wide")

    return LabContext(account, region, name_prefix, scope_tag_key, scope_tag_value)


def assert_in_scope(
    ctx: LabContext, resource_name: str, tags: dict[str, str], *, require_prefix: bool = True
) -> None:
    """A target is safe only with the SOAR scope tag (always), and the name
    prefix for name-identified resources (buckets, IAM users). EC2 instances
    are identified by an opaque id, so there the tag is the sole marker."""
    if require_prefix and not resource_name.startswith(ctx.name_prefix):
        raise SafetyError(f"{resource_name} is outside the lab prefix {ctx.name_prefix!r}")
    if tags.get(ctx.scope_tag_key) != ctx.scope_tag_value:
        raise SafetyError(f"{resource_name} lacks {ctx.scope_tag_key}={ctx.scope_tag_value}")


def read_target_tags(clients: Callable[..., Any], kind: str, name: str) -> dict[str, str]:
    """Read a target's tags with read-only describes (never mutates)."""
    from botocore.exceptions import ClientError

    if kind == "instance":
        try:
            reservations = clients("ec2").describe_instances(InstanceIds=[name])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "").startswith("InvalidInstanceID"):
                raise SafetyError(f"instance {name} not found in this account") from exc
            raise
        instances = [
            i for r in reservations.get("Reservations", []) for i in r.get("Instances", [])
        ]
        if len(instances) != 1:
            raise SafetyError(f"instance {name} not found in this account")
        return {t["Key"]: t["Value"] for t in instances[0].get("Tags", [])}
    if kind == "user":
        tags: dict[str, str] = {}
        for page in clients("iam").get_paginator("list_user_tags").paginate(UserName=name):
            tags.update({t["Key"]: t["Value"] for t in page.get("Tags", [])})
        return tags
    if kind == "bucket":
        try:
            tag_set = clients("s3").get_bucket_tagging(Bucket=name)["TagSet"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "NoSuchTagSet":
                return {}
            raise
        return {t["Key"]: t["Value"] for t in tag_set}
    raise SafetyError(f"unknown target kind {kind!r}")


def verify_targets(ctx: LabContext, clients: Callable[..., Any], targets: dict[str, str]) -> None:
    """Rule 3, enforced before any mutating call: every named target must be
    in scope (read its live tags first). `targets` maps kind -> identifier."""
    for kind, name in targets.items():
        tags = read_target_tags(clients, kind, name)
        # Instance ids are not name-prefixed; buckets and users are.
        assert_in_scope(ctx, name, tags, require_prefix=(kind != "instance"))
