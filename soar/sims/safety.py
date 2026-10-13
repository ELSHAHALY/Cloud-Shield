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
    if caller_region and caller_region != region:
        raise SafetyError(f"client region {caller_region} is not the lab region {region}")

    if live and confirm_account != account:
        raise SafetyError("live mode requires --confirm-live <account-id> matching the caller")

    if not name_prefix:
        raise SafetyError("a name prefix is required so targets can't be account-wide")

    return LabContext(account, region, name_prefix, scope_tag_key, scope_tag_value)


def assert_in_scope(ctx: LabContext, resource_name: str, tags: dict[str, str]) -> None:
    """A target is safe only with the name prefix AND the scope tag."""
    if not resource_name.startswith(ctx.name_prefix):
        raise SafetyError(f"{resource_name} is outside the lab prefix {ctx.name_prefix!r}")
    if tags.get(ctx.scope_tag_key) != ctx.scope_tag_value:
        raise SafetyError(f"{resource_name} lacks {ctx.scope_tag_key}={ctx.scope_tag_value}")
