"""SafetyGuard: the R2 control in front of every playbook (soar/README.md rules 1-5).

The first matching rule decides. Every path that is not a positive, verified
"in scope" returns allowed=False, and an unreadable dry-run switch counts as
dry-run. IAM enforces the scope tag independently, so a bug here cannot widen
what a playbook may touch.

Rule 3 has two Phase D branches (plan §4.1, §4.2):

* ECS task (PB-04): the LIVE task (DescribeTasks in OUR cluster) must carry
  the scope tag, sit in ECS_CLUSTER_ARN and belong to an allowed service.
  Tags embedded in the finding are never trusted.
* IP address (PB-05), which has no tags: the event must come from the edge
  source, carry an allow-listed edge finding type and be fresh, the address
  must be global unicast, and it must not be on the never-block list, which
  is read on every call (unreadable -> refuse).

The guard only sees what the caller wrote. Anyone who can start cs-ir-router
can write a "fresh edge event", so PB-05 itself re-reads the never-block list
and corroborates the address with WAF (the rate rule's managed keys) before it
blocks anything (audit A1).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from botocore.exceptions import ClientError

from core.aws import error_code
from core.config import Settings
from core.finding import (
    EDGE_FINDING_TYPES,
    Ec2Target,
    EcsTaskTarget,
    Finding,
    IamUserTarget,
    IpAddressTarget,
    MalformedFindingError,
    S3BucketTarget,
    UnknownTarget,
    ip_refusal,
    parse_single_ip,
)

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

# Edge events (F24): EventBridge stamps `time` on receipt and the harvester
# never sets it, but a replayed or hand-started execution could carry any value.
EDGE_MAX_AGE = timedelta(minutes=15)
EDGE_MAX_FUTURE = timedelta(seconds=60)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    dry_run: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        # Real booleans only: the router fails closed on anything else.
        return {
            "allowed": self.allowed is True,
            "dry_run": self.dry_run is not False,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class LiveTask:
    """What DescribeTasks says about a task right now."""

    cluster_arn: str
    group: str
    tags: dict[str, str]


class TagReader(Protocol):
    """Live lookups of the target. None = the target does not exist."""

    def tags_for(
        self, target: Ec2Target | IamUserTarget | S3BucketTarget
    ) -> dict[str, str] | None: ...

    def ecs_task(self, cluster_arn: str, task_arn: str) -> LiveTask | None: ...


def read_dry_run(ssm: Any, parameter_name: str) -> bool | None:
    """'true' -> True, 'false' -> False, anything else (or an error) -> None."""
    try:
        value = ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"]
    except (ClientError, KeyError, TypeError):
        return None
    if not isinstance(value, str):
        return None
    return {"true": True, "false": False}.get(value.strip().lower())


def read_never_block(ssm: Any, parameter_name: str) -> tuple[Network, ...] | None:
    """The PB-05 never-block CIDRs, or None when the list cannot be trusted:
    unset, unreadable, empty, or containing ANY entry that is not a CIDR."""
    if not parameter_name:
        return None
    try:
        value = ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"]
    except (ClientError, KeyError, TypeError):
        return None
    if not isinstance(value, str):
        return None
    networks: list[Network] = []
    for entry in (item.strip() for item in value.split(",")):
        if not entry:
            continue
        if "/" not in entry:
            return None
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            return None
    return tuple(networks) or None


class AwsTagReader:
    """Reads tags with exactly the permissions the safety_guard role has."""

    _NOT_FOUND = frozenset(
        {
            "InvalidInstanceID.NotFound",
            "InvalidInstanceID.Malformed",
            "NoSuchEntity",
            "NoSuchBucket",
        }
    )

    def __init__(self, clients: Callable[[str], Any]) -> None:
        self._clients = clients

    def tags_for(self, target: Ec2Target | IamUserTarget | S3BucketTarget) -> dict[str, str] | None:
        try:
            if isinstance(target, Ec2Target):
                return self._instance(target.instance_id)
            if isinstance(target, IamUserTarget):
                return self._user(target.user_name)
            return self._bucket(target.bucket_name)
        except ClientError as exc:
            if error_code(exc) in self._NOT_FOUND:
                return None
            raise

    def ecs_task(self, cluster_arn: str, task_arn: str) -> LiveTask | None:
        """The live task, looked up in OUR cluster only: a task ARN from
        another cluster comes back as a MISSING failure, i.e. None."""
        response = self._clients("ecs").describe_tasks(
            cluster=cluster_arn, tasks=[task_arn], include=["TAGS"]
        )
        tasks = [t for t in response.get("tasks", []) if t.get("taskArn") == task_arn]
        if len(tasks) != 1:
            return None
        task = tasks[0]
        return LiveTask(
            cluster_arn=str(task.get("clusterArn", "")),
            group=str(task.get("group", "")),
            tags={t["key"]: t["value"] for t in task.get("tags", [])},
        )

    def _instance(self, instance_id: str) -> dict[str, str] | None:
        reservations = self._clients("ec2").describe_instances(InstanceIds=[instance_id])
        instances = [
            i for r in reservations.get("Reservations", []) for i in r.get("Instances", [])
        ]
        if len(instances) != 1:
            return None
        return {t["Key"]: t["Value"] for t in instances[0].get("Tags", [])}

    def _user(self, user_name: str) -> dict[str, str]:
        tags: dict[str, str] = {}
        for page in (
            self._clients("iam").get_paginator("list_user_tags").paginate(UserName=user_name)
        ):
            tags.update({t["Key"]: t["Value"] for t in page.get("Tags", [])})
        return tags

    def _bucket(self, bucket_name: str) -> dict[str, str]:
        try:
            tag_set = self._clients("s3").get_bucket_tagging(Bucket=bucket_name)["TagSet"]
        except ClientError as exc:
            if error_code(exc) == "NoSuchTagSet":
                return {}
            raise
        return {t["Key"]: t["Value"] for t in tag_set}


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _no_never_block() -> tuple[Network, ...] | None:
    return None


class SafetyGuard:
    def __init__(
        self,
        settings: Settings,
        tags: TagReader,
        dry_run_reader: Callable[[], bool | None],
        never_block_reader: Callable[[], tuple[Network, ...] | None] = _no_never_block,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._settings = settings
        self._tags = tags
        self._dry_run_reader = dry_run_reader
        self._never_block_reader = never_block_reader
        self._clock = clock

    def evaluate(self, event: Any) -> Decision:
        # Rule 1: read the switch on EVERY call; unreadable -> blocked.
        dry_run = self._dry_run_reader()
        if dry_run is None:
            return Decision(False, True, "dry-run switch unreadable")

        try:
            finding = Finding.from_event(event)
        except MalformedFindingError as exc:
            return Decision(False, dry_run, f"malformed finding: {exc}")

        # Rule 2: sample findings point at fake resources that can never carry
        # the tag, so in dry-run they skip rule 3; live, they are refused.
        if finding.is_sample:
            if dry_run:
                return Decision(True, True, "sample finding (dry-run only)")
            return Decision(False, False, "sample finding")

        # Rules 3 and 4.
        return self._scope(finding, dry_run)

    def _scope(self, finding: Finding, dry_run: bool) -> Decision:
        target = finding.target
        if isinstance(target, UnknownTarget):
            return Decision(False, dry_run, f"unknown resource: {target.reason}")
        if isinstance(target, EcsTaskTarget):
            return self._ecs(target, dry_run)
        if isinstance(target, IpAddressTarget):
            return self._ip(finding, target, dry_run)
        if isinstance(target, S3BucketTarget) and not target.bucket_name.startswith(
            self._settings.bucket_name_prefix
        ):
            return Decision(False, dry_run, "bucket outside the project name prefix")

        tags = self._tags.tags_for(target)
        if tags is None:
            return Decision(False, dry_run, "target not found")
        if tags.get(self._settings.scope_tag_key) != self._settings.scope_tag_value:
            return Decision(False, dry_run, "target lacks the SOAR scope tag")
        return Decision(True, dry_run, "target in scope")

    # ------------------------------------------------------- ECS (PB-04)
    def _ecs(self, target: EcsTaskTarget, dry_run: bool) -> Decision:
        settings = self._settings
        if not settings.ecs_cluster_arn or not settings.ecs_service_names:
            return Decision(False, dry_run, "ECS containment is not configured")
        if target.service_name is None:
            return Decision(False, dry_run, "task was not launched by a service")
        if target.cluster_arn != settings.ecs_cluster_arn:
            return Decision(False, dry_run, "task outside the SOAR cluster")
        if target.service_name not in settings.ecs_service_names:
            return Decision(
                False, dry_run, f"service {target.service_name} is not allowed for PB-04"
            )

        live = self._tags.ecs_task(settings.ecs_cluster_arn, target.task_arn)
        if live is None:
            return Decision(False, dry_run, "target not found")
        if live.cluster_arn != settings.ecs_cluster_arn:
            return Decision(False, dry_run, "task outside the SOAR cluster")
        if live.group != f"service:{target.service_name}":
            return Decision(False, dry_run, "live task group does not match")
        if live.tags.get(settings.scope_tag_key) != settings.scope_tag_value:
            return Decision(False, dry_run, "target lacks the SOAR scope tag")
        return Decision(True, dry_run, "target in scope")

    # -------------------------------------------------------- IP (PB-05)
    def _ip(self, finding: Finding, target: IpAddressTarget, dry_run: bool) -> Decision:
        settings = self._settings
        if not settings.edge_event_source or not settings.never_block_param:
            return Decision(False, dry_run, "IP blocking is not configured")
        # Rule 1: edge source, fresh event.
        if finding.source != settings.edge_event_source:
            return Decision(False, dry_run, "event is not from the edge source")
        # Only edge finding types PB-05 knows how to corroborate (audit A1).
        if finding.type not in EDGE_FINDING_TYPES:
            return Decision(False, dry_run, "edge finding type is not allowed")
        now = self._clock()
        if not now - EDGE_MAX_AGE <= finding.event_time <= now + EDGE_MAX_FUTURE:
            return Decision(False, dry_run, "edge event outside the freshness window")
        # Rule 2 ran in Finding (exactly one address; IPv4-mapped IPv6
        # normalised). Re-parse the canonical form rather than trust it.
        address = parse_single_ip(target.address)
        if address is None:  # pragma: no cover - Finding only builds valid targets
            return Decision(False, dry_run, "address does not parse")
        # Rule 3: global unicast only.
        refusal = ip_refusal(address)
        if refusal is not None:
            return Decision(False, dry_run, refusal)
        # Rule 4: the never-block list, read on EVERY call; unreadable -> refuse.
        never_block = self._never_block_reader()
        if not never_block:
            return Decision(False, dry_run, "never-block list unreadable")
        if any(address in network for network in never_block):
            return Decision(False, dry_run, "address is on the never-block list")
        return Decision(True, dry_run, "address may be blocked")
