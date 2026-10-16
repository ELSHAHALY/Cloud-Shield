"""Finding: the parsed GuardDuty EventBridge event (class model, plan §8.6).

Parsing is strict. Anything the playbooks would act on is validated here, so a
malformed or hostile payload is rejected before any AWS call is made.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

EXFILTRATION_PREFIX = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"
# The only S3 findings that Block Public Access actually remediates (audit A1).
# Data-access findings (Exfiltration:S3/*, Impact:S3/*) by authenticated
# principals are NOT stopped by BPA and must go to an analyst.
S3_EXPOSURE_PREFIX = "Policy:S3/Bucket"
# PB-05 (plan §4.2): custom events from the dedicated edge bus. Only this
# source with resourceType IPAddress resolves to an IP target; GuardDuty can
# never produce one.
EDGE_SOURCE = "cloudshield.edge"
IP_RESOURCE_TYPE = "IPAddress"
ECS_RESOURCE_TYPE = "ECSCluster"

_INSTANCE_ID = re.compile(r"^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$")
_ACCESS_KEY_ID = re.compile(r"^[A-Z0-9]{16,128}$")
_IAM_USER_NAME = re.compile(r"^[\w+=,.@-]{1,64}$")
_BUCKET_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_FINDING_ID = re.compile(r"^[\w.:-]{1,128}$")
_ROLE_ID = re.compile(r"^AROA[A-Z0-9]{8,124}$")
_ARN_PREFIX = r"^arn:aws[\w-]*:ecs:[a-z0-9-]+:\d{12}:"
_ECS_TASK_ARN = re.compile(_ARN_PREFIX + r"task/([\w-]{1,255})/[0-9a-f]{32}\Z", re.ASCII)
_ECS_CLUSTER_ARN = re.compile(_ARN_PREFIX + r"cluster/([\w-]{1,255})\Z", re.ASCII)
_ECS_SERVICE_GROUP = re.compile(r"^service:([\w-]{1,255})\Z", re.ASCII)


class MalformedFindingError(ValueError):
    """The event is not a GuardDuty finding this engine can reason about."""


@dataclass(frozen=True)
class Ec2Target:
    instance_id: str
    # Set for InstanceCredentialExfiltration*: the role id (AROA...) whose
    # session was stolen. PB-01 must revoke exactly that role.
    session_role_id: str | None = None


@dataclass(frozen=True)
class IamUserTarget:
    user_name: str
    access_key_id: str


@dataclass(frozen=True)
class S3BucketTarget:
    bucket_name: str


@dataclass(frozen=True)
class EcsTaskTarget:
    cluster_arn: str
    task_arn: str
    # From taskDetails.group ("service:<name>"); None = not a service task,
    # which PB-04 and the guard refuse. Only a hint: the guard and PB-04
    # re-read the live task and cross-check the service's deployments.
    service_name: str | None


@dataclass(frozen=True)
class IpAddressTarget:
    address: str  # canonical form; IPv4-mapped IPv6 is normalised to IPv4
    version: int  # 4 or 6


@dataclass(frozen=True)
class UnknownTarget:
    reason: str


Target = (
    Ec2Target | IamUserTarget | S3BucketTarget | EcsTaskTarget | IpAddressTarget | UnknownTarget
)


def parse_single_ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Exactly one address, or None. No prefixes ("/"), no zone ids ("%"), no
    surrounding whitespace. IPv4-mapped IPv6 (::ffff:a.b.c.d) becomes IPv4, so
    the IPv4 rules and the IPv4 block list apply to it (plan §4.2 rule 2)."""
    if not isinstance(value, str) or not value or len(value) > 45:
        return None
    if "/" in value or "%" in value or value != value.strip():
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def ip_refusal(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Why an address may never be blocked (plan §4.2 rule 3), or None.

    `is_global` is False for private, loopback, link-local, shared (100.64/10)
    and documentation ranges; multicast, unspecified and reserved are checked
    separately because `is_global` does not cover all of them (F25)."""
    if not address.is_global:
        return "address is not globally routable"
    if address.is_multicast:
        return "address is multicast"
    if address.is_unspecified:
        return "address is unspecified"
    if address.is_reserved:
        return "address is reserved"
    return None


def parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise MalformedFindingError(f"{field} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MalformedFindingError(f"{field} is not an ISO 8601 time") from exc
    if parsed.tzinfo is None:
        raise MalformedFindingError(f"{field} has no time zone")
    return parsed.astimezone(UTC)


def iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _dict(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MalformedFindingError(f"{field} is not an object")
    return value


def _is_sample(detail: dict[str, Any]) -> bool:
    service = detail.get("service")
    info = service.get("additionalInfo") if isinstance(service, dict) else None
    sample = info.get("sample") if isinstance(info, dict) else None
    # Fail closed: a string "true" counts as a sample too.
    return sample is True or (isinstance(sample, str) and sample.strip().lower() == "true")


def _resolve_ecs(resource: dict[str, Any]) -> Target:
    cluster = resource.get("ecsClusterDetails")
    if not isinstance(cluster, dict):
        return UnknownTarget("ECS finding without ecsClusterDetails")
    task = cluster.get("taskDetails")
    task_arn = task.get("arn") if isinstance(task, dict) else None
    if not isinstance(task_arn, str):
        return UnknownTarget("ECS finding without a task")
    task_match = _ECS_TASK_ARN.match(task_arn)
    if not task_match:
        return UnknownTarget("ECS finding without a valid task ARN")
    cluster_arn = cluster.get("arn")
    cluster_match = _ECS_CLUSTER_ARN.match(cluster_arn) if isinstance(cluster_arn, str) else None
    if not cluster_match:
        return UnknownTarget("ECS finding without a valid cluster ARN")
    if cluster_match.group(1) != task_match.group(1):
        return UnknownTarget("ECS task ARN does not belong to the finding's cluster")
    # Tags embedded in the finding (cluster or task) are deliberately ignored:
    # the guard reads the live task's tags.
    group = task.get("group")
    group_match = _ECS_SERVICE_GROUP.match(group) if isinstance(group, str) else None
    return EcsTaskTarget(cluster_arn, task_arn, group_match.group(1) if group_match else None)


def _resolve_ip(resource: dict[str, Any]) -> Target:
    details = resource.get("ipAddressDetails")
    if not isinstance(details, dict):
        return UnknownTarget("IP finding without ipAddressDetails")
    present = {k: details[k] for k in ("ipAddressV4", "ipAddressV6") if k in details}
    if len(present) != 1:
        return UnknownTarget("IP finding must name exactly one address")
    field, raw = next(iter(present.items()))
    address = parse_single_ip(raw)
    if address is None:
        return UnknownTarget("IP finding without a single valid address")
    # The declared family must match, except IPv4-mapped IPv6 (normalised to v4).
    raw_is_v6 = ":" in raw
    if (field == "ipAddressV4") == raw_is_v6:
        return UnknownTarget(f"{field} holds an address of the other family")
    return IpAddressTarget(str(address), address.version)


def _resolve_target(source: str, finding_type: str, resource: dict[str, Any]) -> Target:
    resource_type = resource.get("resourceType")

    # PB-05 targets exist only on edge events; any other source naming an
    # IPAddress resource (or an edge event naming anything else) is unknown.
    if source == EDGE_SOURCE or resource_type == IP_RESOURCE_TYPE:
        if source == EDGE_SOURCE and resource_type == IP_RESOURCE_TYPE:
            return _resolve_ip(resource)
        return UnknownTarget(f"source {source!r} with resource type {resource_type!r}")

    if resource_type == ECS_RESOURCE_TYPE:
        return _resolve_ecs(resource)

    # Scenario A: stolen instance-role credentials arrive as resourceType
    # AccessKey, but the target is the instance the session belongs to.
    if finding_type.startswith(EXFILTRATION_PREFIX):
        details = resource.get("accessKeyDetails")
        principal = details.get("principalId") if isinstance(details, dict) else None
        if not isinstance(principal, str) or ":" not in principal:
            return UnknownTarget("exfiltration finding without a role-session principalId")
        role_id, session = principal.split(":", 1)
        if not _INSTANCE_ID.match(session):
            return UnknownTarget("exfiltration session is not an EC2 instance")
        if not _ROLE_ID.match(role_id):
            return UnknownTarget("exfiltration principalId has no valid role id")
        return Ec2Target(session, session_role_id=role_id)

    if resource_type == "Instance":
        details = resource.get("instanceDetails")
        instance_id = details.get("instanceId") if isinstance(details, dict) else None
        if not isinstance(instance_id, str) or not _INSTANCE_ID.match(instance_id):
            return UnknownTarget("instance finding without a valid instanceId")
        return Ec2Target(instance_id)

    if resource_type == "AccessKey":
        details = resource.get("accessKeyDetails")
        if not isinstance(details, dict) or details.get("userType") != "IAMUser":
            return UnknownTarget("access key does not belong to an IAM user")
        user, key = details.get("userName"), details.get("accessKeyId")
        if not isinstance(user, str) or not _IAM_USER_NAME.match(user):
            return UnknownTarget("access key finding without a valid userName")
        if not isinstance(key, str) or not _ACCESS_KEY_ID.match(key):
            return UnknownTarget("access key finding without a valid accessKeyId")
        return IamUserTarget(user, key)

    if resource_type == "S3Bucket":
        buckets = resource.get("s3BucketDetails")
        if not isinstance(buckets, list) or len(buckets) != 1 or not isinstance(buckets[0], dict):
            return UnknownTarget("S3 finding must name exactly one bucket")
        name = buckets[0].get("name")
        if not isinstance(name, str) or not _BUCKET_NAME.match(name):
            return UnknownTarget("S3 finding without a valid bucket name")
        return S3BucketTarget(name)

    return UnknownTarget(f"unsupported resource type {resource_type!r}")


@dataclass(frozen=True)
class Finding:
    source: str  # EventBridge `source` ("" when absent)
    id: str
    type: str
    severity: float
    resource_type: str
    is_sample: bool
    event_time: datetime  # EventBridge `time`: MTTC clock start (ADR-0002 §3)
    created_at: datetime | None  # GuardDuty `createdAt`, kept for audit
    target: Target

    @classmethod
    def from_event(cls, event: Any) -> Finding:
        event = _dict(event, "event")
        detail = _dict(event.get("detail"), "detail")
        resource = _dict(detail.get("resource"), "detail.resource")

        finding_id = detail.get("id")
        if not isinstance(finding_id, str) or not _FINDING_ID.match(finding_id):
            raise MalformedFindingError("detail.id is missing or invalid")
        finding_type = detail.get("type")
        if not isinstance(finding_type, str) or not finding_type:
            raise MalformedFindingError("detail.type is missing")
        severity = detail.get("severity")
        if isinstance(severity, bool) or not isinstance(severity, int | float):
            raise MalformedFindingError("detail.severity is not a number")
        resource_type = resource.get("resourceType")
        if not isinstance(resource_type, str) or not resource_type:
            raise MalformedFindingError("detail.resource.resourceType is missing")

        source = event.get("source")
        source = source if isinstance(source, str) else ""
        created = detail.get("createdAt")
        return cls(
            source=source,
            id=finding_id,
            type=finding_type,
            severity=float(severity),
            resource_type=resource_type,
            is_sample=_is_sample(detail),
            event_time=parse_time(event.get("time"), "time"),
            created_at=parse_time(created, "detail.createdAt") if created is not None else None,
            target=_resolve_target(source, finding_type, resource),
        )

    def seconds_since_event(self, now: datetime) -> float:
        """Elapsed time from the EventBridge event, i.e. the running MTTC."""
        return (now - self.event_time).total_seconds()
