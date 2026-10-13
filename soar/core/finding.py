"""Finding: the parsed GuardDuty EventBridge event (class model, plan §8.6).

Parsing is strict. Anything the playbooks would act on is validated here, so a
malformed or hostile payload is rejected before any AWS call is made.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

EXFILTRATION_PREFIX = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"
# The only S3 findings that Block Public Access actually remediates (audit A1).
# Data-access findings (Exfiltration:S3/*, Impact:S3/*) by authenticated
# principals are NOT stopped by BPA and must go to an analyst.
S3_EXPOSURE_PREFIX = "Policy:S3/Bucket"

_INSTANCE_ID = re.compile(r"^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$")
_ACCESS_KEY_ID = re.compile(r"^[A-Z0-9]{16,128}$")
_IAM_USER_NAME = re.compile(r"^[\w+=,.@-]{1,64}$")
_BUCKET_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_FINDING_ID = re.compile(r"^[\w.:-]{1,128}$")
_ROLE_ID = re.compile(r"^AROA[A-Z0-9]{8,124}$")


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
class UnknownTarget:
    reason: str


Target = Ec2Target | IamUserTarget | S3BucketTarget | UnknownTarget


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


def _resolve_target(finding_type: str, resource: dict[str, Any]) -> Target:
    resource_type = resource.get("resourceType")

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

        created = detail.get("createdAt")
        return cls(
            id=finding_id,
            type=finding_type,
            severity=float(severity),
            resource_type=resource_type,
            is_sample=_is_sample(detail),
            event_time=parse_time(event.get("time"), "time"),
            created_at=parse_time(created, "detail.createdAt") if created is not None else None,
            target=_resolve_target(finding_type, resource),
        )

    def seconds_since_event(self, now: datetime) -> float:
        """Elapsed time from the EventBridge event, i.e. the running MTTC."""
        return (now - self.event_time).total_seconds()
