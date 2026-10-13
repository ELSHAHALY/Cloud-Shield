"""SafetyGuard: the R2 control in front of every playbook (soar/README.md rules 1-5).

The first matching rule decides. Every path that is not a positive, verified
"in scope" returns allowed=False, and an unreadable dry-run switch counts as
dry-run. IAM enforces the scope tag independently, so a bug here cannot widen
what a playbook may touch.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from botocore.exceptions import ClientError

from core.aws import error_code
from core.config import Settings
from core.finding import (
    Ec2Target,
    Finding,
    IamUserTarget,
    MalformedFindingError,
    S3BucketTarget,
    Target,
    UnknownTarget,
)


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


class TagReader(Protocol):
    """Returns the target's tags, or None if the target does not exist."""

    def tags_for(
        self, target: Ec2Target | IamUserTarget | S3BucketTarget
    ) -> dict[str, str] | None: ...


def read_dry_run(ssm: Any, parameter_name: str) -> bool | None:
    """'true' -> True, 'false' -> False, anything else (or an error) -> None."""
    try:
        value = ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"]
    except (ClientError, KeyError, TypeError):
        return None
    if not isinstance(value, str):
        return None
    return {"true": True, "false": False}.get(value.strip().lower())


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


class SafetyGuard:
    def __init__(
        self, settings: Settings, tags: TagReader, dry_run_reader: Callable[[], bool | None]
    ) -> None:
        self._settings = settings
        self._tags = tags
        self._dry_run_reader = dry_run_reader

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
        return self._scope(finding.target, dry_run)

    def _scope(self, target: Target, dry_run: bool) -> Decision:
        if isinstance(target, UnknownTarget):
            return Decision(False, dry_run, f"unknown resource: {target.reason}")
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
