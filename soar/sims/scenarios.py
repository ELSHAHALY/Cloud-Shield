"""GuardDuty EventBridge events for replay, built for REAL lab targets.

These are the same shape the detection pipeline delivers. `time` is set to now
by the caller. The MITRE technique and the playbook each scenario exercises are
recorded alongside, so a run report can cite them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class Scenario:
    key: str
    name: str
    attack_techniques: tuple[str, ...]
    finding_type: str
    resource_type: str
    expected_playbook: str


SCENARIOS: dict[str, Scenario] = {
    "a": Scenario(
        "a",
        "EC2 IMDS credential theft + recon",
        ("T1552.005", "T1046"),
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "AccessKey",
        "pb01-ec2-isolate",
    ),
    "a-recon": Scenario(
        "a-recon", "EC2 port scan", ("T1046",), "Recon:EC2/Portscan", "Instance", "pb01-ec2-isolate"
    ),
    "b": Scenario(
        "b",
        "Leaked honeytoken IAM key",
        ("T1078", "T1552.001"),
        "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
        "AccessKey",
        "pb02-iam-key-revoke",
    ),
    "c": Scenario(
        "c",
        "Public S3 exposure",
        ("T1530",),
        "Policy:S3/BucketBlockPublicAccessDisabled",
        "S3Bucket",
        "pb03-s3-restore-bpa",
    ),
    # D and E are replay-local fixtures only, and only while dry-run is on (D20).
    "d": Scenario(
        "d",
        "ECS runtime compromise",
        ("T1610", "T1059"),
        "Execution:Runtime/NewBinaryExecuted",
        "ECSCluster",
        "pb04-ecs-task-contain",
    ),
    "e": Scenario(
        "e",
        "Edge IP abuse",
        ("T1190", "T1595"),
        "CloudShield:IPAddress/WafRateLimitExceeded",
        "IPAddress",
        "pb05-waf-ip-block",
    ),
}

# Scenarios that never act on a real account (D20).
DRY_RUN_ONLY = frozenset({"d", "e"})

EDGE_SOURCE = "cloudshield.edge"
_TASK_ARN = re.compile(
    r"^(arn:aws[\w-]*:ecs:[a-z0-9-]+:\d{12}:)task/([\w-]{1,255})/[0-9a-f]{32}\Z", re.ASCII
)


def cluster_arn_of(task_arn: str) -> str | None:
    """The cluster ARN a (new-format) task ARN belongs to, or None."""
    match = _TASK_ARN.match(task_arn)
    return f"{match.group(1)}cluster/{match.group(2)}" if match else None


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _envelope(
    detail: dict[str, Any],
    account: str,
    region: str,
    now: datetime,
    *,
    source: str = "aws.guardduty",
    detail_type: str = "GuardDuty Finding",
) -> dict[str, Any]:
    return {
        "version": "0",
        "id": f"sim-{int(now.timestamp() * 1000)}",
        "detail-type": detail_type,
        "source": source,
        "account": account,
        "time": _iso(now),
        "region": region,
        "resources": [],
        "detail": detail,
    }


def build_event(
    scenario: Scenario,
    account: str,
    region: str,
    *,
    now: datetime | None = None,
    instance_id: str | None = None,
    role_id: str | None = None,
    user_name: str | None = None,
    access_key_id: str | None = None,
    bucket_name: str | None = None,
    task_arn: str | None = None,
    service_name: str | None = None,
    ip: str | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(UTC)
    if scenario.resource_type == "IPAddress":
        return _edge_event(scenario, account, region, now, ip)
    base = {
        "schemaVersion": "2.0",
        "accountId": account,
        "region": region,
        "id": f"sim-{scenario.key}-{int(now.timestamp())}",
        "type": scenario.finding_type,
        "severity": 2.0 if scenario.key == "c" else 8.0,
        "createdAt": _iso(now),
        "updatedAt": _iso(now),
        "service": {"serviceName": "guardduty", "additionalInfo": {"sample": False}},
    }

    if scenario.resource_type == "AccessKey" and scenario.key.startswith("a"):
        if not (instance_id and role_id):
            raise ValueError("scenario A needs instance_id and role_id")
        base["resource"] = {
            "resourceType": "AccessKey",
            "accessKeyDetails": {
                "accessKeyId": "ASIASIMROLEKEY01",
                "principalId": f"{role_id}:{instance_id}",
                "userName": "sim-role-session",
                "userType": "AssumedRole",
            },
        }
    elif scenario.resource_type == "Instance":
        if not instance_id:
            raise ValueError("scenario A recon needs instance_id")
        base["resource"] = {
            "resourceType": "Instance",
            "instanceDetails": {"instanceId": instance_id},
        }
    elif scenario.resource_type == "AccessKey":
        if not (user_name and access_key_id):
            raise ValueError("scenario B needs user_name and access_key_id")
        base["resource"] = {
            "resourceType": "AccessKey",
            "accessKeyDetails": {
                "accessKeyId": access_key_id,
                "principalId": "AIDASIMHONEYTOKEN",
                "userName": user_name,
                "userType": "IAMUser",
            },
        }
    elif scenario.resource_type == "ECSCluster":
        cluster = cluster_arn_of(task_arn or "")
        if not (cluster and service_name):
            raise ValueError("scenario D needs a task_arn (new ARN format) and service_name")
        base["resource"] = {
            "resourceType": "ECSCluster",
            "ecsClusterDetails": {
                "arn": cluster,
                "name": cluster.rsplit("/", 1)[-1],
                "taskDetails": {"arn": task_arn, "group": f"service:{service_name}"},
            },
        }
    else:  # S3Bucket
        if not bucket_name:
            raise ValueError("scenario C needs bucket_name")
        base["resource"] = {
            "resourceType": "S3Bucket",
            "s3BucketDetails": [{"name": bucket_name, "type": "Destination"}],
        }

    return _envelope(base, account, region, now)


def _edge_event(
    scenario: Scenario, account: str, region: str, now: datetime, ip: str | None
) -> dict[str, Any]:
    """Scenario E: the harvester's event shape (plan §4.2), source cloudshield.edge."""
    if not ip:
        raise ValueError("scenario E needs ip (no default)")
    family = "ipAddressV6" if ":" in ip else "ipAddressV4"
    normalised = re.sub(r"[^0-9A-Za-z]", "-", ip)
    detail = {
        "schemaVersion": "2.0",
        "accountId": account,
        "region": region,
        "id": f"sim-e-{normalised}-{int(now.timestamp())}",
        "type": scenario.finding_type,
        "severity": 5.0,
        "createdAt": _iso(now),
        "resource": {"resourceType": "IPAddress", "ipAddressDetails": {family: ip}},
        "service": {
            "serviceName": "cloudshield",
            "additionalInfo": {"sample": False, "publisher": "sim-runner"},
        },
    }
    return _envelope(
        detail, account, region, now, source=EDGE_SOURCE, detail_type="CloudShield Edge Finding"
    )
