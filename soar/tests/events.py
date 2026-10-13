"""GuardDuty EventBridge events for each scenario, shaped like real findings.

Only placeholder identifiers are used (account 123456789012, fake key ids).
"""

from __future__ import annotations

import copy
from typing import Any

ACCOUNT = "123456789012"
EVENT_TIME = "2026-10-14T10:00:00Z"
CREATED_AT = "2026-10-14T09:59:58.123Z"


def _event(
    finding_type: str,
    severity: float,
    resource: dict[str, Any],
    finding_id: str,
    sample: bool | str | None = None,
) -> dict[str, Any]:
    service: dict[str, Any] = {"serviceName": "guardduty", "action": {}}
    if sample is not None:
        service["additionalInfo"] = {"sample": sample}
    return {
        "version": "0",
        "id": "c0ffee00-0000-4000-8000-000000000000",
        "detail-type": "GuardDuty Finding",
        "source": "aws.guardduty",
        "account": ACCOUNT,
        "time": EVENT_TIME,
        "region": "us-east-1",
        "resources": [],
        "detail": {
            "schemaVersion": "2.0",
            "accountId": ACCOUNT,
            "region": "us-east-1",
            "id": finding_id,
            "type": finding_type,
            "severity": severity,
            "createdAt": CREATED_AT,
            "updatedAt": CREATED_AT,
            "resource": resource,
            "service": service,
        },
    }


def portscan(instance_id: str, **kw: Any) -> dict[str, Any]:
    return _event(
        "Recon:EC2/Portscan",
        5.0,
        {
            "resourceType": "Instance",
            "instanceDetails": {"instanceId": instance_id},
        },
        kw.pop("finding_id", "f-pb01-portscan"),
        **kw,
    )


def exfiltration(instance_id: str, **kw: Any) -> dict[str, Any]:
    return _event(
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        8.0,
        {
            "resourceType": "AccessKey",
            "accessKeyDetails": {
                "accessKeyId": "FAKESTSKEYID00000001",
                "principalId": f"AROAEXAMPLEFAKEROLEID:{instance_id}",
                "userName": "cs-dev-report-worker",
                "userType": "AssumedRole",
            },
        },
        kw.pop("finding_id", "f-pb01-exfil"),
        **kw,
    )


def leaked_key(user_name: str, access_key_id: str, **kw: Any) -> dict[str, Any]:
    return _event(
        "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
        8.0,
        {
            "resourceType": "AccessKey",
            "accessKeyDetails": {
                "accessKeyId": access_key_id,
                "principalId": "AIDAEXAMPLEFAKEUSERID",
                "userName": user_name,
                "userType": kw.pop("user_type", "IAMUser"),
            },
        },
        kw.pop("finding_id", "f-pb02-key"),
        **kw,
    )


def public_bucket(bucket_name: str, **kw: Any) -> dict[str, Any]:
    return _event(
        "Policy:S3/BucketBlockPublicAccessDisabled",
        2.0,
        {
            "resourceType": "S3Bucket",
            "s3BucketDetails": [{"name": bucket_name, "type": "Destination"}],
        },
        kw.pop("finding_id", "f-pb03-bucket"),
        **kw,
    )


def router_state(
    event: dict[str, Any], *, allowed: bool = True, dry_run: Any = False
) -> dict[str, Any]:
    """What cs-ir-router passes a playbook as payload.event."""
    state = copy.deepcopy(event)
    state["guard"] = {"decision": {"allowed": allowed, "dry_run": dry_run, "reason": "test"}}
    return state


def payload(action: str, event: dict[str, Any], **kw: Any) -> dict[str, Any]:
    return {"action": action, "event": router_state(event, **kw)}
