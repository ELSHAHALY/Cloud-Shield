"""In-process mirror of cs-ir-router for `replay --target local` (runs in CI).

It drives the real guard and playbook handlers the way the Step Functions
router does, so a routing or fail-closed regression shows up offline. The
routing order is contract-tested against state-machine.tf in the test suite.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from core.config import Settings
from core.finding import EDGE_SOURCE, EXFILTRATION_PREFIX, S3_EXPOSURE_PREFIX
from core.guard import AwsTagReader, SafetyGuard, read_dry_run, read_never_block
from playbooks.pb01_ec2_isolate import Pb01Ec2Isolate
from playbooks.pb02_iam_key_revoke import Pb02IamKeyRevoke
from playbooks.pb03_s3_restore_bpa import Pb03S3RestoreBpa
from playbooks.pb04_ecs_task_contain import Pb04EcsTaskContain
from playbooks.pb05_waf_ip_block import Pb05WafIpBlock

# Step Functions StringMatches "*:Runtime/*".
_RUNTIME_TYPE = re.compile(r".*:Runtime/.*", re.DOTALL)


def _route(event: dict[str, Any]) -> tuple[str, str] | None:
    """RouteByResource, choice by choice and in order (state-machine.tf
    local.route_choices; tests/route_choices.json is the shared expected
    table). Every type-based choice also requires the matching resourceType
    (audit A5), so the router acts on the same target the guard vetted."""
    detail = event["detail"]
    finding_type = detail.get("type", "")
    resource_type = detail.get("resource", {}).get("resourceType")
    if finding_type.startswith(EXFILTRATION_PREFIX) and resource_type == "AccessKey":
        return "pb01-ec2-isolate", "isolate"
    if resource_type == "Instance":
        return "pb01-ec2-isolate", "isolate"
    if resource_type == "AccessKey":
        return "pb02-iam-key-revoke", "revoke"
    if resource_type == "S3Bucket" and finding_type.startswith(S3_EXPOSURE_PREFIX):
        return "pb03-s3-restore-bpa", "restore"
    # PB04Contain / PB05Block exist in the real router only with enable_pb04 /
    # enable_pb05; here the playbooks refuse when their settings are empty.
    if resource_type == "ECSCluster" and _RUNTIME_TYPE.fullmatch(finding_type):
        return "pb04-ecs-task-contain", "contain"
    if event.get("source") == EDGE_SOURCE and resource_type == "IPAddress":
        return "pb05-waf-ip-block", "block"
    return None


def _record_detected(
    event: dict[str, Any], settings: Settings, clients: Callable[..., Any]
) -> None:
    detail = event["detail"]
    clients("dynamodb").put_item(
        TableName=settings.incidents_table,
        Item={
            "incidentId": {"S": detail["id"]},
            "status": {"S": "DETECTED"},
            "findingType": {"S": detail.get("type", "")},
            "resourceType": {"S": detail.get("resource", {}).get("resourceType", "")},
            "eventTime": {"S": event["time"]},
            "findingCreatedAt": {"S": detail.get("createdAt", event["time"])},
            "executionArn": {"S": "local-replay"},
        },
    )


def run_local(
    event: dict[str, Any],
    settings: Settings,
    clients: Callable[..., Any],
    *,
    clock: Callable[[], datetime] | None = None,
    force_dry_run: bool = False,
) -> dict[str, Any]:
    """`force_dry_run` (scenarios D/E, D20, audit A10): the guard AND the
    playbook read a switch that always says "dry-run", so flipping the SSM
    parameter mid-run can never make a dry-run-only scenario act."""
    clock = clock or (lambda: datetime.now(UTC))

    def ssm_switch() -> bool | None:
        return read_dry_run(clients("ssm"), settings.dry_run_param)

    def always_dry_run() -> bool:
        return True

    dry_run_reader = always_dry_run if force_dry_run else ssm_switch
    guard = SafetyGuard(
        settings,
        AwsTagReader(clients),
        dry_run_reader,
        lambda: read_never_block(clients("ssm"), settings.never_block_param),
    )
    decision = guard.evaluate(event)
    result: dict[str, Any] = {"guard": decision.to_dict()}
    if not decision.allowed:
        result["status"] = "BLOCKED_BY_GUARD"
        return result

    route = _route(event)
    if route is None:
        result["status"] = "NO_PLAYBOOK_ANALYST_REVIEW"
        return result

    # The real router's RecordDetected creates the row and starts the MTTC
    # clock before any playbook runs; mirror that here.
    _record_detected(event, settings, clients)

    name, action = route
    playbooks = {
        "pb01-ec2-isolate": Pb01Ec2Isolate,
        "pb02-iam-key-revoke": Pb02IamKeyRevoke,
        "pb03-s3-restore-bpa": Pb03S3RestoreBpa,
        "pb04-ecs-task-contain": Pb04EcsTaskContain,
        "pb05-waf-ip-block": Pb05WafIpBlock,
    }
    playbook = playbooks[name](
        settings, clients, clock, dry_run_reader=always_dry_run if force_dry_run else None
    )
    state = {**event, "guard": {"decision": decision.to_dict()}}
    containment = playbook.handle({"action": action, "event": state})
    result["playbook"] = name
    result["containment"] = containment

    if not decision.dry_run and containment.get("contained") is True:
        result["status"] = "CONTAINED"
    elif decision.dry_run:
        result["status"] = "WOULD_CONTAIN_DRY_RUN"
    else:
        result["status"] = "FAILED"
    return result
