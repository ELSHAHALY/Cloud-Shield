"""PB-04: compromised ECS task containment (scenario D).

ECS is driven through botocore's Stubber, not moto: moto 5.2 gives tasks UUID
ids (real ECS uses 32 hex), never moves containers past PENDING, and has no
DEPROVISIONING state, so none of PB-04's verification semantics (F21) could
be exercised. The Stubber still validates every request and response against
the ECS API model, and it enforces call ORDER, which is what "capture before
StopTask" and "cross-check before StopTask" need. DynamoDB, SSM and S3 (row,
dry-run switch, evidence) are moto, as for PB-01..03.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
import pytest
from botocore.stub import ANY, Stubber

from core.config import Settings
from core.playbook import PlaybookError
from playbooks.pb04_ecs_task_contain import Pb04EcsTaskContain, lambda_handler
from tests import events
from tests.conftest import EVIDENCE_BUCKET, EXECUTION_ARN, NOW, SCOPE_KEY, SCOPE_VALUE

CLUSTER, TASK, SERVICE = events.CLUSTER_ARN, events.TASK_ARN, events.SERVICE_NAME
TASK_DEF = f"arn:aws:ecs:us-east-1:{events.ACCOUNT}:task-definition/cs-dev-app:3"
OLD_DEPLOYMENT = events.DEPLOYMENT_ID
NEW_DEPLOYMENT = "ecs-svc/2222222222222222222"
SCOPE = [{"key": SCOPE_KEY, "value": SCOPE_VALUE}]
DIGEST = "sha256:" + "a" * 64
EVENT_AT = datetime(2026, 10, 14, 10, 0, 0, tzinfo=UTC)


# ------------------------------------------------------------- responses
def task(
    *,
    desired: str = "RUNNING",
    last: str = "RUNNING",
    containers: tuple[str, ...] = ("RUNNING",),
    tags: list[dict[str, str]] | None = None,
    group: str = f"service:{SERVICE}",
    started_by: str = OLD_DEPLOYMENT,
    cluster: str = CLUSTER,
) -> dict[str, Any]:
    return {
        "tasks": [
            {
                "taskArn": TASK,
                "clusterArn": cluster,
                "taskDefinitionArn": TASK_DEF,
                "group": group,
                "startedBy": started_by,
                "startedAt": datetime(2026, 10, 14, 9, 0, tzinfo=UTC),
                "launchType": "FARGATE",
                "platformVersion": "1.4.0",
                "availabilityZone": "us-east-1a",
                "desiredStatus": desired,
                "lastStatus": last,
                "containers": [
                    {
                        "name": f"docs-api-{i}",
                        "image": f"123456789012.dkr.ecr.us-east-1.amazonaws.com/app@{DIGEST}",
                        "imageDigest": DIGEST,
                        "lastStatus": status,
                        "runtimeId": f"{events.TASK_ID}-{i}",
                    }
                    for i, status in enumerate(containers)
                ],
                "attachments": [
                    {
                        "id": "att-1",
                        "type": "ElasticNetworkInterface",
                        "status": "ATTACHED",
                        "details": [
                            {"name": "subnetId", "value": "subnet-0aaaaaaaaaaaaaaaa"},
                            {"name": "networkInterfaceId", "value": "eni-0bbbbbbbbbbbbbbbb"},
                            {"name": "privateIPv4Address", "value": "10.20.10.25"},
                        ],
                    }
                ],
                "tags": SCOPE if tags is None else tags,
            }
        ],
        "failures": [],
    }


def deployment(dep_id: str, status: str, created: datetime) -> dict[str, Any]:
    return {"id": dep_id, "status": status, "taskDefinition": TASK_DEF, "createdAt": created}


OLD = deployment(OLD_DEPLOYMENT, "PRIMARY", datetime(2026, 10, 1, tzinfo=UTC))
OLD_ACTIVE = deployment(OLD_DEPLOYMENT, "ACTIVE", datetime(2026, 10, 1, tzinfo=UTC))
NEW = deployment(NEW_DEPLOYMENT, "PRIMARY", NOW + timedelta(seconds=1))


def service(
    deployments: list[dict[str, Any]] | None = None, tags: list[dict[str, str]] | None = None
) -> dict[str, Any]:
    return {
        "services": [
            {
                "serviceName": SERVICE,
                "clusterArn": CLUSTER,
                "status": "ACTIVE",
                "deployments": [OLD] if deployments is None else deployments,
                "tags": SCOPE if tags is None else tags,
            }
        ],
        "failures": [],
    }


TASK_DEF_RESPONSE = {
    "taskDefinition": {
        "taskDefinitionArn": TASK_DEF,
        "containerDefinitions": [
            {
                "name": "docs-api",
                "image": f"app@{DIGEST}",
                "environment": [{"name": "APP_ENV", "value": "dev"}],
                "stopTimeout": 2,
            }
        ],
    }
}


class Ecs:
    """A Stubber-backed ECS client that also logs the operations called."""

    def __init__(self) -> None:
        self.client = boto3.client("ecs", region_name="us-east-1")
        self.stub = Stubber(self.client)
        self.ops: list[str] = []
        self.client.meta.events.register(
            "provide-client-params.ecs.*", lambda model, **_: self.ops.append(model.name)
        )

    def describe_task(self, response: dict[str, Any], *, tags: bool = True) -> None:
        params: dict[str, Any] = {"cluster": CLUSTER, "tasks": [TASK]}
        if tags:
            params["include"] = ["TAGS"]
        self.stub.add_response("describe_tasks", response, params)

    def describe_service(self, response: dict[str, Any]) -> None:
        self.stub.add_response(
            "describe_services",
            response,
            {"cluster": CLUSTER, "services": [SERVICE], "include": ["TAGS"]},
        )

    def describe_task_definition(self) -> None:
        self.stub.add_response(
            "describe_task_definition", TASK_DEF_RESPONSE, {"taskDefinition": TASK_DEF}
        )

    def stop(self) -> None:
        self.stub.add_response(
            "stop_task",
            {"task": {"taskArn": TASK, "desiredStatus": "STOPPED"}},
            {"cluster": CLUSTER, "task": TASK, "reason": "cloudshield-soar f-pb04-task"},
        )

    def redeploy(self, deployments: list[dict[str, Any]] | None = None) -> None:
        self.stub.add_response(
            "update_service",
            {"service": {"serviceName": SERVICE, "deployments": deployments or [NEW, OLD_ACTIVE]}},
            {"cluster": CLUSTER, "service": SERVICE, "forceNewDeployment": True},
        )

    def verify_round(self, task_response: dict[str, Any], service_response: dict[str, Any]) -> None:
        self.describe_task(task_response, tags=False)
        self.describe_service(service_response)

    def prologue(
        self,
        task_response: dict[str, Any] | None = None,
        service_response: dict[str, Any] | None = None,
    ) -> None:
        """The reads before any mutation: scope + cross-check + capture."""
        self.describe_task(task_response or task())
        self.describe_service(service_response or service())
        self.describe_task_definition()


STOPPED = task(desired="STOPPED", last="DEPROVISIONING", containers=("STOPPED",))
REDEPLOYED = service([NEW, OLD_ACTIVE])


def settings(world: Any, **extra: str) -> Settings:
    return Settings.from_env(
        {**world.env, "ECS_CLUSTER_ARN": CLUSTER, "ECS_SERVICE_NAMES": SERVICE, **extra}
    )


def pb04(world: Any, ecs: Ecs, recorder: list[tuple[str, str]] | None = None) -> Any:
    def clients(service_name: str, **kw: Any) -> Any:
        real = ecs.client if service_name == "ecs" else boto3.client(service_name, **kw)
        if recorder is None:
            return real

        class Proxy:
            def __getattr__(self, name: str) -> Any:
                attr = getattr(real, name)
                if callable(attr):

                    def wrapped(*a: Any, **k: Any) -> Any:
                        recorder.append((service_name, name))
                        return attr(*a, **k)

                    return wrapped
                return attr

        return Proxy()

    ecs.stub.activate()
    return Pb04EcsTaskContain(settings(world), clients, lambda: NOW, sleep=lambda _: None)


def seed(world: Any) -> dict[str, Any]:
    event = events.ecs_runtime()
    world.seed_incident(event["detail"]["id"])
    return event


# ------------------------------------------------------------ happy path
def test_contain_stops_task_redeploys_and_verifies(world: Any) -> None:
    event = seed(world)
    ecs = Ecs()
    ecs.prologue()
    ecs.stop()
    ecs.redeploy()
    ecs.verify_round(STOPPED, REDEPLOYED)

    result = pb04(world, ecs).handle(events.payload("contain", event))

    ecs.stub.assert_no_pending_responses()
    assert result["contained"] is True
    assert result["verified"] == {
        "taskStopped": True,
        "newDeploymentPrimary": True,
        "serviceInScope": True,
    }
    assert result["taskStop"] == "requested"
    assert result["deployment"] == NEW_DEPLOYMENT
    # Capture strictly BEFORE StopTask, cross-check strictly before too.
    assert ecs.ops.index("DescribeTaskDefinition") < ecs.ops.index("StopTask")
    assert ecs.ops.index("DescribeServices") < ecs.ops.index("StopTask")
    assert ecs.ops.index("StopTask") < ecs.ops.index("UpdateService")
    row = world.incident(event["detail"]["id"])
    assert [a["step"] for a in row["actions"]] == ["capture-prestate", "stop-task", "redeploy"]
    assert row["containmentVerified"] is True
    # No evidence write inside the MTTC window.
    assert boto3.client("s3").list_objects_v2(Bucket=EVIDENCE_BUCKET).get("KeyCount", 0) == 0


def test_prestate_content_and_json_safety(world: Any) -> None:
    event = seed(world)
    ecs = Ecs()
    ecs.prologue()
    ecs.stop()
    ecs.redeploy()
    ecs.verify_round(STOPPED, REDEPLOYED)

    prestate = pb04(world, ecs).handle(events.payload("contain", event))["prestate"]

    json.dumps(prestate)  # Step Functions passes it on: no datetimes, no bytes
    assert prestate["schema"] == "cloudshield.evidence.ecs-task.v1"
    assert prestate["task"]["taskDefinitionArn"] == TASK_DEF
    assert prestate["task"]["startedBy"] == OLD_DEPLOYMENT
    assert prestate["task"]["startedAt"].startswith("2026-10-14 09:00:00")
    assert prestate["task"]["lastStatus"] == "RUNNING"  # the state BEFORE StopTask
    assert prestate["task"]["containers"][0]["imageDigest"] == DIGEST
    assert prestate["task"]["networkInterfaces"] == [
        {
            "networkInterfaceId": "eni-0bbbbbbbbbbbbbbbb",
            "privateIPv4Address": "10.20.10.25",
            "subnetId": "subnet-0aaaaaaaaaaaaaaaa",
        }
    ]
    assert prestate["taskDefinition"]["containerDefinitions"][0]["stopTimeout"] == 2


def test_verify_polls_until_processes_are_dead(world: Any) -> None:
    event = seed(world)
    ecs = Ecs()
    ecs.prologue()
    ecs.stop()
    ecs.redeploy()
    # STOPPING with a live container is NOT contained; DEPROVISIONING with
    # every container STOPPED is (only the ENI is still detaching, F21).
    ecs.verify_round(task(desired="STOPPED", last="STOPPING", containers=("RUNNING",)), REDEPLOYED)
    ecs.verify_round(
        task(desired="STOPPED", last="STOPPING", containers=("STOPPED", "RUNNING")), REDEPLOYED
    )
    ecs.verify_round(STOPPED, REDEPLOYED)

    result = pb04(world, ecs).handle(events.payload("contain", event))

    assert result["contained"] is True
    ecs.stub.assert_no_pending_responses()


def test_fully_stopped_task_counts(world: Any) -> None:
    event = seed(world)
    ecs = Ecs()
    ecs.prologue()
    ecs.stop()
    ecs.redeploy()
    ecs.verify_round(task(desired="STOPPED", last="STOPPED", containers=("STOPPED",)), REDEPLOYED)
    assert pb04(world, ecs).handle(events.payload("contain", event))["contained"] is True


@pytest.mark.parametrize(
    ("task_response", "service_response", "failed"),
    [
        # never stops
        (task(desired="STOPPED", last="STOPPING", containers=("RUNNING",)), REDEPLOYED, "task"),
        # desired never flips (StopTask silently ignored)
        (task(desired="RUNNING", last="RUNNING", containers=("STOPPED",)), REDEPLOYED, "task"),
        # no containers reported -> cannot prove they are dead
        (task(desired="STOPPED", last="STOPPED", containers=()), REDEPLOYED, "task"),
        # task vanished from DescribeTasks
        ({"tasks": [], "failures": [{"arn": TASK, "reason": "MISSING"}]}, REDEPLOYED, "task"),
        # the new deployment never became PRIMARY
        (STOPPED, service([deployment(NEW_DEPLOYMENT, "ACTIVE", NOW), OLD]), "deployment"),
        # the service lost its scope tag meanwhile
        (STOPPED, service([NEW, OLD_ACTIVE], tags=[]), "scope"),
    ],
)
def test_verify_timeout_is_not_contained(
    world: Any,
    monkeypatch: pytest.MonkeyPatch,
    task_response: dict[str, Any],
    service_response: dict[str, Any],
    failed: str,
) -> None:
    monkeypatch.setattr(Pb04EcsTaskContain, "VERIFY_ATTEMPTS", 3)
    event = seed(world)
    ecs = Ecs()
    ecs.prologue()
    ecs.stop()
    ecs.redeploy()
    for _ in range(3):
        ecs.verify_round(task_response, service_response)

    result = pb04(world, ecs).handle(events.payload("contain", event))

    ecs.stub.assert_no_pending_responses()
    assert result["contained"] is False
    key = {"task": "taskStopped", "deployment": "newDeploymentPrimary", "scope": "serviceInScope"}
    assert result["verified"][key[failed]] is False
    assert world.incident(event["detail"]["id"])["containmentVerified"] is False


def test_verify_budget_is_about_45_seconds() -> None:
    attempts, delay = Pb04EcsTaskContain.VERIFY_ATTEMPTS, Pb04EcsTaskContain.VERIFY_DELAY
    assert delay == 2.0
    assert 40 <= (attempts - 1) * delay <= 46  # within the 55 s Lambda timeout


# --------------------------------------------------------- idempotency
def test_already_stopped_task_is_not_stopped_again(world: Any) -> None:
    event = seed(world)
    ecs = Ecs()
    ecs.prologue(task_response=STOPPED)
    ecs.redeploy()
    ecs.verify_round(STOPPED, REDEPLOYED)

    result = pb04(world, ecs).handle(events.payload("contain", event))

    assert result["contained"] is True
    assert result["taskStop"] == "already-stopped"
    assert "StopTask" not in ecs.ops


def test_existing_fresh_primary_skips_update_service(world: Any) -> None:
    # A router retry after UpdateService already ran: the PRIMARY deployment
    # is newer than the finding and is not the compromised task's own.
    event = seed(world)
    ecs = Ecs()
    ecs.prologue(service_response=REDEPLOYED)
    ecs.stop()
    ecs.verify_round(STOPPED, REDEPLOYED)

    result = pb04(world, ecs).handle(events.payload("contain", event))

    assert result["contained"] is True
    assert result["deployment"] == NEW_DEPLOYMENT
    assert "UpdateService" not in ecs.ops
    assert ecs.ops.count("StopTask") == 1


def test_stale_primary_does_not_count_as_fresh(world: Any) -> None:
    # A PRIMARY deployment older than the finding must not skip the redeploy.
    event = seed(world)
    ecs = Ecs()
    other_old = deployment("ecs-svc/3333", "PRIMARY", EVENT_AT - timedelta(seconds=1))
    ecs.prologue(service_response=service([other_old, OLD_ACTIVE]))
    ecs.stop()
    ecs.redeploy()
    ecs.verify_round(STOPPED, REDEPLOYED)
    assert pb04(world, ecs).handle(events.payload("contain", event))["contained"] is True
    assert "UpdateService" in ecs.ops


# ------------------------------------------------------------ refusals
def test_started_by_not_a_service_deployment_raises_before_stop(world: Any) -> None:
    # A forged `group` cannot make PB-04 redeploy the wrong service: the task
    # must have been started by one of THIS service's deployments.
    event = seed(world)
    ecs = Ecs()
    ecs.describe_task(task(started_by="ecs-svc/9999999999999999999"))
    ecs.describe_service(service())
    with pytest.raises(PlaybookError, match="not started by a deployment"):
        pb04(world, ecs).handle(events.payload("contain", event))
    assert "StopTask" not in ecs.ops
    assert "UpdateService" not in ecs.ops


def test_untagged_service_raises(world: Any) -> None:
    event = seed(world)
    ecs = Ecs()
    ecs.describe_task(task())
    ecs.describe_service(service(tags=[]))
    with pytest.raises(PlaybookError, match="service docs-api lacks the SOAR scope tag"):
        pb04(world, ecs).handle(events.payload("contain", event))
    assert "StopTask" not in ecs.ops


def test_untagged_task_raises(world: Any) -> None:
    event = seed(world)
    ecs = Ecs()
    ecs.describe_task(task(tags=[]))
    with pytest.raises(PlaybookError, match="task lacks the SOAR scope tag"):
        pb04(world, ecs).handle(events.payload("contain", event))
    assert ecs.ops == ["DescribeTasks"]


@pytest.mark.parametrize(
    ("task_response", "message"),
    [
        (task(group="service:billing"), "does not belong to service docs-api"),
        (task(cluster=f"arn:aws:ecs:us-east-1:{events.ACCOUNT}:cluster/other"), "outside"),
        ({"tasks": [], "failures": [{"arn": TASK, "reason": "MISSING"}]}, "not found"),
    ],
)
def test_live_task_mismatch_raises(world: Any, task_response: dict[str, Any], message: str) -> None:
    event = seed(world)
    ecs = Ecs()
    ecs.describe_task(task_response)
    with pytest.raises(PlaybookError, match=message):
        pb04(world, ecs).handle(events.payload("contain", event))
    assert ecs.ops == ["DescribeTasks"]


def test_missing_service_raises(world: Any) -> None:
    event = seed(world)
    ecs = Ecs()
    ecs.describe_task(task())
    ecs.describe_service({"services": [], "failures": [{"arn": SERVICE, "reason": "MISSING"}]})
    with pytest.raises(PlaybookError, match="service docs-api not found"):
        pb04(world, ecs).handle(events.payload("contain", event))


@pytest.mark.parametrize(
    ("event", "extra", "message"),
    [
        (events.ecs_runtime(group=None), {}, "not launched by a service"),
        (events.ecs_runtime(group="service:billing"), {}, "not allowed"),
        (
            events.ecs_runtime(
                f"arn:aws:ecs:us-east-1:{events.ACCOUNT}:task/other/{events.TASK_ID}",
                cluster_arn=f"arn:aws:ecs:us-east-1:{events.ACCOUNT}:cluster/other",
            ),
            {},
            "outside the SOAR cluster",
        ),
        (events.ecs_runtime(), {"ECS_CLUSTER_ARN": ""}, "not configured"),
        (events.portscan("i-0123abcd"), {}, "needs an ECS task target"),
    ],
)
def test_refusals_before_any_ecs_call(
    world: Any, event: dict[str, Any], extra: dict[str, str], message: str
) -> None:
    ecs = Ecs()
    ecs.stub.activate()
    playbook = Pb04EcsTaskContain(
        settings(world, **extra), lambda s, **kw: ecs.client if s == "ecs" else boto3.client(s)
    )
    with pytest.raises(PlaybookError, match=message):
        playbook.handle(events.payload("contain", event))
    assert ecs.ops == []


def test_stop_task_failure_propagates(world: Any) -> None:
    event = seed(world)
    ecs = Ecs()
    ecs.prologue()
    ecs.stub.add_client_error("stop_task", "AccessDeniedException")
    with pytest.raises(Exception, match="AccessDenied"):
        pb04(world, ecs).handle(events.payload("contain", event))


def test_task_definition_read_error_does_not_block_containment(world: Any) -> None:
    event = seed(world)
    ecs = Ecs()
    ecs.describe_task(task())
    ecs.describe_service(service())
    ecs.stub.add_client_error("describe_task_definition", "ThrottlingException")
    ecs.stop()
    ecs.redeploy()
    ecs.verify_round(STOPPED, REDEPLOYED)

    result = pb04(world, ecs).handle(events.payload("contain", event))

    assert result["contained"] is True
    assert result["prestate"]["taskDefinition"] == {"captureError": "ThrottlingException"}


# ------------------------------------------------------------- dry run
@pytest.mark.parametrize("decision_dry_run", [True, "false", None])
def test_dry_run_makes_zero_aws_mutations(world: Any, decision_dry_run: Any) -> None:
    calls: list[tuple[str, str]] = []
    ecs = Ecs()
    result = pb04(world, ecs, calls).handle(
        events.payload("contain", events.ecs_runtime(), dry_run=decision_dry_run)
    )
    assert result["contained"] is False
    assert result["would"] == "contain"
    assert any("StopTask" in step for step in result["plan"])
    reads = ("describe_", "get_", "list_")
    assert [c for c in calls if not c[1].startswith(reads)] == []
    assert ecs.ops == []


def test_switch_overrides_a_live_guard_decision(world: Any) -> None:
    world.set_dry_run("true")
    calls: list[tuple[str, str]] = []
    ecs = Ecs()
    result = pb04(world, ecs, calls).handle(events.payload("contain", events.ecs_runtime()))
    assert result["contained"] is False
    assert ecs.ops == []


def test_evidence_plan_in_dry_run(world: Any) -> None:
    ecs = Ecs()
    result = pb04(world, ecs).handle(
        events.payload("evidence", events.ecs_runtime(group=None), dry_run=True)
    )
    assert result["would"] == "evidence"
    assert result["plan"] == [f"store the pre-state of {TASK} as hashed evidence (after CONTAINED)"]
    assert ecs.ops == []


# ------------------------------------------------------------ evidence
def test_evidence_after_contained_writes_hashed_prestate(world: Any) -> None:
    event = seed(world)
    ecs = Ecs()
    ecs.prologue()
    ecs.stop()
    ecs.redeploy()
    ecs.verify_round(STOPPED, REDEPLOYED)
    contained = pb04(world, ecs).handle(events.payload("contain", event))

    state = events.router_state(event)
    state["containment"] = {"result": contained}
    evidence = pb04(world, Ecs()).handle({"action": "evidence", "event": state})

    key = evidence["evidence"]["key"]
    assert key == "incidents/f-pb04-task/pb04-ecs-task-20261014T100007Z.json"
    raw = boto3.client("s3").get_object(Bucket=EVIDENCE_BUCKET, Key=key)["Body"].read()
    document = json.loads(raw)
    assert document["actor"] == EXECUTION_ARN
    assert document["task"]["containers"][0]["imageDigest"] == DIGEST
    row = world.incident(event["detail"]["id"])
    assert row["evidenceSha256"] == hashlib.sha256(raw).hexdigest()


def test_evidence_without_prestate_raises(world: Any) -> None:
    with pytest.raises(PlaybookError, match="no pre-state"):
        pb04(world, Ecs()).handle(events.payload("evidence", events.ecs_runtime()))


# ---------------------------------------------------------- entry point
def test_lambda_handler_entry_point_dry_run(world: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ECS_CLUSTER_ARN", CLUSTER)
    monkeypatch.setenv("ECS_SERVICE_NAMES", SERVICE)
    result = lambda_handler(events.payload("contain", events.ecs_runtime(), dry_run=True), None)
    assert result == {"contained": False, "would": "contain", "dry_run": True, "plan": ANY}
