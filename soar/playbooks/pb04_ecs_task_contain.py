"""PB-04: compromised ECS task (scenario D, plan §4.1, D12).

action "contain" runs BEFORE CONTAINED (Lambda timeout 55 s):
  1. re-check the scope (defence in depth: guard + IAM + code): the LIVE task
     is in ECS_CLUSTER_ARN, carries the scope tag, and belongs to an allowed
     service, which also carries the scope tag. Membership is proven by ECS
     itself (audit A4): ListTasks(cluster, serviceName) must contain the task
     ARN (desired RUNNING, else desired STOPPED, which ECS keeps listing for
     about an hour). A forged `group` or `startedBy` therefore cannot get the
     wrong service redeployed.
  2. capture the task (definition ARN, images + digests, ENI and private IP,
     start time) and its task definition, in memory, BEFORE anything changes.
     The definition read is best-effort and short: evidence never blocks
     containment.
  3. StopTask. Already stopping/stopped -> skipped (idempotent).
  4. UpdateService(forceNewDeployment) so every sibling task is replaced.
     Skipped when a PRIMARY deployment newer than the finding (and not the
     compromised task's own) already exists, i.e. on a router retry.
  5. verify, polling every 2 s for about 45 s (F21): the task's processes are
     dead (desiredStatus STOPPED, every container STOPPED, task lastStatus
     DEPROVISIONING or STOPPED), the redeploy is PRIMARY, and the service is
     still in scope. Only then contained.

action "evidence" runs AFTER CONTAINED (router step PB04Evidence), outside
the MTTC window: the pre-state becomes SHA-256-checksummed evidence.

Limit (D12): forceNewDeployment re-runs the same task definition and image
digest. If the image itself is compromised, so are the replacements;
eradication (a new image) is human. ECS Exec volatile capture is a runbook
step, never automated here.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from botocore.exceptions import BotoCoreError, ClientError

from core import aws
from core.aws import error_code
from core.evidence import EvidenceCollector
from core.finding import EcsTaskTarget, Finding, iso
from core.playbook import Playbook, PlaybookError

_TASK_GONE = frozenset({"DEPROVISIONING", "STOPPED"})
_ENI_FIELDS = ("networkInterfaceId", "privateIPv4Address", "subnetId")


def _json_safe(value: Any) -> Any:
    """Step Functions carries the pre-state on: datetimes become strings."""
    return json.loads(json.dumps(value, default=str))


def _tags(resource: dict[str, Any]) -> dict[str, str]:
    return {t["key"]: t["value"] for t in resource.get("tags", [])}


class Pb04EcsTaskContain(Playbook):
    name = "pb04-ecs-task-contain"
    actions = frozenset({"contain", "evidence"})

    # About 45 s of polling inside the 55 s Lambda timeout (F21).
    VERIFY_ATTEMPTS: ClassVar[int] = 23
    VERIFY_DELAY: ClassVar[float] = 2.0

    def plan(self, action: str, finding: Finding) -> list[str]:
        target = finding.target
        task = target.task_arn if isinstance(target, EcsTaskTarget) else "<unresolved>"
        service = (
            target.service_name
            if isinstance(target, EcsTaskTarget) and target.service_name
            else "<no service>"
        )
        if action == "evidence":
            return [f"store the pre-state of {task} as hashed evidence (after CONTAINED)"]
        return [
            f"re-check scope of {task} and of service {service}; "
            f"require {task} in ListTasks(serviceName={service})",
            f"capture task metadata and task definition of {task}",
            f"StopTask {task}",
            f"UpdateService {service} forceNewDeployment (replace sibling tasks)",
            "verify the task's processes are dead and the redeploy is PRIMARY",
        ]

    def run(self, action: str, finding: Finding, state: dict[str, Any]) -> dict[str, Any]:
        target = finding.target
        if not isinstance(target, EcsTaskTarget):
            raise PlaybookError("PB-04 needs an ECS task target")
        if action == "evidence":
            return self._evidence(finding, state)
        return self._contain(finding, target)

    # ---------------------------------------------------------------- contain
    def _contain(self, finding: Finding, target: EcsTaskTarget) -> dict[str, Any]:
        settings = self.settings
        if not settings.ecs_cluster_arn or not settings.ecs_service_names:
            raise PlaybookError("PB-04 is not configured (ECS_CLUSTER_ARN / ECS_SERVICE_NAMES)")
        service_name = target.service_name
        if service_name is None:
            raise PlaybookError("task was not launched by a service")
        if target.cluster_arn != settings.ecs_cluster_arn:
            raise PlaybookError("task is outside the SOAR cluster")
        if service_name not in settings.ecs_service_names:
            raise PlaybookError(f"service {service_name} is not allowed for PB-04")

        cluster = settings.ecs_cluster_arn
        ecs = self.clients("ecs")

        # 1. scope + ownership, all from live reads.
        task = self._task(ecs, cluster, target.task_arn, tags=True)
        if task is None:
            raise PlaybookError(f"task {target.task_arn} not found in the SOAR cluster")
        if task.get("clusterArn") != cluster:
            raise PlaybookError("task is outside the SOAR cluster")
        if task.get("group") != f"service:{service_name}":
            raise PlaybookError(f"task does not belong to service {service_name}")
        if not self._in_scope(task):
            raise PlaybookError("task lacks the SOAR scope tag")
        service = self._service(ecs, cluster, service_name)
        if not self._in_scope(service):
            raise PlaybookError(f"service {service_name} lacks the SOAR scope tag")
        if not self._service_lists_task(ecs, cluster, service_name, target.task_arn):
            raise PlaybookError(
                f"ECS does not list the task under service {service_name}; refusing"
            )
        started_by = task.get("startedBy")
        deployments = service.get("deployments", [])

        # 2. capture BEFORE any change.
        prestate = self._prestate(task, cluster)
        self.record(finding, "capture-prestate", taskArn=target.task_arn)

        # 3. stop the compromised task (idempotent).
        if task.get("desiredStatus") == "STOPPED":
            stop = "already-stopped"
        else:
            ecs.stop_task(
                cluster=cluster, task=target.task_arn, reason=f"cloudshield-soar {finding.id}"
            )
            stop = "requested"
        self.record(finding, "stop-task", taskArn=target.task_arn, result=stop)

        # 4. replace every sibling (idempotent on retry).
        fresh = self._fresh_primary(deployments, finding, started_by)
        if fresh is None:
            updated = ecs.update_service(
                cluster=cluster, service=service_name, forceNewDeployment=True
            )["service"]
            fresh = self._fresh_primary(updated.get("deployments", []), finding, started_by)
            redeploy = "requested"
        else:
            redeploy = "already-redeployed"
        deployment_id = fresh.get("id") if fresh else None
        self.record(
            finding, "redeploy", serviceName=service_name, result=redeploy, deployment=deployment_id
        )

        # 5. verify by re-reading.
        def check() -> dict[str, bool]:
            now_task = self._task(ecs, cluster, target.task_arn, tags=False)
            now_service = self._service(ecs, cluster, service_name)
            return {
                "taskStopped": self._processes_dead(now_task),
                "newDeploymentPrimary": deployment_id is not None
                and any(
                    d.get("id") == deployment_id and d.get("status") == "PRIMARY"
                    for d in now_service.get("deployments", [])
                ),
                "serviceInScope": self._in_scope(now_service),
            }

        verified = self.verify_with_retry(
            check, attempts=self.VERIFY_ATTEMPTS, delay=self.VERIFY_DELAY
        )
        return self.contained_result(
            finding,
            "contain",
            verified,
            taskArn=target.task_arn,
            serviceName=service_name,
            taskStop=stop,
            deployment=deployment_id,
            prestate=prestate,
        )

    def _in_scope(self, resource: dict[str, Any]) -> bool:
        return _tags(resource).get(self.settings.scope_tag_key) == self.settings.scope_tag_value

    @staticmethod
    def _task(ecs: Any, cluster: str, task_arn: str, *, tags: bool) -> dict[str, Any] | None:
        kwargs: dict[str, Any] = {"cluster": cluster, "tasks": [task_arn]}
        if tags:
            kwargs["include"] = ["TAGS"]
        tasks = [
            t for t in ecs.describe_tasks(**kwargs).get("tasks", []) if t.get("taskArn") == task_arn
        ]
        return tasks[0] if len(tasks) == 1 else None

    @staticmethod
    def _service_lists_task(ecs: Any, cluster: str, service_name: str, task_arn: str) -> bool:
        """ECS's own answer to "is this task one of the service's tasks?"."""
        paginator = ecs.get_paginator("list_tasks")
        for desired in ("RUNNING", "STOPPED"):
            for page in paginator.paginate(
                cluster=cluster, serviceName=service_name, desiredStatus=desired
            ):
                if task_arn in page.get("taskArns", []):
                    return True
        return False

    @staticmethod
    def _service(ecs: Any, cluster: str, service_name: str) -> dict[str, Any]:
        services = ecs.describe_services(
            cluster=cluster, services=[service_name], include=["TAGS"]
        ).get("services", [])
        if len(services) != 1 or services[0].get("serviceName") != service_name:
            raise PlaybookError(f"service {service_name} not found in the SOAR cluster")
        return services[0]

    @staticmethod
    def _fresh_primary(
        deployments: list[dict[str, Any]], finding: Finding, started_by: str | None
    ) -> dict[str, Any] | None:
        """A PRIMARY deployment created at or after the finding's event time,
        and not the deployment that launched the compromised task."""
        for d in deployments:
            created = d.get("createdAt")
            if (
                d.get("status") == "PRIMARY"
                and d.get("id") != started_by
                and created is not None
                and created >= finding.event_time
            ):
                return d
        return None

    @staticmethod
    def _processes_dead(task: dict[str, Any] | None) -> bool:
        # F21: STOPPED desired, every container STOPPED, and the task past
        # STOPPING. DEPROVISIONING = only the ENI is still detaching.
        if task is None:
            return False
        containers = task.get("containers", [])
        return (
            task.get("desiredStatus") == "STOPPED"
            and bool(containers)
            and all(c.get("lastStatus") == "STOPPED" for c in containers)
            and task.get("lastStatus") in _TASK_GONE
        )

    def _prestate(self, task: dict[str, Any], cluster: str) -> dict[str, Any]:
        enis = []
        for attachment in task.get("attachments", []):
            if attachment.get("type") != "ElasticNetworkInterface":
                continue
            details = {d.get("name"): d.get("value") for d in attachment.get("details", [])}
            enis.append({k: details.get(k) for k in _ENI_FIELDS})
        captured = {
            "taskDefinitionArn": task.get("taskDefinitionArn"),
            "group": task.get("group"),
            "startedBy": task.get("startedBy"),
            "startedAt": task.get("startedAt"),
            "launchType": task.get("launchType"),
            "platformVersion": task.get("platformVersion"),
            "availabilityZone": task.get("availabilityZone"),
            "desiredStatus": task.get("desiredStatus"),
            "lastStatus": task.get("lastStatus"),
            "containers": [
                {k: c.get(k) for k in ("name", "image", "imageDigest", "lastStatus", "runtimeId")}
                for c in task.get("containers", [])
            ],
            "networkInterfaces": enis,
            "tags": _tags(task),
        }
        return _json_safe(
            {
                "schema": "cloudshield.evidence.ecs-task.v1",
                "taskArn": task.get("taskArn"),
                "clusterArn": cluster,
                "capturedAt": iso(self.clock()),
                "task": captured,
                "taskDefinition": self._task_definition(task.get("taskDefinitionArn")),
            }
        )

    def _task_definition(self, arn: Any) -> dict[str, Any]:
        # Best-effort, single attempt, short timeouts: never blocks containment.
        # Environment values are non-secret configuration by design.
        if not isinstance(arn, str):
            return {"captureError": "no taskDefinitionArn"}
        try:
            definition = self.clients("ecs", config=aws.QUICK).describe_task_definition(
                taskDefinition=arn
            )["taskDefinition"]
        except ClientError as exc:
            return {"captureError": error_code(exc) or type(exc).__name__}
        except BotoCoreError as exc:
            return {"captureError": type(exc).__name__}
        return {
            "taskDefinitionArn": definition.get("taskDefinitionArn"),
            "containerDefinitions": definition.get("containerDefinitions", []),
        }

    # --------------------------------------------------------------- evidence
    def _evidence(self, finding: Finding, state: dict[str, Any]) -> dict[str, Any]:
        containment = state.get("containment")
        result = containment.get("result") if isinstance(containment, dict) else None
        prestate = result.get("prestate") if isinstance(result, dict) else None
        if not isinstance(prestate, dict):
            raise PlaybookError("no pre-state in the router state to preserve")
        actor = self.incidents.get(finding.id).get("executionArn", "unknown")
        collected_at = self.clock()
        document = {
            **prestate,
            "incidentId": finding.id,
            "actor": actor,
            "collectedAt": iso(collected_at),
        }
        # Timestamped key: a re-run after FAILED never overwrites earlier evidence.
        key = f"incidents/{finding.id}/pb04-ecs-task-{collected_at:%Y%m%dT%H%M%SZ}.json"
        record = EvidenceCollector(self.settings.evidence_bucket, self.clients("s3")).put_json(
            key, document
        )
        self.incidents.add_evidence(finding.id, record.to_dict())
        return {"evidence": record.to_dict()}


lambda_handler = Pb04EcsTaskContain.lambda_handler
