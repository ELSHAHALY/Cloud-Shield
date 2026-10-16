"""Attack simulation suite: safety gates, scenarios, local replay, runner CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import boto3
import pytest

from sims import scenarios
from sims.runner import build_parser, main
from sims.safety import LabContext, SafetyError, assert_in_scope, require_lab
from tests import events
from tests.conftest import REGION

ACCOUNT = "123456789012"
PREFIX = "cs-dev-"


def clients_factory(world: Any = None) -> Any:
    def clients(service: str, **kw: Any) -> Any:
        return boto3.client(service, **kw)

    return clients


# ------------------------------------------------------------------- safety
def test_require_lab_accepts_allow_listed_account(world: Any) -> None:
    ctx = require_lab(boto3.client, [ACCOUNT], REGION, PREFIX)
    assert ctx.account_id == ACCOUNT
    assert ctx.name_prefix == PREFIX


def test_require_lab_refuses_unknown_account(world: Any) -> None:
    with pytest.raises(SafetyError, match="not in the allow-list"):
        require_lab(boto3.client, ["999999999999"], REGION, PREFIX)


def test_require_lab_needs_an_allow_list() -> None:
    with pytest.raises(SafetyError, match="no --allowed-account"):
        require_lab(boto3.client, [], REGION, PREFIX)


def test_require_lab_refuses_wrong_region(world: Any) -> None:
    with pytest.raises(SafetyError, match="not the lab region"):
        require_lab(boto3.client, [ACCOUNT], "eu-west-1", PREFIX)


def test_live_mode_needs_matching_confirmation(world: Any) -> None:
    with pytest.raises(SafetyError, match="confirm-live"):
        require_lab(boto3.client, [ACCOUNT], REGION, PREFIX, live=True, confirm_account="000")
    ctx = require_lab(boto3.client, [ACCOUNT], REGION, PREFIX, live=True, confirm_account=ACCOUNT)
    assert ctx.account_id == ACCOUNT


def test_assert_in_scope_requires_prefix_and_tag() -> None:
    ctx = LabContext(ACCOUNT, REGION, PREFIX, "cloudshield:soar-scope", "in-scope")
    assert_in_scope(ctx, "cs-dev-report-worker", {"cloudshield:soar-scope": "in-scope"})
    with pytest.raises(SafetyError, match="outside the lab prefix"):
        assert_in_scope(ctx, "prod-worker", {"cloudshield:soar-scope": "in-scope"})
    with pytest.raises(SafetyError, match="lacks"):
        assert_in_scope(ctx, "cs-dev-worker", {})


# --------------------------------------------------------------- scenarios
def test_every_scenario_builds_a_routable_event() -> None:
    from core.finding import Finding

    targets = {
        "a": {"instance_id": "i-0abc", "role_id": "AROAFAKEROLEID00001"},
        "a-recon": {"instance_id": "i-0abc"},
        "b": {"user_name": "cs-dev-honeytoken", "access_key_id": "AKIAFAKEKEY000000001"},
        "c": {"bucket_name": "cs-dev-lab-exposure"},
        "d": {"task_arn": events.TASK_ARN, "service_name": "docs-api"},
        "e": {"ip": "1.1.1.1"},
    }
    for key, scenario in scenarios.SCENARIOS.items():
        event = scenarios.build_event(scenario, ACCOUNT, REGION, **targets[key])
        finding = Finding.from_event(event)  # must parse
        assert finding.type == scenario.finding_type
        assert scenario.attack_techniques  # MITRE mapped


def test_scenario_a_needs_instance_and_role() -> None:
    with pytest.raises(ValueError, match="instance_id and role_id"):
        scenarios.build_event(scenarios.SCENARIOS["a"], ACCOUNT, REGION)


# --------------------------------------------------------------- local replay
def _run(args: list[str], clients: Any) -> int:
    return main(args, clients=clients)


def test_replay_local_scenario_c_contains(world: Any) -> None:
    from playbooks.pb03_s3_restore_bpa import BPA_FLAGS

    boto3.client("s3").put_public_access_block(
        Bucket=world.bucket, PublicAccessBlockConfiguration=dict.fromkeys(BPA_FLAGS, False)
    )
    code = _run(
        [
            "--scenario",
            "c",
            "--mode",
            "replay",
            "--target",
            "local",
            "--allowed-account",
            ACCOUNT,
            "--region",
            REGION,
            "--name",
            "cs-dev",
            "--bucket-name",
            world.bucket,
        ],
        clients_factory(),
    )
    assert code == 0
    after = boto3.client("s3").get_public_access_block(Bucket=world.bucket)
    assert after["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is True


def test_replay_local_scenario_a_contains(world: Any) -> None:
    code = _run(
        [
            "--scenario",
            "a",
            "--mode",
            "replay",
            "--target",
            "local",
            "--allowed-account",
            ACCOUNT,
            "--region",
            REGION,
            "--name",
            "cs-dev",
            "--instance-id",
            world.instance_id,
            "--role-id",
            world.role_id,
        ],
        clients_factory(),
    )
    assert code == 0


def test_replay_local_scenario_b_contains(world: Any) -> None:
    code = _run(
        [
            "--scenario",
            "b",
            "--mode",
            "replay",
            "--target",
            "local",
            "--allowed-account",
            ACCOUNT,
            "--region",
            REGION,
            "--name",
            "cs-dev",
            "--user-name",
            world.user_name,
            "--access-key-id",
            world.access_key_id,
        ],
        clients_factory(),
    )
    assert code == 0


def test_runner_refuses_untagged_instance_before_acting(world: Any, capsys: Any) -> None:
    # Audit A1: the untagged worker is in the lab account but lacks the scope
    # tag; the sim must exit 3 before any pipeline call.
    code = _run(
        [
            "--scenario",
            "a",
            "--mode",
            "replay",
            "--target",
            "local",
            "--allowed-account",
            ACCOUNT,
            "--region",
            REGION,
            "--name",
            "cs-dev",
            "--instance-id",
            world.untagged_instance_id,
            "--role-id",
            world.role_id,
        ],
        clients_factory(),
    )
    assert code == 3
    assert "lacks" in capsys.readouterr().err
    # The incident row was never created: the gate ran before RecordDetected.
    with pytest.raises(LookupError):
        world.incident("sim-a-" + world.untagged_instance_id)


def test_runner_refuses_bucket_outside_prefix(world: Any, capsys: Any) -> None:
    code = _run(
        [
            "--scenario",
            "c",
            "--mode",
            "replay",
            "--target",
            "local",
            "--allowed-account",
            ACCOUNT,
            "--region",
            REGION,
            "--name",
            "cs-dev",
            "--bucket-name",
            world.untagged_bucket,
        ],
        clients_factory(),
    )
    assert code == 3
    assert "lacks" in capsys.readouterr().err


def test_runner_refuses_untagged_account(world: Any, capsys: Any) -> None:
    code = _run(
        [
            "--scenario",
            "a",
            "--mode",
            "replay",
            "--target",
            "local",
            "--allowed-account",
            "999999999999",
            "--region",
            REGION,
            "--name",
            "cs-dev",
            "--instance-id",
            world.instance_id,
            "--role-id",
            world.role_id,
        ],
        clients_factory(),
    )
    assert code == 3
    assert "SAFETY" in capsys.readouterr().err


def test_replay_local_dry_run_is_would_contain(world: Any) -> None:
    world.set_dry_run("true")
    result_code = _run(
        [
            "--scenario",
            "a",
            "--mode",
            "replay",
            "--target",
            "local",
            "--allowed-account",
            ACCOUNT,
            "--region",
            REGION,
            "--name",
            "cs-dev",
            "--instance-id",
            world.instance_id,
            "--role-id",
            world.role_id,
        ],
        clients_factory(),
    )
    # WOULD_CONTAIN_DRY_RUN counts as a pass for the sim.
    assert result_code == 0


def test_live_mode_is_not_automated(world: Any, capsys: Any) -> None:
    code = _run(
        [
            "--scenario",
            "a",
            "--mode",
            "live-aws",
            "--allowed-account",
            ACCOUNT,
            "--region",
            REGION,
            "--name",
            "cs-dev",
            "--confirm-live",
            ACCOUNT,
            "--instance-id",
            world.instance_id,
            "--role-id",
            world.role_id,
        ],
        clients_factory(),
    )
    assert code == 3
    assert "operator-run" in capsys.readouterr().err


def test_replay_aws_requires_state_machine_arn(world: Any, capsys: Any) -> None:
    code = _run(
        [
            "--scenario",
            "a",
            "--mode",
            "replay",
            "--target",
            "aws",
            "--allowed-account",
            ACCOUNT,
            "--region",
            REGION,
            "--name",
            "cs-dev",
            "--instance-id",
            world.instance_id,
            "--role-id",
            world.role_id,
        ],
        clients_factory(),
    )
    assert code == 3
    assert "state-machine-arn" in capsys.readouterr().err


# --------------------------------------------------------------- router parity
STATE_MACHINE_TF = (
    Path(__file__).resolve().parents[2] / "infra/terraform/modules/soar/state-machine.tf"
)


def _route_choices_tf() -> str:
    tf = STATE_MACHINE_TF.read_text(encoding="utf-8")
    # RouteByResource takes its choices from local.route_choices (concat of
    # conditional lists); the graph must still route through it.
    assert "Choices = local.route_choices" in tf.split("RouteByResource = {", 1)[1].split("}", 1)[0]
    return tf.split("route_choices = concat(", 1)[1].split("evidence_choices = concat(", 1)[0]


def test_local_router_matches_state_machine_routing() -> None:
    """Every scenario's _route() must agree with cs-ir-router (state-machine.tf)."""
    from sims.local_router import _route

    cases = {
        "a": ({"instance_id": "i-0abc", "role_id": "AROAFAKEROLEID00001"}, "pb01-ec2-isolate"),
        "a-recon": ({"instance_id": "i-0abc"}, "pb01-ec2-isolate"),
        "b": (
            {"user_name": "cs-dev-honeytoken", "access_key_id": "AKIAFAKEKEY000000001"},
            "pb02-iam-key-revoke",
        ),
        "c": ({"bucket_name": "cs-dev-lab-exposure"}, "pb03-s3-restore-bpa"),
        "d": ({"task_arn": events.TASK_ARN, "service_name": "docs-api"}, "pb04-ecs-task-contain"),
        "e": ({"ip": "1.1.1.1"}, "pb05-waf-ip-block"),
    }
    sm_next = {
        "pb01-ec2-isolate": "PB01Isolate",
        "pb02-iam-key-revoke": "PB02Revoke",
        "pb03-s3-restore-bpa": "PB03Restore",
        "pb04-ecs-task-contain": "PB04Contain",
        "pb05-waf-ip-block": "PB05Block",
    }
    block = _route_choices_tf()

    assert set(cases) == set(scenarios.SCENARIOS)
    for key, (targets, expected_pb) in cases.items():
        event = scenarios.build_event(scenarios.SCENARIOS[key], ACCOUNT, REGION, **targets)
        route = _route(event)
        assert route is not None, f"{key} did not route"
        assert route[0] == expected_pb, f"{key} routed to {route}"
        assert scenarios.SCENARIOS[key].expected_playbook == expected_pb
        assert f'Next = "{sm_next[expected_pb]}"' in block, f"{sm_next[expected_pb]} not routed"


def test_router_parity_ecs_and_ip_conditions() -> None:
    """The two Phase D choices, condition by condition, incl. the source check."""
    from sims.local_router import _route

    block = _route_choices_tf()
    ecs = block.split("local.enable_pb04 ? [{", 1)[1].split("}] : []", 1)[0]
    assert '{ Variable = "$.detail.resource.resourceType", StringEquals = "ECSCluster" }' in ecs
    assert '{ Variable = "$.detail.type", StringMatches = "*:Runtime/*" }' in ecs
    edge = block.split("local.enable_pb05 ? [{", 1)[1].split("}] : []", 1)[0]
    assert '{ Variable = "$.source", IsPresent = true }' in edge
    assert '{ Variable = "$.source", StringEquals = local.edge_event_source }' in edge
    assert '{ Variable = "$.detail.resource.resourceType", StringEquals = "IPAddress" }' in edge

    d = scenarios.build_event(
        scenarios.SCENARIOS["d"], ACCOUNT, REGION, task_arn=events.TASK_ARN, service_name="x"
    )
    assert _route(d) == ("pb04-ecs-task-contain", "contain")
    d["detail"]["type"] = "Discovery:Kubernetes/SuccessfulAnonymousAccess"
    assert _route(d) is None  # not *:Runtime/*
    e = scenarios.build_event(scenarios.SCENARIOS["e"], ACCOUNT, REGION, ip="1.1.1.1")
    assert _route(e) == ("pb05-waf-ip-block", "block")
    e["source"] = "aws.guardduty"
    assert _route(e) is None  # the source check
    del e["source"]
    assert _route(e) is None


def test_parser_rejects_unknown_scenario() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(
            ["--scenario", "z", "--mode", "replay", "--region", "x", "--name", "y"]
        )


class FakeSfn:
    """A Step Functions client that 'runs' the local router against moto."""

    def __init__(self, world: Any) -> None:
        self.world = world
        self._inputs: dict[str, str] = {}

    def start_execution(self, stateMachineArn: str, name: str, input: str) -> dict[str, Any]:
        import json as _json

        from core.config import Settings
        from sims.local_router import run_local

        arn = f"{stateMachineArn}:{name}"
        event = _json.loads(input)
        outcome = run_local(event, Settings.from_env(self.world.env), boto3.client)
        # A real execution's MarkContained writes the terminal status and the
        # MTTC stop time; the in-process router only returns them.
        if outcome.get("status") == "CONTAINED":
            from datetime import timedelta

            from core.finding import iso, parse_time

            contained_at = iso(parse_time(event["time"], "time") + timedelta(seconds=30))
            boto3.client("dynamodb").update_item(
                TableName=self.world.settings.incidents_table,
                Key={"incidentId": {"S": event["detail"]["id"]}},
                UpdateExpression="SET #s = :s, containedAt = :t",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":s": {"S": "CONTAINED"}, ":t": {"S": contained_at}},
            )
        self._inputs[arn] = input
        return {"executionArn": arn}

    def describe_execution(self, executionArn: str) -> dict[str, Any]:
        return {"status": "SUCCEEDED", "executionArn": executionArn}


def test_replay_aws_asserts_mttc_and_contained(world: Any) -> None:
    from sims.runner import replay_aws
    from sims.safety import LabContext

    ctx = LabContext(ACCOUNT, REGION, PREFIX, "cloudshield:soar-scope", "in-scope")
    fake = FakeSfn(world)

    def clients(service: str, **kw: Any) -> Any:
        return fake if service == "stepfunctions" else boto3.client(service, **kw)

    result = replay_aws(
        scenarios.SCENARIOS["c"],
        ctx,
        clients,
        "arn:aws:states:us-east-1:123456789012:stateMachine:cs-dev-cs-ir-router",
        poll_seconds=5,
        bucket_name=world.bucket,
    )
    assert result.status == "CONTAINED"
    assert result.passed is True
    assert result.mttc_seconds is not None
    assert result.mttc_seconds < 60
    assert "cs-dev-cs-ir-router" in result.execution_arn
    assert result.detail["sfn_status"] == "SUCCEEDED"


# --------------------------------------------------------------- safety internals
def test_region_must_be_resolved(world: Any, monkeypatch: Any) -> None:
    class NoRegionSts:
        class meta:
            region_name = None

        def get_caller_identity(self) -> dict[str, Any]:
            return {"Account": ACCOUNT}

    def clients(service: str, **kw: Any) -> Any:
        return NoRegionSts() if service == "sts" else boto3.client(service, **kw)

    with pytest.raises(SafetyError, match="no resolved region"):
        require_lab(clients, [ACCOUNT], REGION, PREFIX)


def test_read_target_tags_for_user_and_bucket(world: Any) -> None:
    from sims.safety import read_target_tags

    assert (
        read_target_tags(boto3.client, "user", world.user_name)["cloudshield:soar-scope"]
        == "in-scope"
    )
    # A bucket with no tag set returns {} rather than raising.
    assert read_target_tags(boto3.client, "bucket", world.untagged_bucket) == {}


def test_read_target_tags_unknown_kind_raises(world: Any) -> None:
    from sims.safety import read_target_tags

    with pytest.raises(SafetyError, match="unknown target kind"):
        read_target_tags(boto3.client, "role", "whatever")


def test_read_target_tags_missing_instance_raises(world: Any) -> None:
    from sims.safety import read_target_tags

    with pytest.raises(SafetyError, match="not found"):
        read_target_tags(boto3.client, "instance", "i-0fffffffffffffff0")


def test_assert_in_scope_instance_skips_prefix(world: Any) -> None:
    from sims.safety import LabContext, assert_in_scope

    ctx = LabContext(ACCOUNT, REGION, PREFIX, "cloudshield:soar-scope", "in-scope")
    # An instance id never starts with the name prefix; the tag alone governs.
    assert_in_scope(ctx, "i-0abc", {"cloudshield:soar-scope": "in-scope"}, require_prefix=False)
    with pytest.raises(SafetyError, match="lacks"):
        assert_in_scope(ctx, "i-0abc", {}, require_prefix=False)


# ------------------------------------------------------- scenarios D and E (D20)
def _de_args(scenario: str, *extra: str, target: str = "local", mode: str = "replay") -> list[str]:
    args = ["--scenario", scenario, "--mode", mode]
    if mode == "replay":
        args += ["--target", target]
    return [
        *args,
        "--allowed-account",
        ACCOUNT,
        "--region",
        REGION,
        "--name",
        "cs-dev",
        *extra,
    ]


D_ARGS = ("--task-arn", events.TASK_ARN, "--service-name", "docs-api")
E_ARGS = ("--ip", "1.1.1.1")


def _ecs_stub_factory(*responses: dict[str, Any]) -> Any:
    from botocore.stub import Stubber

    ecs = boto3.client("ecs", region_name=REGION)
    stub = Stubber(ecs)
    for response in responses:
        stub.add_response(
            "describe_tasks",
            response,
            {"cluster": events.CLUSTER_ARN, "tasks": [events.TASK_ARN], "include": ["TAGS"]},
        )
    stub.activate()

    def clients(service: str, **kw: Any) -> Any:
        return ecs if service == "ecs" else boto3.client(service, **kw)

    clients.stub = stub  # type: ignore[attr-defined]
    return clients


def _live_task(tags: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "tasks": [
            {
                "taskArn": events.TASK_ARN,
                "clusterArn": events.CLUSTER_ARN,
                "group": "service:docs-api",
                "tags": tags,
            }
        ]
    }


IN_SCOPE_TAGS = [{"key": "cloudshield:soar-scope", "value": "in-scope"}]


@pytest.mark.parametrize(("scenario", "extra"), [("d", D_ARGS), ("e", E_ARGS)])
@pytest.mark.parametrize(
    ("target", "mode", "extra_flags"),
    [("aws", "replay", ("--state-machine-arn", "arn:aws:states:x")), ("local", "live-aws", ())],
)
def test_d_e_refuse_aws_targets_and_live_mode(
    world: Any,
    capsys: Any,
    scenario: str,
    extra: tuple[str, ...],
    target: str,
    mode: str,
    extra_flags: tuple[str, ...],
) -> None:
    world.set_dry_run("true")
    flags = (*extra, *extra_flags, "--confirm-live", ACCOUNT)
    code = _run(_de_args(scenario, *flags, target=target, mode=mode), clients_factory())
    assert code == 3
    assert "replay --target local only" in capsys.readouterr().err


@pytest.mark.parametrize(("scenario", "extra"), [("d", D_ARGS), ("e", E_ARGS)])
@pytest.mark.parametrize("switch", ["false", None, "garbage"])
def test_d_e_refuse_unless_dry_run_reads_true(
    world: Any, capsys: Any, scenario: str, extra: tuple[str, ...], switch: str | None
) -> None:
    if switch is None:
        boto3.client("ssm").delete_parameter(Name=world.settings.dry_run_param)
    else:
        world.set_dry_run(switch)
    code = _run(_de_args(scenario, *extra), clients_factory())
    assert code == 3
    assert "reads 'true'" in capsys.readouterr().err


def test_e_requires_ip(world: Any, capsys: Any) -> None:
    world.set_dry_run("true")
    assert _run(_de_args("e"), clients_factory()) == 3
    assert "needs --ip" in capsys.readouterr().err
    with pytest.raises(ValueError, match="needs ip"):
        scenarios.build_event(scenarios.SCENARIOS["e"], ACCOUNT, REGION)


def test_d_requires_task_and_service(world: Any, capsys: Any) -> None:
    world.set_dry_run("true")
    assert _run(_de_args("d", "--task-arn", events.TASK_ARN), clients_factory()) == 3
    assert "needs --task-arn and --service-name" in capsys.readouterr().err
    with pytest.raises(ValueError, match="scenario D needs"):
        scenarios.build_event(
            scenarios.SCENARIOS["d"], ACCOUNT, REGION, task_arn="x", service_name="docs-api"
        )


@pytest.mark.parametrize("ip", ["203.0.113.9", "10.0.0.1", "1.1.1.0/24", "not-an-ip"])
def test_e_refuses_non_blockable_ip_before_acting(world: Any, capsys: Any, ip: str) -> None:
    world.set_dry_run("true")
    assert _run(_de_args("e", "--ip", ip), clients_factory()) == 3
    assert "SAFETY" in capsys.readouterr().err


def test_e_replay_local_is_would_contain(world: Any, capsys: Any) -> None:
    world.set_dry_run("true")
    boto3.client("ssm").put_parameter(
        Name="/cs-dev/soar/pb05_never_block", Value="8.8.8.8/32", Type="String"
    )
    code = _run(_de_args("e", *E_ARGS), clients_factory())
    out = capsys.readouterr().out
    assert code == 0, out
    assert '"status": "WOULD_CONTAIN_DRY_RUN"' in out
    assert '"playbook": "pb05-waf-ip-block"' in out


def test_e_never_block_hit_is_blocked_by_guard(world: Any, capsys: Any) -> None:
    world.set_dry_run("true")
    boto3.client("ssm").put_parameter(
        Name="/cs-dev/soar/pb05_never_block", Value="1.1.1.1/32", Type="String"
    )
    code = _run(_de_args("e", *E_ARGS), clients_factory())
    assert code == 1
    assert '"status": "BLOCKED_BY_GUARD"' in capsys.readouterr().out


def test_d_replay_local_is_would_contain(world: Any, capsys: Any) -> None:
    world.set_dry_run("true")
    # One read for the runner's scope gate, one for the guard (live tags).
    clients = _ecs_stub_factory(_live_task(IN_SCOPE_TAGS), _live_task(IN_SCOPE_TAGS))
    code = _run(_de_args("d", *D_ARGS), clients)
    out = capsys.readouterr().out
    assert code == 0, out
    assert '"status": "WOULD_CONTAIN_DRY_RUN"' in out
    assert '"playbook": "pb04-ecs-task-contain"' in out
    clients.stub.assert_no_pending_responses()  # and no StopTask / UpdateService


def test_d_refuses_untagged_task_before_acting(world: Any, capsys: Any) -> None:
    world.set_dry_run("true")
    clients = _ecs_stub_factory(_live_task([]))
    assert _run(_de_args("d", *D_ARGS), clients) == 3
    assert "lacks" in capsys.readouterr().err


def test_d_refuses_missing_or_malformed_task(world: Any, capsys: Any) -> None:
    world.set_dry_run("true")
    clients = _ecs_stub_factory({"tasks": [], "failures": []})
    assert _run(_de_args("d", *D_ARGS), clients) == 3
    assert "not found" in capsys.readouterr().err
    bad = ("--task-arn", "arn:aws:ecs:us-east-1:123456789012:task/abc", "--service-name", "x")
    assert _run(_de_args("d", *bad), clients_factory()) == 3
    assert "not a (new-format) ECS task ARN" in capsys.readouterr().err
