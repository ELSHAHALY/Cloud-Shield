"""Attack simulation suite: safety gates, scenarios, local replay, runner CLI."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import boto3
import pytest

from sims import scenarios
from sims.runner import build_parser, main
from sims.safety import LabContext, SafetyError, assert_in_scope, require_lab
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
def test_local_router_matches_state_machine_routing() -> None:
    """The in-process router's routes must match cs-ir-router (state-machine.tf)."""
    tf = (
        Path(__file__).resolve().parents[2] / "infra/terraform/modules/soar/state-machine.tf"
    ).read_text(encoding="utf-8")
    block = tf.split("RouteByResource = {", 1)[1].split('Default = "NoPlaybook"', 1)[0]
    # Each scenario's finding routes to its expected playbook via the real table.
    assert '"PB01Isolate"' in block
    assert re.search(r'StringEquals\s*=\s*"S3Bucket".*?"PB03Restore"', block, re.DOTALL)
    assert re.search(r'StringEquals\s*=\s*"AccessKey".*?"PB02Revoke"', block, re.DOTALL)


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
