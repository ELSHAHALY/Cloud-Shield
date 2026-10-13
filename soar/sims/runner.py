"""Attack simulation runner (plan §7). Three modes, all behind the R4 gates.

    python -m sims.runner --scenario a --mode replay --target local \
        --allowed-account 123456789012 --region us-east-1 --name cloudshield-dev

Modes:
  replay --target local   drive the in-process router against moto/this process (CI)
  replay --target aws     StartExecution on cs-ir-router with a real-target event;
                          poll the execution and the incident row; assert MTTC < 60 s
  live-aws                perform the reversible attacker action; wait for the real
                          GuardDuty finding to drive the pipeline
  (cleanup is exposed per scenario; live modes always clean up in `finally`)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from core import aws
from core.finding import parse_time
from sims import scenarios
from sims.safety import LabContext, SafetyError, require_lab, verify_targets

MTTC_TARGET_SECONDS = 60.0


@dataclass
class SimResult:
    scenario: str
    mode: str
    status: str
    passed: bool
    incident_id: str | None = None
    mttc_seconds: float | None = None
    execution_arn: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {**self.__dict__}


def _settings(name: str) -> Any:
    from core.config import Settings

    # Real infra ids (quarantine SG/NACL, revocable roles, tables) come from
    # the same environment the Lambdas receive, so a local replay drives the
    # actual playbooks. Anything unset falls back to a name-based placeholder.
    env = dict(os.environ)
    env.setdefault("DRY_RUN_PARAM", f"/{name}/soar/dry_run")
    env.setdefault("SCOPE_TAG_KEY", "cloudshield:soar-scope")
    env.setdefault("SCOPE_TAG_VALUE", "in-scope")
    env.setdefault("INCIDENTS_TABLE", f"{name}-soar-incidents")
    env.setdefault("EVIDENCE_BUCKET", f"{name}-soar-evidence")
    env.setdefault("QUARANTINE_SG_ID", "sg-placeholder")
    env.setdefault("BUCKET_NAME_PREFIX", f"{name}-")
    return Settings.from_env(env)


# --------------------------------------------------------------- replay: local
def replay_local(
    scenario: scenarios.Scenario, ctx: LabContext, clients: Any, **targets: Any
) -> SimResult:
    from sims.local_router import run_local

    event = scenarios.build_event(scenario, ctx.account_id, ctx.region, **targets)
    settings = _settings(ctx.name_prefix.rstrip("-"))
    outcome = run_local(event, settings, clients)
    status = outcome.get("status", "UNKNOWN")
    passed = status in {"CONTAINED", "WOULD_CONTAIN_DRY_RUN"}
    return SimResult(
        scenario.key,
        "replay-local",
        status,
        passed,
        incident_id=event["detail"]["id"],
        detail=outcome,
    )


# ----------------------------------------------------------------- replay: aws
def replay_aws(
    scenario: scenarios.Scenario,
    ctx: LabContext,
    clients: Any,
    state_machine_arn: str,
    *,
    poll_seconds: float = 90.0,
    **targets: Any,
) -> SimResult:
    event = scenarios.build_event(scenario, ctx.account_id, ctx.region, **targets)
    incident_id = event["detail"]["id"]
    sfn = clients("stepfunctions")
    execution = sfn.start_execution(
        stateMachineArn=state_machine_arn,
        name=f"sim-{scenario.key}-{int(time.time())}",
        input=json.dumps(event),
    )
    arn = execution["executionArn"]
    deadline = time.monotonic() + poll_seconds
    sfn_status = "RUNNING"
    while time.monotonic() < deadline:
        described = sfn.describe_execution(executionArn=arn)
        sfn_status = described["status"]
        if sfn_status != "RUNNING":
            break
        time.sleep(2)

    row = _incident(clients, ctx, incident_id)
    mttc = _mttc(row)
    status = row.get("status", sfn_status)
    if status == "CONTAINED":
        # A CONTAINED row without a computable MTTC cannot be said to meet the
        # 60 s bar, so it does NOT pass (audit A3).
        passed = mttc is not None and mttc < MTTC_TARGET_SECONDS
    else:
        passed = status == "WOULD_CONTAIN_DRY_RUN"
    return SimResult(
        scenario.key,
        "replay-aws",
        status,
        passed,
        incident_id=incident_id,
        mttc_seconds=mttc,
        execution_arn=arn,
        detail={"sfn_status": sfn_status},
    )


def _incident(clients: Any, ctx: LabContext, incident_id: str) -> dict[str, Any]:
    from core.incidents import IncidentRepository

    try:
        return IncidentRepository(f"{ctx.name_prefix}soar-incidents", clients("dynamodb")).get(
            incident_id
        )
    except LookupError:
        return {}


def _mttc(row: dict[str, Any]) -> float | None:
    if row.get("status") != "CONTAINED":
        return None
    try:
        event_time = parse_time(row["eventTime"], "eventTime")
        contained = parse_time(row["containedAt"], "containedAt")
    except (KeyError, ValueError):
        return None
    return round((contained - event_time).total_seconds(), 3)


# ------------------------------------------------------------------------- CLI
def _dispatch(args: argparse.Namespace, clients: Any = aws.client) -> SimResult:
    scenario = scenarios.SCENARIOS[args.scenario]
    ctx = require_lab(
        clients,
        args.allowed_account,
        args.region,
        f"{args.name}-",
        live=(args.mode == "live-aws"),
        confirm_account=args.confirm_live,
    )
    # Rule 3 (audit A1): before ANY mutating call, read each named target's
    # live tags and refuse anything not in scope. role_id / access_key_id are
    # derived values, not taggable resources, so only the real resources below
    # are gated here; the pipeline's own IAM + guard remain as defence in depth.
    scope_targets = {
        kind: name
        for kind, name in (
            ("instance", args.instance_id),
            ("user", args.user_name),
            ("bucket", args.bucket_name),
        )
        if name is not None
    }
    verify_targets(ctx, clients, scope_targets)

    targets = {
        "instance_id": args.instance_id,
        "role_id": args.role_id,
        "user_name": args.user_name,
        "access_key_id": args.access_key_id,
        "bucket_name": args.bucket_name,
        "now": datetime.now(UTC),
    }
    targets = {k: v for k, v in targets.items() if v is not None}

    if args.mode == "replay" and args.target == "local":
        return replay_local(scenario, ctx, clients, **targets)
    if args.mode == "replay" and args.target == "aws":
        if not args.state_machine_arn:
            raise SafetyError("--state-machine-arn is required for replay --target aws")
        return replay_aws(scenario, ctx, clients, args.state_machine_arn, **targets)
    raise SafetyError("live-aws mode is operator-run; see sims/README.md (not automated here)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="CloudShield attack simulation runner")
    p.add_argument("--scenario", required=True, choices=sorted(scenarios.SCENARIOS))
    p.add_argument("--mode", required=True, choices=("replay", "live-aws"))
    p.add_argument("--target", choices=("local", "aws"), default="local")
    p.add_argument(
        "--allowed-account",
        action="append",
        default=[],
        help="allow-listed account id (repeatable); required",
    )
    p.add_argument("--region", required=True)
    p.add_argument("--name", required=True, help="environment name prefix, e.g. cloudshield-dev")
    p.add_argument("--confirm-live", help="account id, retyped, required for --mode live-aws")
    p.add_argument("--state-machine-arn", help="cs-ir-router ARN (replay --target aws)")
    p.add_argument("--instance-id")
    p.add_argument("--role-id")
    p.add_argument("--user-name")
    p.add_argument("--access-key-id")
    p.add_argument("--bucket-name")
    p.add_argument("--output", help="write the JSON result here")
    return p


def main(argv: list[str] | None = None, clients: Any = aws.client) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = _dispatch(args, clients)
    except SafetyError as exc:
        print(f"SAFETY: {exc}", file=sys.stderr)
        return 3
    payload = json.dumps(result.to_dict(), indent=2, default=str)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
    print(payload)
    return 0 if result.passed else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
