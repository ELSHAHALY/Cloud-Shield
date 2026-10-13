"""PB-01: EC2 isolation and forensic snapshot."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError

from core.finding import MalformedFindingError
from core.playbook import REVOKE_POLICY_NAME, PlaybookError
from playbooks.pb01_ec2_isolate import Pb01Ec2Isolate, lambda_handler
from tests import events
from tests.conftest import EVIDENCE_BUCKET, EXECUTION_ARN

ALL_VERIFIED = {
    "onlyQuarantineGroup": True,
    "naclIngressDeny": True,
    "naclEgressDeny": True,
    "noPreemptingNaclEntries": True,
    "terminationProtection": True,
    "stopProtection": True,
    "roleSessionsRevoked": True,
}


def pb01(world: Any, clock: Any, clients: Any = None, **settings: str) -> Pb01Ec2Isolate:
    resolved = world.settings.__class__.from_env({**world.env, **settings})
    return Pb01Ec2Isolate(resolved, clients or boto3.client, clock, sleep=lambda _: None)


def exfil(world: Any) -> dict[str, Any]:
    return events.exfiltration(world.instance_id, role_id=world.role_id)


def nacl_entries(world: Any) -> list[dict[str, Any]]:
    acl = boto3.client("ec2").describe_network_acls(NetworkAclIds=[world.worker_nacl_id])
    return acl["NetworkAcls"][0]["Entries"]


def instance(world: Any) -> dict[str, Any]:
    return boto3.client("ec2").describe_instances(InstanceIds=[world.instance_id])["Reservations"][
        0
    ]["Instances"][0]


def overriding(service: str, method: str, fn: Any) -> Any:
    """Client factory where one method of one service is replaced."""

    def clients(name: str, **kw: Any) -> Any:
        real = boto3.client(name, **kw)
        if name != service:
            return real

        class Proxy:
            def __getattr__(self, attr: str) -> Any:
                return fn if attr == method else getattr(real, attr)

        return Proxy()

    return clients


class Recorder:
    """Client factory that records every call made through it."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def __call__(self, service: str, **kw: Any) -> Any:
        real = boto3.client(service, **kw)
        recorder = self

        class Proxy:
            def __getattr__(self, name: str) -> Any:
                attr = getattr(real, name)
                if callable(attr):

                    def wrapped(*a: Any, **k: Any) -> Any:
                        recorder.calls.append((service, name))
                        return attr(*a, **k)

                    return wrapped
                return attr

        return Proxy()

    def mutating(self) -> list[tuple[str, str]]:
        reads = ("describe_", "get_", "list_")
        return [c for c in self.calls if not c[1].startswith(reads)]


# ------------------------------------------------------------- isolate: live
@pytest.mark.parametrize("scenario", ["portscan", "exfiltration"])
def test_isolate_contains_and_verifies(world: Any, clock: Any, scenario: str) -> None:
    event = exfil(world) if scenario == "exfiltration" else events.portscan(world.instance_id)
    world.seed_incident(event["detail"]["id"])

    result = pb01(world, clock).handle(events.payload("isolate", event))

    assert result["contained"] is True
    assert result["verified"] == ALL_VERIFIED
    assert [g["GroupId"] for g in instance(world)["SecurityGroups"]] == [world.quarantine_sg_id]
    denies = [e for e in nacl_entries(world) if e["RuleNumber"] == 10]
    assert {(e["Egress"], e["RuleAction"], e["CidrBlock"]) for e in denies} == {
        (False, "deny", "0.0.0.0/0"),
        (True, "deny", "0.0.0.0/0"),
    }

    policy = boto3.client("iam").get_role_policy(
        RoleName="cs-dev-report-worker", PolicyName=REVOKE_POLICY_NAME
    )["PolicyDocument"]
    policy = json.loads(policy) if isinstance(policy, str) else policy
    statement = policy["Statement"][0]
    assert statement["Effect"] == "Deny"
    # Whole seconds, rounded up (audit A12); NOW has no sub-second part.
    assert statement["Condition"] == {
        "DateLessThan": {"aws:TokenIssueTime": "2026-10-14T10:00:07Z"}
    }
    assert result["revokedRole"] == world.role_arn

    row = world.incident(event["detail"]["id"])
    assert row["status"] == "DETECTED"  # playbooks never write status: the router does
    assert row["containmentVerified"] is True
    assert row["containmentVerifiedAt"] == "2026-10-14T10:00:07.000Z"
    assert float(row["playbookSecondsSinceEvent"]) == 7.0
    assert [a["step"] for a in row["actions"]] == [
        "nacl-deny",
        "sg-swap",
        "protection",
        "revoke-role-sessions",
    ]
    assert row["actions"][1]["previousGroups"] == [world.worker_sg_id]


def test_isolate_is_idempotent_on_retry(world: Any, clock: Any) -> None:
    event = events.portscan(world.instance_id)
    world.seed_incident(event["detail"]["id"])
    pb01(world, clock).handle(events.payload("isolate", event))
    again = pb01(world, clock).handle(events.payload("isolate", event))
    assert again["contained"] is True
    assert len([e for e in nacl_entries(world) if e["RuleNumber"] == 10]) == 2
    # The retry must not overwrite the recovery record with the quarantine SG.
    swaps = [a for a in world.incident(event["detail"]["id"])["actions"] if a["step"] == "sg-swap"]
    assert [s["previousGroups"] for s in swaps] == [[world.worker_sg_id]]


def test_conflicting_rule_at_quarantine_number_is_not_contained(world: Any, clock: Any) -> None:
    boto3.client("ec2").create_network_acl_entry(
        NetworkAclId=world.worker_nacl_id,
        RuleNumber=10,
        Protocol="6",
        RuleAction="allow",
        Egress=False,
        CidrBlock="0.0.0.0/0",
        PortRange={"From": 443, "To": 443},
    )
    event = events.portscan(world.instance_id)
    world.seed_incident(event["detail"]["id"])

    result = pb01(world, clock).handle(events.payload("isolate", event))

    assert result["contained"] is False
    assert result["verified"]["naclIngressDeny"] is False
    assert world.incident(event["detail"]["id"])["containmentVerified"] is False


def test_preempting_allow_below_quarantine_rule_is_not_contained(world: Any, clock: Any) -> None:
    boto3.client("ec2").create_network_acl_entry(
        NetworkAclId=world.worker_nacl_id,
        RuleNumber=5,
        Protocol="-1",
        RuleAction="allow",
        Egress=True,
        CidrBlock="0.0.0.0/0",
    )
    event = events.portscan(world.instance_id)
    world.seed_incident(event["detail"]["id"])

    result = pb01(world, clock).handle(events.payload("isolate", event))

    assert result["contained"] is False
    assert result["verified"]["noPreemptingNaclEntries"] is False


def test_verify_polls_for_eventual_consistency(world: Any, clock: Any) -> None:
    real_ec2 = boto3.client("ec2")
    reads = {"n": 0}

    def stale_then_fresh(**kw: Any) -> Any:
        reads["n"] += 1
        response = real_ec2.describe_instance_attribute(**kw)
        if reads["n"] <= 2:  # first verify pass sees the old values
            return {**response, "DisableApiTermination": {"Value": False}}
        return response

    sleeps: list[float] = []
    event = events.portscan(world.instance_id)
    world.seed_incident(event["detail"]["id"])
    playbook = Pb01Ec2Isolate(
        world.settings,
        overriding("ec2", "describe_instance_attribute", stale_then_fresh),
        clock,
        sleep=sleeps.append,
    )
    assert playbook.handle(events.payload("isolate", event))["contained"] is True
    assert sleeps == [1.0]


# ----------------------------------------------------------- isolate: refusals
def test_untagged_instance_is_refused(world: Any, clock: Any) -> None:
    event = events.portscan(world.untagged_instance_id)
    with pytest.raises(PlaybookError, match="scope tag"):
        pb01(world, clock).handle(events.payload("isolate", event))


def test_nacl_not_in_allow_list_is_refused(world: Any, clock: Any) -> None:
    event = events.portscan(world.instance_id)
    with pytest.raises(PlaybookError, match="not a quarantine NACL"):
        pb01(world, clock, QUARANTINE_NACL_IDS="").handle(events.payload("isolate", event))
    assert [g["GroupId"] for g in instance(world)["SecurityGroups"]] == [world.worker_sg_id]


def test_role_not_revocable_is_refused_before_any_change(world: Any, clock: Any) -> None:
    with pytest.raises(PlaybookError, match="not revocable"):
        pb01(world, clock, REVOCABLE_ROLE_ARNS="").handle(events.payload("isolate", exfil(world)))
    assert not [e for e in nacl_entries(world) if e["RuleNumber"] == 10]


def test_exfiltration_of_a_different_role_is_refused(world: Any, clock: Any) -> None:
    event = events.exfiltration(world.instance_id, role_id="AROAOTHERFAKEROLEID00")
    with pytest.raises(PlaybookError, match="not the role in the finding"):
        pb01(world, clock).handle(events.payload("isolate", event))
    assert not [e for e in nacl_entries(world) if e["RuleNumber"] == 10]


def test_exfiltration_without_instance_role_is_refused(world: Any, clock: Any) -> None:
    ec2 = boto3.client("ec2")
    association = ec2.describe_iam_instance_profile_associations(
        Filters=[{"Name": "instance-id", "Values": [world.instance_id]}]
    )["IamInstanceProfileAssociations"][0]["AssociationId"]
    ec2.disassociate_iam_instance_profile(AssociationId=association)
    with pytest.raises(PlaybookError, match="no instance role"):
        pb01(world, clock).handle(events.payload("isolate", exfil(world)))


def test_revoke_policy_missing_on_readback_is_not_contained(world: Any, clock: Any) -> None:
    def no_such_policy(**_: Any) -> Any:
        raise ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetRolePolicy")

    event = exfil(world)
    world.seed_incident(event["detail"]["id"])
    result = pb01(world, clock, overriding("iam", "get_role_policy", no_such_policy)).handle(
        events.payload("isolate", event)
    )
    assert result["contained"] is False
    assert result["verified"]["roleSessionsRevoked"] is False


def test_multi_eni_instance_is_refused(world: Any, clock: Any) -> None:
    ec2 = boto3.client("ec2")
    eni = ec2.create_network_interface(SubnetId=world.worker_subnet_id)["NetworkInterface"]
    ec2.attach_network_interface(
        NetworkInterfaceId=eni["NetworkInterfaceId"], InstanceId=world.instance_id, DeviceIndex=1
    )
    with pytest.raises(PlaybookError, match="ENIs"):
        pb01(world, clock).handle(events.payload("isolate", events.portscan(world.instance_id)))


def test_aws_error_propagates_so_router_records_failed(world: Any, clock: Any) -> None:
    def denied(**_: Any) -> Any:
        raise ClientError({"Error": {"Code": "UnauthorizedOperation"}}, "ModifyInstanceAttribute")

    event = events.portscan(world.instance_id)
    world.seed_incident(event["detail"]["id"])
    with pytest.raises(ClientError):
        pb01(world, clock, overriding("ec2", "modify_instance_attribute", denied)).handle(
            events.payload("isolate", event)
        )


def test_unresolvable_exfiltration_principal_is_refused(world: Any, clock: Any) -> None:
    event = exfil(world)
    event["detail"]["resource"]["accessKeyDetails"]["principalId"] = "AROAEXAMPLE:attacker"
    with pytest.raises(PlaybookError, match="EC2 instance target"):
        pb01(world, clock).handle(events.payload("isolate", event))


# ------------------------------------------------------------------ dry-run
@pytest.mark.parametrize("decision_dry_run", [True, None, "false", 0])
def test_dry_run_makes_no_change(world: Any, clock: Any, decision_dry_run: Any) -> None:
    recorder = Recorder()
    result = pb01(world, clock, recorder).handle(
        events.payload("isolate", events.portscan(world.instance_id), dry_run=decision_dry_run)
    )
    assert result["contained"] is False
    assert result["would"] == "isolate"
    assert recorder.mutating() == []
    assert [g["GroupId"] for g in instance(world)["SecurityGroups"]] == [world.worker_sg_id]


@pytest.mark.parametrize("param", ["true", "garbage"])
def test_switch_overrides_a_live_guard_decision(world: Any, clock: Any, param: str) -> None:
    world.set_dry_run(param)
    recorder = Recorder()
    result = pb01(world, clock, recorder).handle(
        events.payload("isolate", events.portscan(world.instance_id), dry_run=False)
    )
    assert result["contained"] is False
    assert recorder.mutating() == []


def test_sample_finding_in_dry_run_plans_only(world: Any, clock: Any) -> None:
    event = events.portscan("i-99999999", sample=True)
    result = pb01(world, clock).handle(events.payload("isolate", event, dry_run=True))
    assert result["would"] == "isolate"
    assert any("i-99999999" in step for step in result["plan"])
    snapshot_plan = pb01(world, clock).handle(events.payload("snapshot", event, dry_run=True))
    assert snapshot_plan["would"] == "snapshot"


# ---------------------------------------------------------------- payloads
@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {"action": "isolate"},
        {"action": "isolate", "event": "x"},
        {"action": "revoke", "event": {}},
        {"event": {}},
    ],
)
def test_bad_payload_raises(world: Any, clock: Any, payload: Any) -> None:
    with pytest.raises(PlaybookError):
        pb01(world, clock).handle(payload)


def test_malformed_finding_raises(world: Any, clock: Any) -> None:
    with pytest.raises(MalformedFindingError):
        pb01(world, clock).handle({"action": "isolate", "event": {"detail": {}}})


def test_non_instance_target_is_refused(world: Any, clock: Any) -> None:
    with pytest.raises(PlaybookError, match="EC2 instance target"):
        pb01(world, clock).handle(events.payload("isolate", events.public_bucket(world.bucket)))


# ----------------------------------------------------------------- snapshot
def test_snapshot_writes_checksummed_manifest(world: Any, clock: Any) -> None:
    event = exfil(world)
    world.seed_incident(event["detail"]["id"])

    result = pb01(world, clock).handle(events.payload("snapshot", event))

    assert len(result["snapshots"]) == 1
    snapshot_id = result["snapshots"][0]["snapshotId"]
    snap = boto3.client("ec2").describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]
    tags = {t["Key"]: t["Value"] for t in snap["Tags"]}
    assert tags["cloudshield:incident-id"] == event["detail"]["id"]
    assert tags["cloudshield:actor"] == EXECUTION_ARN

    key = result["evidence"]["key"]
    assert key == "incidents/f-pb01-exfil/pb01-ebs-manifest-20261014T100007Z.json"
    body = boto3.client("s3").get_object(Bucket=EVIDENCE_BUCKET, Key=key)["Body"].read()
    manifest = json.loads(body)
    assert manifest["actor"] == EXECUTION_ARN
    assert manifest["eventTime"] == "2026-10-14T10:00:00.000Z"
    assert manifest["findingCreatedAt"] == "2026-10-14T09:59:58.123Z"
    assert manifest["snapshots"][0]["snapshotId"] == snapshot_id

    digest = hashlib.sha256(body).digest()
    assert result["evidence"]["sha256"] == digest.hex()
    assert result["evidence"]["sha256Base64"] == base64.b64encode(digest).decode()
    row = world.incident(event["detail"]["id"])
    assert row["evidenceSha256"] == digest.hex()
    assert row["snapshotIds"] == [snapshot_id]


def test_snapshot_retry_reuses_snapshots(world: Any, clock: Any) -> None:
    event = exfil(world)
    world.seed_incident(event["detail"]["id"])
    first = pb01(world, clock).handle(events.payload("snapshot", event))
    second = pb01(world, clock).handle(events.payload("snapshot", event))
    assert first["snapshots"][0]["snapshotId"] == second["snapshots"][0]["snapshotId"]
    snaps = boto3.client("ec2").describe_snapshots(
        OwnerIds=["self"],
        Filters=[{"Name": "tag:cloudshield:incident-id", "Values": [event["detail"]["id"]]}],
    )["Snapshots"]
    assert len(snaps) == 1
    row = world.incident(event["detail"]["id"])
    assert len(row["evidenceRecords"]) == 2
    assert row["evidenceSha256"] == first["evidence"]["sha256"]  # first hash is kept


def test_snapshot_skips_untagged_volumes_and_fails_with_none(world: Any, clock: Any) -> None:
    volume = instance(world)["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]
    boto3.client("ec2").delete_tags(Resources=[volume], Tags=[{"Key": "cloudshield:soar-scope"}])
    event = events.portscan(world.instance_id)
    world.seed_incident(event["detail"]["id"])
    with pytest.raises(PlaybookError, match="no in-scope EBS volume"):
        pb01(world, clock).handle(events.payload("snapshot", event))


def test_snapshot_requires_incident_row(world: Any, clock: Any) -> None:
    with pytest.raises(LookupError):
        pb01(world, clock).handle(events.payload("snapshot", events.portscan(world.instance_id)))


def test_lambda_handler_entry_point(world: Any) -> None:
    event = events.portscan(world.instance_id)
    world.seed_incident(event["detail"]["id"])
    assert lambda_handler(events.payload("isolate", event), None)["contained"] is True
