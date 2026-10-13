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
from core.playbook import PlaybookError
from playbooks.pb01_ec2_isolate import REVOKE_POLICY_NAME, Pb01Ec2Isolate, lambda_handler
from tests import events
from tests.conftest import EVIDENCE_BUCKET, EXECUTION_ARN


def pb01(world: Any, clock: Any, clients: Any = None) -> Pb01Ec2Isolate:
    return Pb01Ec2Isolate(world.settings, clients or boto3.client, clock)


def nacl_entries(world: Any) -> list[dict[str, Any]]:
    acl = boto3.client("ec2").describe_network_acls(NetworkAclIds=[world.worker_nacl_id])
    return acl["NetworkAcls"][0]["Entries"]


def instance(world: Any) -> dict[str, Any]:
    return boto3.client("ec2").describe_instances(InstanceIds=[world.instance_id])["Reservations"][
        0
    ]["Instances"][0]


class Recorder:
    """Client factory that records every call made through it."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def __call__(self, service: str) -> Any:
        real = boto3.client(service)
        recorder = self

        class Proxy:
            def __getattr__(self, name: str) -> Any:
                attr = getattr(real, name)
                if callable(attr):

                    def wrapped(*a: Any, **kw: Any) -> Any:
                        recorder.calls.append((service, name))
                        return attr(*a, **kw)

                    return wrapped
                return attr

        return Proxy()

    def mutating(self) -> list[tuple[str, str]]:
        reads = ("describe_", "get_", "list_")
        return [c for c in self.calls if not c[1].startswith(reads)]


# ------------------------------------------------------------- isolate: live
@pytest.mark.parametrize("make_event", [events.portscan, events.exfiltration])
def test_isolate_contains_and_verifies(world: Any, clock: Any, make_event: Any) -> None:
    event = make_event(world.instance_id)
    world.seed_incident(event["detail"]["id"])

    result = pb01(world, clock).handle(events.payload("isolate", event))

    assert result["contained"] is True
    assert result["verified"] == {
        "onlyQuarantineGroup": True,
        "naclIngressDeny": True,
        "naclEgressDeny": True,
        "terminationProtection": True,
        "stopProtection": True,
    }
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
    assert statement["Condition"] == {
        "DateLessThan": {"aws:TokenIssueTime": "2026-10-14T10:00:07.000Z"}
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


# ----------------------------------------------------------- isolate: refusals
def test_untagged_instance_is_refused(world: Any, clock: Any) -> None:
    event = events.portscan(world.untagged_instance_id)
    with pytest.raises(PlaybookError, match="scope tag"):
        pb01(world, clock).handle(events.payload("isolate", event))


def test_nacl_not_in_allow_list_is_refused(
    world: Any, clock: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = world.settings.__class__.from_env({**world.env, "QUARANTINE_NACL_IDS": ""})
    event = events.portscan(world.instance_id)
    with pytest.raises(PlaybookError, match="not a quarantine NACL"):
        Pb01Ec2Isolate(settings, boto3.client, clock).handle(events.payload("isolate", event))
    assert [g["GroupId"] for g in instance(world)["SecurityGroups"]] == [world.worker_sg_id]


def test_role_not_revocable_is_refused_before_any_change(world: Any, clock: Any) -> None:
    settings = world.settings.__class__.from_env({**world.env, "REVOCABLE_ROLE_ARNS": ""})
    event = events.exfiltration(world.instance_id)
    with pytest.raises(PlaybookError, match="not revocable"):
        Pb01Ec2Isolate(settings, boto3.client, clock).handle(events.payload("isolate", event))
    assert not [e for e in nacl_entries(world) if e["RuleNumber"] == 10]


def test_multi_eni_instance_is_refused(world: Any, clock: Any) -> None:
    ec2 = boto3.client("ec2")
    eni = ec2.create_network_interface(SubnetId=world.worker_subnet_id)["NetworkInterface"]
    ec2.attach_network_interface(
        NetworkInterfaceId=eni["NetworkInterfaceId"], InstanceId=world.instance_id, DeviceIndex=1
    )
    with pytest.raises(PlaybookError, match="ENIs"):
        pb01(world, clock).handle(events.payload("isolate", events.portscan(world.instance_id)))


def test_aws_error_propagates_so_router_records_failed(world: Any, clock: Any) -> None:
    def clients(service: str) -> Any:
        real = boto3.client(service)
        if service != "ec2":
            return real

        class Ec2:
            def __getattr__(self, name: str) -> Any:
                return getattr(real, name)

            def modify_instance_attribute(self, **_: Any) -> Any:
                raise ClientError(
                    {"Error": {"Code": "UnauthorizedOperation"}}, "ModifyInstanceAttribute"
                )

        return Ec2()

    event = events.portscan(world.instance_id)
    world.seed_incident(event["detail"]["id"])
    with pytest.raises(ClientError):
        pb01(world, clock, clients).handle(events.payload("isolate", event))


def test_unresolvable_exfiltration_principal_is_refused(world: Any, clock: Any) -> None:
    event = events.exfiltration(world.instance_id)
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


# ----------------------------------------------------------------- snapshot
def test_snapshot_writes_checksummed_manifest(world: Any, clock: Any) -> None:
    event = events.exfiltration(world.instance_id)
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


def test_snapshot_skips_untagged_volumes_and_fails_with_none(world: Any, clock: Any) -> None:
    ec2 = boto3.client("ec2")
    volume = instance(world)["BlockDeviceMappings"][0]["Ebs"]["VolumeId"]
    ec2.delete_tags(Resources=[volume], Tags=[{"Key": "cloudshield:soar-scope"}])
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
