"""Shared moto world: the dev environment's SOAR-relevant resources, in miniature."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import boto3
import pytest
from moto import mock_aws

from core.config import Settings

REGION = "us-east-1"
SCOPE_KEY, SCOPE_VALUE = "cloudshield:soar-scope", "in-scope"
SCOPE_TAG = [{"Key": SCOPE_KEY, "Value": SCOPE_VALUE}]
DRY_RUN_PARAM = "/cs-dev/soar/dry_run"
INCIDENTS_TABLE = "cs-dev-soar-incidents"
EVIDENCE_BUCKET = "cs-dev-soar-evidence-123456789012"
EXECUTION_ARN = "arn:aws:states:us-east-1:123456789012:execution:cs-dev-cs-ir-router:run-1"
NOW = datetime(2026, 10, 14, 10, 0, 7, tzinfo=UTC)
AMI = "ami-12c6146b"


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # Never let a test reach a real account.
    for name, value in {
        "AWS_DEFAULT_REGION": REGION,
        "AWS_REGION": REGION,
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@dataclass
class World:
    vpc_id: str
    worker_subnet_id: str
    app_subnet_id: str
    worker_nacl_id: str
    quarantine_sg_id: str
    worker_sg_id: str
    role_arn: str
    instance_id: str
    untagged_instance_id: str
    user_name: str
    access_key_id: str
    untagged_user_name: str
    untagged_access_key_id: str
    bucket: str
    untagged_bucket: str
    settings: Settings
    env: dict[str, str]

    def seed_incident(self, incident_id: str, **extra: Any) -> None:
        item = {
            "incidentId": {"S": incident_id},
            "status": {"S": "DETECTED"},
            "executionArn": {"S": EXECUTION_ARN},
        }
        item.update(extra)
        boto3.client("dynamodb").put_item(TableName=INCIDENTS_TABLE, Item=item)

    def incident(self, incident_id: str) -> dict[str, Any]:
        from core.incidents import IncidentRepository

        return IncidentRepository(INCIDENTS_TABLE, boto3.client("dynamodb")).get(incident_id)

    def set_dry_run(self, value: str) -> None:
        boto3.client("ssm").put_parameter(
            Name=DRY_RUN_PARAM, Value=value, Type="String", Overwrite=True
        )


def _instance(ec2: Any, subnet: str, sg: str, *, tagged: bool, profile: str | None) -> str:
    tags = (
        [*SCOPE_TAG, {"Key": "Name", "Value": "report-worker"}]
        if tagged
        else [{"Key": "Name", "Value": "other"}]
    )
    kwargs: dict[str, Any] = {
        "ImageId": AMI,
        "MinCount": 1,
        "MaxCount": 1,
        "InstanceType": "t3.micro",
        "SubnetId": subnet,
        "SecurityGroupIds": [sg],
        "TagSpecifications": [
            {"ResourceType": "instance", "Tags": tags},
            {"ResourceType": "volume", "Tags": SCOPE_TAG if tagged else tags},
        ],
    }
    if profile:
        kwargs["IamInstanceProfile"] = {"Name": profile}
    return ec2.run_instances(**kwargs)["Instances"][0]["InstanceId"]


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    with mock_aws():
        ec2, iam = boto3.client("ec2"), boto3.client("iam")
        s3, ddb, ssm = boto3.client("s3"), boto3.client("dynamodb"), boto3.client("ssm")

        vpc = ec2.create_vpc(CidrBlock="10.20.0.0/16")["Vpc"]["VpcId"]
        worker_subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.20.20.0/24")["Subnet"][
            "SubnetId"
        ]
        app_subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.20.10.0/24")["Subnet"]["SubnetId"]

        # Dedicated worker-tier NACL, as modules/network creates it.
        nacl = ec2.create_network_acl(VpcId=vpc)["NetworkAcl"]["NetworkAclId"]
        for egress in (False, True):
            ec2.create_network_acl_entry(
                NetworkAclId=nacl,
                RuleNumber=100,
                Protocol="-1",
                RuleAction="allow",
                Egress=egress,
                CidrBlock="0.0.0.0/0",
            )
        current = ec2.describe_network_acls(
            Filters=[{"Name": "association.subnet-id", "Values": [worker_subnet]}]
        )["NetworkAcls"][0]
        association = next(
            a["NetworkAclAssociationId"]
            for a in current["Associations"]
            if a["SubnetId"] == worker_subnet
        )
        ec2.replace_network_acl_association(AssociationId=association, NetworkAclId=nacl)

        quarantine = ec2.create_security_group(
            GroupName="cs-dev-quarantine", Description="q", VpcId=vpc
        )["GroupId"]
        worker_sg = ec2.create_security_group(
            GroupName="cs-dev-worker", Description="w", VpcId=vpc
        )["GroupId"]

        role_arn = iam.create_role(RoleName="cs-dev-report-worker", AssumeRolePolicyDocument="{}")[
            "Role"
        ]["Arn"]
        iam.create_instance_profile(InstanceProfileName="cs-dev-report-worker")
        iam.add_role_to_instance_profile(
            InstanceProfileName="cs-dev-report-worker", RoleName="cs-dev-report-worker"
        )

        instance = _instance(
            ec2, worker_subnet, worker_sg, tagged=True, profile="cs-dev-report-worker"
        )
        untagged_instance = _instance(ec2, worker_subnet, worker_sg, tagged=False, profile=None)

        iam.create_user(UserName="cs-dev-honeytoken", Tags=SCOPE_TAG)
        key = iam.create_access_key(UserName="cs-dev-honeytoken")["AccessKey"]["AccessKeyId"]
        iam.create_user(UserName="alice")
        alice_key = iam.create_access_key(UserName="alice")["AccessKey"]["AccessKeyId"]

        s3.create_bucket(Bucket="cs-dev-public-docs")
        s3.put_bucket_tagging(Bucket="cs-dev-public-docs", Tagging={"TagSet": SCOPE_TAG})
        s3.create_bucket(Bucket="cs-dev-untagged")
        s3.create_bucket(Bucket=EVIDENCE_BUCKET)
        s3.put_bucket_versioning(
            Bucket=EVIDENCE_BUCKET, VersioningConfiguration={"Status": "Enabled"}
        )

        ddb.create_table(
            TableName=INCIDENTS_TABLE,
            BillingMode="PAY_PER_REQUEST",
            KeySchema=[{"AttributeName": "incidentId", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "incidentId", "AttributeType": "S"}],
        )
        ssm.put_parameter(Name=DRY_RUN_PARAM, Value="false", Type="String")

        env = {
            "DRY_RUN_PARAM": DRY_RUN_PARAM,
            "SCOPE_TAG_PARAM": "/cs-dev/soar/scope_tag",
            "SCOPE_TAG_KEY": SCOPE_KEY,
            "SCOPE_TAG_VALUE": SCOPE_VALUE,
            "INCIDENTS_TABLE": INCIDENTS_TABLE,
            "EVIDENCE_BUCKET": EVIDENCE_BUCKET,
            "QUARANTINE_SG_ID": quarantine,
            "QUARANTINE_NACL_IDS": nacl,
            "QUARANTINE_NACL_RULE": "10",
            "REVOCABLE_ROLE_ARNS": role_arn,
            "BUCKET_NAME_PREFIX": "cs-dev-",
        }
        for name, value in env.items():
            monkeypatch.setenv(name, value)

        yield World(
            vpc_id=vpc,
            worker_subnet_id=worker_subnet,
            app_subnet_id=app_subnet,
            worker_nacl_id=nacl,
            quarantine_sg_id=quarantine,
            worker_sg_id=worker_sg,
            role_arn=role_arn,
            instance_id=instance,
            untagged_instance_id=untagged_instance,
            user_name="cs-dev-honeytoken",
            access_key_id=key,
            untagged_user_name="alice",
            untagged_access_key_id=alice_key,
            bucket="cs-dev-public-docs",
            untagged_bucket="cs-dev-untagged",
            settings=Settings.from_env(env),
            env=env,
        )


@pytest.fixture
def clock() -> Any:
    return lambda: NOW
