"""PB-01: EC2 isolation (scenario A: IMDS credential theft / port scan).

action "isolate" runs BEFORE CONTAINED (Figure 6.5: containment before evidence):
  1. NACL deny-all on the worker-tier NACL: stateless, so it cuts the
     connections the SG swap leaves alive (ADR-0003, handoff gap 10)
  2. swap the instance onto the quarantine security group
  3. termination + stop protection, so the evidence cannot be destroyed
  4. revoke the instance role's active sessions (stolen IMDS credentials)
  5. record ASG membership for the analyst (detect only)
  6. verify everything by re-describing; contained only if all checks pass

action "snapshot" runs AFTER CONTAINED: EBS snapshots of in-scope volumes plus
a SHA-256-checksummed manifest in the evidence bucket.

Every step is idempotent, because the router retries Lambda service errors.
"""

from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from core.aws import error_code
from core.evidence import EvidenceCollector
from core.finding import Ec2Target, Finding, iso
from core.playbook import Playbook, PlaybookError

REVOKE_POLICY_NAME = "cloudshield-soar-revoke-older-sessions"
_TAG_PREFIX = "cloudshield:"


def _instance_role_name(role_arn: str) -> str:
    return role_arn.rsplit("/", 1)[-1]


class Pb01Ec2Isolate(Playbook):
    name = "pb01-ec2-isolate"
    actions = frozenset({"isolate", "snapshot"})

    def plan(self, action: str, finding: Finding) -> list[str]:
        target = finding.target
        instance = target.instance_id if isinstance(target, Ec2Target) else "<unresolved>"
        if action == "snapshot":
            return [
                f"snapshot in-scope EBS volumes of {instance}",
                "write SHA-256 manifest to the evidence bucket",
            ]
        return [
            f"add deny-all NACL entries (rule {self.settings.quarantine_nacl_rule}) "
            f"on the subnet NACL of {instance}",
            f"swap {instance} onto {self.settings.quarantine_sg_id}",
            "enable termination and stop protection",
            "revoke the instance role's active sessions",
            "verify isolation",
        ]

    def run(self, action: str, finding: Finding) -> dict[str, Any]:
        if not isinstance(finding.target, Ec2Target):
            raise PlaybookError("PB-01 needs an EC2 instance target")
        if action == "isolate":
            return self._isolate(finding, finding.target.instance_id)
        return self._snapshot(finding, finding.target.instance_id)

    # ------------------------------------------------------------------ helpers
    def _describe(self, instance_id: str) -> dict[str, Any]:
        reservations = self.clients("ec2").describe_instances(InstanceIds=[instance_id])
        instances = [
            i for r in reservations.get("Reservations", []) for i in r.get("Instances", [])
        ]
        if len(instances) != 1:
            raise PlaybookError(f"instance {instance_id} not found")
        instance = instances[0]
        tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        # Defence in depth: the guard checked this, IAM enforces it, and so do we.
        if tags.get(self.settings.scope_tag_key) != self.settings.scope_tag_value:
            raise PlaybookError(f"instance {instance_id} lacks the SOAR scope tag")
        return instance

    def _subnet_nacl(self, subnet_id: str) -> dict[str, Any]:
        acls = (
            self.clients("ec2")
            .describe_network_acls(
                Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}],
            )
            .get("NetworkAcls", [])
        )
        if len(acls) != 1:
            raise PlaybookError(f"cannot resolve the NACL of subnet {subnet_id}")
        if acls[0]["NetworkAclId"] not in self.settings.quarantine_nacl_ids:
            raise PlaybookError(
                f"NACL {acls[0]['NetworkAclId']} is not a quarantine NACL; refusing to isolate"
            )
        return acls[0]

    def _quarantine_entry_present(self, nacl: dict[str, Any], egress: bool) -> bool:
        rule = self.settings.quarantine_nacl_rule
        return any(
            e.get("RuleNumber") == rule
            and e.get("Egress") is egress
            and e.get("RuleAction") == "deny"
            and e.get("Protocol") == "-1"
            and e.get("CidrBlock") == "0.0.0.0/0"
            for e in nacl.get("Entries", [])
        )

    def _role_arn(self, instance: dict[str, Any]) -> str | None:
        profile = instance.get("IamInstanceProfile")
        if not profile:
            return None
        profile_name = profile["Arn"].rsplit("/", 1)[-1]
        roles = (
            self.clients("iam")
            .get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
            .get("Roles", [])
        )
        if len(roles) != 1:
            raise PlaybookError(f"instance profile {profile_name} must hold exactly one role")
        return roles[0]["Arn"]

    # ------------------------------------------------------------------ isolate
    def _isolate(self, finding: Finding, instance_id: str) -> dict[str, Any]:
        ec2 = self.clients("ec2")
        instance = self._describe(instance_id)

        enis = instance.get("NetworkInterfaces", [])
        if len(enis) != 1:
            # A multi-ENI swap needs ModifyNetworkInterfaceAttribute, which is
            # not granted. Fail rather than leave an interface un-isolated.
            raise PlaybookError(f"{instance_id} has {len(enis)} ENIs; PB-01 isolates exactly one")

        nacl = self._subnet_nacl(instance["SubnetId"])
        role_arn = self._role_arn(instance)
        if role_arn is not None and role_arn not in self.settings.revocable_role_arns:
            raise PlaybookError(
                f"role {role_arn} is not revocable; stolen credentials would "
                "stay valid, so this is not containment"
            )

        # 1. NACL deny-all, ingress and egress. Already-present = done (retry).
        for egress in (False, True):
            try:
                ec2.create_network_acl_entry(
                    NetworkAclId=nacl["NetworkAclId"],
                    RuleNumber=self.settings.quarantine_nacl_rule,
                    Protocol="-1",
                    RuleAction="deny",
                    Egress=egress,
                    CidrBlock="0.0.0.0/0",
                )
            except ClientError as exc:
                if error_code(exc) != "NetworkAclEntryAlreadyExists":
                    raise
        self.record(
            finding,
            "nacl-deny",
            networkAclId=nacl["NetworkAclId"],
            ruleNumber=self.settings.quarantine_nacl_rule,
        )

        # 2. Security-group swap.
        previous_groups = [g["GroupId"] for g in instance.get("SecurityGroups", [])]
        ec2.modify_instance_attribute(
            InstanceId=instance_id, Groups=[self.settings.quarantine_sg_id]
        )
        self.record(
            finding,
            "sg-swap",
            previousGroups=previous_groups,
            quarantineGroup=self.settings.quarantine_sg_id,
        )

        # 3. Termination + stop protection (one attribute per call).
        ec2.modify_instance_attribute(InstanceId=instance_id, DisableApiTermination={"Value": True})
        ec2.modify_instance_attribute(InstanceId=instance_id, DisableApiStop={"Value": True})
        self.record(finding, "protection", disableApiTermination=True, disableApiStop=True)

        # 4. Revoke the instance role's sessions issued before now.
        revoked_role = None
        if role_arn is not None:
            self.clients("iam").put_role_policy(
                RoleName=_instance_role_name(role_arn),
                PolicyName=REVOKE_POLICY_NAME,
                PolicyDocument=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "CloudShieldRevokeOlderSessions",
                                "Effect": "Deny",
                                "Action": "*",
                                "Resource": "*",
                                "Condition": {
                                    "DateLessThan": {"aws:TokenIssueTime": iso(self.clock())}
                                },
                            }
                        ],
                    }
                ),
            )
            revoked_role = role_arn
            self.record(finding, "revoke-role-sessions", roleArn=role_arn)

        # 5. ASG membership: an ASG could replace or terminate the instance.
        asg = (
            self.clients("autoscaling")
            .describe_auto_scaling_instances(InstanceIds=[instance_id])
            .get("AutoScalingInstances", [])
        )
        asg_name = asg[0]["AutoScalingGroupName"] if asg else None
        if asg_name:
            self.record(
                finding,
                "asg-attached",
                autoScalingGroup=asg_name,
                note="detach manually; PB-01 has no autoscaling write permission",
            )

        # 6. Verify by re-reading AWS, never by trusting our own calls.
        verified = self._verify_isolation(instance_id, nacl["NetworkAclId"])
        return self.contained_result(
            finding,
            "isolate",
            verified,
            instanceId=instance_id,
            networkAclId=nacl["NetworkAclId"],
            revokedRole=revoked_role,
            autoScalingGroup=asg_name,
        )

    def _verify_isolation(self, instance_id: str, nacl_id: str) -> dict[str, bool]:
        ec2 = self.clients("ec2")
        instance = self._describe(instance_id)
        groups = [g["GroupId"] for g in instance.get("SecurityGroups", [])]
        nacl = ec2.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"][0]
        termination = ec2.describe_instance_attribute(
            InstanceId=instance_id, Attribute="disableApiTermination"
        )["DisableApiTermination"]
        stop = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="disableApiStop")[
            "DisableApiStop"
        ]
        return {
            "onlyQuarantineGroup": groups == [self.settings.quarantine_sg_id],
            "naclIngressDeny": self._quarantine_entry_present(nacl, egress=False),
            "naclEgressDeny": self._quarantine_entry_present(nacl, egress=True),
            "terminationProtection": termination.get("Value") is True,
            "stopProtection": stop.get("Value") is True,
        }

    # ----------------------------------------------------------------- snapshot
    def _snapshot(self, finding: Finding, instance_id: str) -> dict[str, Any]:
        ec2 = self.clients("ec2")
        instance = self._describe(instance_id)
        actor = self.incidents.get(finding.id).get("executionArn", "unknown")

        volume_ids = sorted(
            m["Ebs"]["VolumeId"] for m in instance.get("BlockDeviceMappings", []) if "Ebs" in m
        )
        volumes = (
            ec2.describe_volumes(VolumeIds=volume_ids).get("Volumes", []) if volume_ids else []
        )

        snapshots, skipped = [], []
        for volume in sorted(volumes, key=lambda v: v["VolumeId"]):
            tags = {t["Key"]: t["Value"] for t in volume.get("Tags", [])}
            if tags.get(self.settings.scope_tag_key) != self.settings.scope_tag_value:
                # IAM would refuse anyway; record it rather than fail the rest.
                skipped.append({"volumeId": volume["VolumeId"], "reason": "no SOAR scope tag"})
                continue
            snapshot = ec2.create_snapshot(
                VolumeId=volume["VolumeId"],
                Description=f"CloudShield forensic snapshot, incident {finding.id}",
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": f"{_TAG_PREFIX}incident-id", "Value": finding.id},
                            {"Key": f"{_TAG_PREFIX}finding-type", "Value": finding.type[:256]},
                            {"Key": f"{_TAG_PREFIX}source-instance", "Value": instance_id},
                            {"Key": f"{_TAG_PREFIX}source-volume", "Value": volume["VolumeId"]},
                            {"Key": f"{_TAG_PREFIX}actor", "Value": str(actor)[:256]},
                        ],
                    }
                ],
            )
            snapshots.append(
                {
                    "volumeId": volume["VolumeId"],
                    "snapshotId": snapshot["SnapshotId"],
                    "startTime": iso(snapshot["StartTime"]),
                }
            )
        if not snapshots:
            raise PlaybookError(f"no in-scope EBS volume on {instance_id}; no evidence captured")
        self.record(finding, "ebs-snapshots", snapshotIds=[s["snapshotId"] for s in snapshots])

        collected_at = self.clock()
        manifest = {
            "schema": "cloudshield.evidence.ebs.v1",
            "incidentId": finding.id,
            "findingType": finding.type,
            "eventTime": iso(finding.event_time),
            "findingCreatedAt": iso(finding.created_at) if finding.created_at else None,
            "instanceId": instance_id,
            "snapshots": snapshots,
            "skippedVolumes": skipped,
            "actor": actor,
            "collectedAt": iso(collected_at),
        }
        key = f"incidents/{finding.id}/pb01-ebs-manifest-{collected_at:%Y%m%dT%H%M%SZ}.json"
        record = EvidenceCollector(self.settings.evidence_bucket, self.clients("s3")).put_json(
            key, manifest
        )
        self.incidents.set_fields(
            finding.id,
            {
                "evidenceManifest": record.to_dict(),
                "evidenceSha256": record.sha256_hex,
                "snapshotIds": [s["snapshotId"] for s in snapshots],
            },
        )
        return {"evidence": record.to_dict(), "snapshots": snapshots, "skippedVolumes": skipped}


lambda_handler = Pb01Ec2Isolate.lambda_handler
