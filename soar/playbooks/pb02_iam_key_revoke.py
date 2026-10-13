"""PB-02: leaked IAM user access key (scenario B).

1. deactivate the key: this IS the containment
2. revoke sessions derived from the user (inline deny on aws:TokenIssueTime).
   IAM only allows this on users carrying the SOAR target permissions
   boundary (audit M10). If it is refused, that is recorded but does not undo
   the containment, because the key itself is already dead.
3. verify via ListAccessKeys; contained only if the key reads Inactive
"""

from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from core.aws import error_code
from core.finding import Finding, IamUserTarget, iso
from core.playbook import Playbook, PlaybookError

REVOKE_POLICY_NAME = "cloudshield-soar-revoke-older-sessions"


class Pb02IamKeyRevoke(Playbook):
    name = "pb02-iam-key-revoke"
    actions = frozenset({"revoke"})

    def plan(self, action: str, finding: Finding) -> list[str]:
        target = finding.target
        user = target.user_name if isinstance(target, IamUserTarget) else "<unresolved>"
        return [
            f"deactivate the access key of IAM user {user}",
            "revoke sessions issued before now",
            "verify the key is Inactive",
        ]

    def run(self, action: str, finding: Finding) -> dict[str, Any]:
        target = finding.target
        if not isinstance(target, IamUserTarget):
            raise PlaybookError("PB-02 needs an IAM user access-key target")
        iam = self.clients("iam")

        iam.update_access_key(
            UserName=target.user_name, AccessKeyId=target.access_key_id, Status="Inactive"
        )
        self.record(
            finding, "deactivate-key", userName=target.user_name, accessKeyId=target.access_key_id
        )

        try:
            iam.put_user_policy(
                UserName=target.user_name,
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
            session_revoke = "applied"
        except ClientError as exc:
            if error_code(exc) != "AccessDenied":
                raise
            session_revoke = "denied-by-permissions-boundary-guardrail"
        self.record(finding, "revoke-user-sessions", result=session_revoke)

        status = None
        for page in iam.get_paginator("list_access_keys").paginate(UserName=target.user_name):
            for key in page.get("AccessKeyMetadata", []):
                if key["AccessKeyId"] == target.access_key_id:
                    status = key["Status"]
        if status is None:
            raise PlaybookError(
                f"access key {target.access_key_id} not found on {target.user_name}"
            )

        return self.contained_result(
            finding,
            "revoke",
            {"keyInactive": status == "Inactive"},
            userName=target.user_name,
            accessKeyId=target.access_key_id,
            sessionRevoke=session_revoke,
        )


lambda_handler = Pb02IamKeyRevoke.lambda_handler
