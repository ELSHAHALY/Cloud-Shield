"""PB-02: leaked IAM user access key (scenario B).

1. re-check the user's SOAR scope tag (defence in depth: guard + IAM + code)
2. revoke the user's temporary sessions: inline deny on aws:TokenIssueTime
   < now. Deactivating a key does NOT invalidate GetSessionToken /
   GetFederationToken credentials already minted from it (valid up to 36 h),
   so this is part of containment, not an extra (audit A2). IAM allows it
   only on users carrying the SOAR target permissions boundary.
3. deactivate the key. If the finding names a temporary (ASIA...) key, the
   long-term keys that can mint new sessions are deactivated instead.
4. verify both by reading back; contained only if every check passes

Limit (documented, not handled): sessions from roles the user assumed
(AssumeRole) belong to those roles, so a user inline policy can't revoke them.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from core.aws import error_code
from core.finding import Finding, IamUserTarget
from core.playbook import (
    REVOKE_POLICY_NAME,
    Playbook,
    PlaybookError,
    is_revoke_policy,
    session_revoke_policy,
)


class Pb02IamKeyRevoke(Playbook):
    name = "pb02-iam-key-revoke"
    actions = frozenset({"revoke"})

    def plan(self, action: str, finding: Finding) -> list[str]:
        target = finding.target
        user = target.user_name if isinstance(target, IamUserTarget) else "<unresolved>"
        return [
            f"revoke sessions of IAM user {user} issued before now",
            f"deactivate the leaked access key of {user}",
            "verify sessions revoked and key Inactive",
        ]

    def run(self, action: str, finding: Finding, state: dict[str, Any]) -> dict[str, Any]:
        target = finding.target
        if not isinstance(target, IamUserTarget):
            raise PlaybookError("PB-02 needs an IAM user access-key target")
        iam = self.clients("iam")
        user = target.user_name

        tags: dict[str, str] = {}
        for page in iam.get_paginator("list_user_tags").paginate(UserName=user):
            tags.update({t["Key"]: t["Value"] for t in page.get("Tags", [])})
        if tags.get(self.settings.scope_tag_key) != self.settings.scope_tag_value:
            raise PlaybookError(f"IAM user {user} lacks the SOAR scope tag")

        # Sessions first: it must be attempted even if the key step fails.
        try:
            iam.put_user_policy(
                UserName=user,
                PolicyName=REVOKE_POLICY_NAME,
                PolicyDocument=session_revoke_policy(self.clock()),
            )
            session_revoke = "applied"
        except ClientError as exc:
            if error_code(exc) != "AccessDenied":
                raise
            # Most likely the user lacks the SOAR target boundary. Recorded,
            # and verification below then reports NOT contained.
            session_revoke = "denied (user lacks the SOAR target permissions boundary?)"
        self.record(finding, "revoke-user-sessions", result=session_revoke)

        keys = self._keys(iam, user)
        if target.access_key_id.startswith("ASIA"):
            to_deactivate = sorted(k for k, status in keys.items() if status == "Active")
        else:
            if target.access_key_id not in keys:
                raise PlaybookError(f"access key {target.access_key_id} not found on {user}")
            to_deactivate = [target.access_key_id]
        for key_id in to_deactivate:
            iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
        self.record(finding, "deactivate-keys", userName=user, accessKeyIds=to_deactivate)

        after = self._keys(iam, user)
        verified = {
            "keysInactive": all(after.get(k) == "Inactive" for k in to_deactivate),
            "sessionsRevoked": self._revoke_policy_present(iam, user),
        }
        return self.contained_result(
            finding,
            "revoke",
            verified,
            userName=user,
            deactivatedKeys=to_deactivate,
            sessionRevoke=session_revoke,
        )

    @staticmethod
    def _keys(iam: Any, user: str) -> dict[str, str]:
        keys: dict[str, str] = {}
        for page in iam.get_paginator("list_access_keys").paginate(UserName=user):
            keys.update({k["AccessKeyId"]: k["Status"] for k in page.get("AccessKeyMetadata", [])})
        return keys

    @staticmethod
    def _revoke_policy_present(iam: Any, user: str) -> bool:
        try:
            document = iam.get_user_policy(UserName=user, PolicyName=REVOKE_POLICY_NAME)[
                "PolicyDocument"
            ]
        except ClientError as exc:
            if error_code(exc) == "NoSuchEntity":
                return False
            raise
        return is_revoke_policy(document)


lambda_handler = Pb02IamKeyRevoke.lambda_handler
