"""PB-03: public S3 exposure (scenario C).

action "restore" runs BEFORE CONTAINED:
  1. refuse anything but a public-exposure finding (Policy:S3/Bucket*).
     Exfiltration:S3/* or Impact:S3/* by an authenticated principal is not
     stopped by Block Public Access (audit A1), so "contained" would be false.
  2. re-check the bucket's prefix and SOAR scope tag (guard + IAM + code)
  3. read the exposure as it is now (BPA flags, policy, policy status, ACL).
     This must come first, because step 4 overwrites the old BPA flags. The
     reads are single-attempt and short, and a failed read is recorded
     rather than raised, so evidence can never block containment.
  4. enable all four Block Public Access flags on the bucket
  5. verify; return contained + the pre-state for the router to pass on

action "evidence" runs AFTER CONTAINED (router step PB03Evidence), so the
upload never counts toward MTTC (ADR-0002 §3, audit A4): it writes the
pre-state as SHA-256-checksummed evidence and appends its hash to the row.

Bucket-level only: account-level BPA is deliberately not set (handoff gap 6).
"""

from __future__ import annotations

import contextlib
import json
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from core import aws
from core.aws import error_code
from core.evidence import EvidenceCollector
from core.finding import S3_EXPOSURE_PREFIX, Finding, S3BucketTarget, iso
from core.playbook import Playbook, PlaybookError

BPA_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _strip(response: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in response.items() if k != "ResponseMetadata"}


class Pb03S3RestoreBpa(Playbook):
    name = "pb03-s3-restore-bpa"
    actions = frozenset({"restore", "evidence"})

    def plan(self, action: str, finding: Finding) -> list[str]:
        target = finding.target
        bucket = target.bucket_name if isinstance(target, S3BucketTarget) else "<unresolved>"
        return [
            f"capture policy, ACL and BPA state of {bucket}",
            f"enable all four Block Public Access flags on {bucket}",
            "verify",
            "store the pre-state as hashed evidence (after CONTAINED)",
        ]

    def run(self, action: str, finding: Finding, state: dict[str, Any]) -> dict[str, Any]:
        target = finding.target
        if not isinstance(target, S3BucketTarget):
            raise PlaybookError("PB-03 needs an S3 bucket target")
        if action == "evidence":
            return self._evidence(finding, state)
        return self._restore(finding, target.bucket_name)

    # ------------------------------------------------------------------ restore
    def _restore(self, finding: Finding, bucket: str) -> dict[str, Any]:
        if not finding.type.startswith(S3_EXPOSURE_PREFIX):
            raise PlaybookError(
                f"{finding.type} is not a public-exposure finding; Block Public Access "
                "would not contain it"
            )
        if not bucket.startswith(self.settings.bucket_name_prefix):
            raise PlaybookError(f"bucket {bucket} is outside the project prefix")
        s3 = self.clients("s3")
        tags = self._bucket_tags(s3, bucket)
        if tags.get(self.settings.scope_tag_key) != self.settings.scope_tag_value:
            raise PlaybookError(f"bucket {bucket} lacks the SOAR scope tag")

        prestate = self._prestate(self.clients("s3", config=aws.QUICK), bucket)
        self.record(finding, "capture-prestate", bucket=bucket)

        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration=dict.fromkeys(BPA_FLAGS, True),
        )
        self.record(finding, "restore-bpa", bucket=bucket)

        def check() -> dict[str, bool]:
            after = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
            return {flag: after.get(flag) is True for flag in BPA_FLAGS}

        verified = self.verify_with_retry(check)
        return self.contained_result(finding, "restore", verified, bucket=bucket, prestate=prestate)

    @staticmethod
    def _bucket_tags(s3: Any, bucket: str) -> dict[str, str]:
        try:
            tag_set = s3.get_bucket_tagging(Bucket=bucket)["TagSet"]
        except ClientError as exc:
            if error_code(exc) == "NoSuchTagSet":
                return {}
            raise
        return {t["Key"]: t["Value"] for t in tag_set}

    def _prestate(self, s3: Any, bucket: str) -> dict[str, Any]:
        # Containment outranks evidence: a failed read is recorded in the
        # document instead of raising, so it can never block the restore.
        def capture(call: Any, missing: str | None = None) -> dict[str, Any] | None:
            try:
                return _strip(call(Bucket=bucket))
            except ClientError as exc:
                if missing and error_code(exc) == missing:
                    return None
                return {"captureError": error_code(exc) or type(exc).__name__}
            except BotoCoreError as exc:
                return {"captureError": type(exc).__name__}

        policy = capture(s3.get_bucket_policy, "NoSuchBucketPolicy")
        if policy and "Policy" in policy:
            # An unparsable policy is kept as the raw string: it is the evidence.
            with contextlib.suppress(ValueError):
                policy = {"Policy": json.loads(policy["Policy"])}
        return {
            "schema": "cloudshield.evidence.s3-exposure.v1",
            "bucket": bucket,
            "capturedAt": iso(self.clock()),
            "publicAccessBlock": capture(
                s3.get_public_access_block, "NoSuchPublicAccessBlockConfiguration"
            ),
            "policy": policy,
            "policyStatus": capture(s3.get_bucket_policy_status, "NoSuchBucketPolicy"),
            "acl": capture(s3.get_bucket_acl),
        }

    # ----------------------------------------------------------------- evidence
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
        key = f"incidents/{finding.id}/pb03-s3-prestate-{collected_at:%Y%m%dT%H%M%SZ}.json"
        record = EvidenceCollector(self.settings.evidence_bucket, self.clients("s3")).put_json(
            key, document
        )
        self.incidents.add_evidence(finding.id, record.to_dict())
        return {"evidence": record.to_dict()}


lambda_handler = Pb03S3RestoreBpa.lambda_handler
