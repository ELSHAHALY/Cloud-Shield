"""PB-03: public S3 exposure (scenario C).

1. read the exposure as it is now (BPA flags, policy, policy status, ACL).
   This must come first, because step 2 overwrites the old BPA flags.
2. re-enable all four Block Public Access flags on the bucket
3. verify; contained only if all four read back true
4. write the pre-state as SHA-256-checksummed evidence and store the hash on
   the incident row. This runs after verify, so it doesn't count toward MTTC,
   and an evidence failure is recorded without un-containing the incident.

Bucket-level only: account-level BPA is deliberately not set (handoff gap 6).
"""

from __future__ import annotations

import contextlib
import json
import logging
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from core.aws import error_code
from core.evidence import EvidenceCollector, EvidenceIntegrityError
from core.finding import Finding, S3BucketTarget, iso
from core.playbook import Playbook, PlaybookError

logger = logging.getLogger("cloudshield.soar.pb03")

BPA_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def _strip(response: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in response.items() if k != "ResponseMetadata"}


class Pb03S3RestoreBpa(Playbook):
    name = "pb03-s3-restore-bpa"
    actions = frozenset({"restore"})

    def plan(self, action: str, finding: Finding) -> list[str]:
        target = finding.target
        bucket = target.bucket_name if isinstance(target, S3BucketTarget) else "<unresolved>"
        return [
            f"capture policy, ACL and BPA state of {bucket}",
            f"enable all four Block Public Access flags on {bucket}",
            "verify",
            "store the pre-state as hashed evidence",
        ]

    def run(self, action: str, finding: Finding) -> dict[str, Any]:
        target = finding.target
        if not isinstance(target, S3BucketTarget):
            raise PlaybookError("PB-03 needs an S3 bucket target")
        bucket = target.bucket_name
        if not bucket.startswith(self.settings.bucket_name_prefix):
            raise PlaybookError(f"bucket {bucket} is outside the project prefix")
        s3 = self.clients("s3")

        prestate = self._prestate(s3, bucket)
        self.record(finding, "capture-prestate", bucket=bucket)

        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration=dict.fromkeys(BPA_FLAGS, True),
        )
        self.record(finding, "restore-bpa", bucket=bucket)

        after = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        verified = {flag: after.get(flag) is True for flag in BPA_FLAGS}

        evidence: dict[str, Any] | None = None
        evidence_error = None
        try:
            record = EvidenceCollector(self.settings.evidence_bucket, s3).put_json(
                f"incidents/{finding.id}/pb03-s3-prestate.json", prestate
            )
            evidence = record.to_dict()
            self.incidents.set_fields(
                finding.id, {"evidenceManifest": evidence, "evidenceSha256": record.sha256_hex}
            )
        except (ClientError, BotoCoreError, EvidenceIntegrityError) as exc:
            logger.exception("PB-03 evidence write failed")
            evidence_error = type(exc).__name__
            self.record(finding, "evidence-failed", error=evidence_error)

        return self.contained_result(
            finding,
            "restore",
            verified,
            bucket=bucket,
            evidence=evidence,
            evidenceError=evidence_error,
        )

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


lambda_handler = Pb03S3RestoreBpa.lambda_handler
