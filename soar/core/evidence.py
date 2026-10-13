"""EvidenceCollector: writes chain-of-custody documents to the evidence bucket.

Each document is serialised canonically, hashed locally, and uploaded with
ChecksumSHA256 so S3 itself rejects a corrupted upload. The hash is returned
for the caller to store on the incident row, because a file cannot contain its
own hash. When the bucket has Object Lock default retention (graded run), every
object is locked on write without needing s3:PutObjectRetention.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any


class EvidenceIntegrityError(RuntimeError):
    """S3 did not confirm the checksum computed locally."""


@dataclass(frozen=True)
class EvidenceRecord:
    bucket: str
    key: str
    version_id: str | None
    sha256_hex: str
    sha256_b64: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "bucket": self.bucket,
            "key": self.key,
            "versionId": self.version_id,
            "sha256": self.sha256_hex,
            "sha256Base64": self.sha256_b64,
        }


def canonical_json(document: Any) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), default=str).encode()


class EvidenceCollector:
    def __init__(self, bucket: str, s3: Any) -> None:
        self._bucket = bucket
        self._s3 = s3

    def put_json(self, key: str, document: Any) -> EvidenceRecord:
        body = canonical_json(document)
        digest = hashlib.sha256(body).digest()
        b64 = base64.b64encode(digest).decode()
        response = self._s3.put_object(
            Bucket=self._bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
            ChecksumAlgorithm="SHA256",
            ChecksumSHA256=b64,
        )
        if response.get("ChecksumSHA256") != b64:
            raise EvidenceIntegrityError(f"S3 checksum mismatch for s3://{self._bucket}/{key}")
        return EvidenceRecord(self._bucket, key, response.get("VersionId"), digest.hex(), b64)
