"""Incident Response report from an incident id (FR-8, success criterion 06).

    python -m tools.generate_ir_report <incident-id> [--format md|json] [--output FILE]

Read-only: dynamodb:GetItem on the incidents table and s3:GetObject (+
kms:Decrypt) on the evidence bucket. Every evidence object listed on the row
is downloaded and its SHA-256 RECOMPUTED, so the report verifies the chain of
custody instead of repeating what the row claims.

Exit codes: 0 report written; 1 incident not found / bad input;
2 report written but an evidence hash did not match (chain of custody broken).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from core import aws
from core.incidents import IncidentRepository

MTTC_TARGET_SECONDS = 60.0


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo else None


def _seconds(start: datetime | None, end: datetime | None) -> float | None:
    if start is None or end is None:
        return None
    return round((end - start).total_seconds(), 3)


@dataclass
class EvidenceCheck:
    key: str
    version_id: str | None
    recorded_sha256: str | None
    actual_sha256: str | None
    ok: bool
    error: str | None = None


@dataclass
class IrReport:
    incident_id: str
    status: str
    finding_type: str | None
    severity: float | None
    resource_type: str | None
    finding_created_at: str | None
    event_time: str | None
    contained_at: str | None
    containment_verified: bool | None
    mttc_seconds: float | None
    detection_latency_seconds: float | None
    mttc_target_met: bool | None
    execution_arn: str | None
    actions: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[EvidenceCheck] = field(default_factory=list)
    guard_reason: str | None = None
    failure: str | None = None

    @property
    def chain_of_custody_ok(self) -> bool | None:
        """None = no evidence expected/recorded; else every hash matched."""
        if not self.evidence:
            return None
        return all(e.ok for e in self.evidence)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["chain_of_custody_ok"] = self.chain_of_custody_ok
        return data

    def to_markdown(self) -> str:
        def show(value: Any) -> str:
            return "—" if value is None else str(value)

        mttc = (
            f"{self.mttc_seconds:.3f} s ({'meets' if self.mttc_target_met else 'MISSES'} "
            f"the {MTTC_TARGET_SECONDS:.0f} s target)"
            if self.mttc_seconds is not None
            else "— (not contained: no MTTC is recorded)"
        )
        lines = [
            f"# Incident report: `{self.incident_id}`",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| Status | **{self.status}** |",
            f"| Finding type | `{show(self.finding_type)}` |",
            f"| Severity | {show(self.severity)} |",
            f"| Resource type | {show(self.resource_type)} |",
            f"| GuardDuty createdAt | {show(self.finding_created_at)} |",
            f"| EventBridge time (MTTC start) | {show(self.event_time)} |",
            f"| Contained at (MTTC stop) | {show(self.contained_at)} |",
            f"| MTTC | {mttc} |",
            f"| Detection latency (createdAt -> event) | {show(self.detection_latency_seconds)}"
            " s |",
            f"| Playbook verified containment | {show(self.containment_verified)} |",
            f"| Step Functions execution | `{show(self.execution_arn)}` |",
        ]
        if self.guard_reason:
            lines.append(f"| Safety guard decision | `{self.guard_reason}` |")
        if self.failure:
            lines.append(f"| Failure | `{self.failure}` |")

        lines += ["", "## Containment actions", ""]
        if self.actions:
            lines += ["| Time | Playbook | Step | Details |", "|---|---|---|---|"]
            for action in self.actions:
                details = {k: v for k, v in action.items() if k not in {"at", "playbook", "step"}}
                lines.append(
                    f"| {show(action.get('at'))} | {show(action.get('playbook'))} | "
                    f"{show(action.get('step'))} | `{json.dumps(details, default=str)}` |"
                )
        else:
            lines.append("No playbook actions recorded.")

        lines += ["", "## Evidence (SHA-256 recomputed from S3)", ""]
        if self.evidence:
            lines += ["| Object | Recorded | Recomputed | Match |", "|---|---|---|---|"]
            for e in self.evidence:
                mark = "✓" if e.ok else f"✗ {e.error or 'mismatch'}"
                lines.append(
                    f"| `{e.key}` | `{show(e.recorded_sha256)}` | "
                    f"`{show(e.actual_sha256)}` | {mark} |"
                )
            verdict = "intact" if self.chain_of_custody_ok else "**BROKEN**"
            lines += ["", f"Chain of custody: {verdict}."]
        else:
            lines.append("No evidence recorded for this incident.")
        return "\n".join(lines) + "\n"


def _check_evidence(s3: Any, record: dict[str, Any]) -> EvidenceCheck:
    key = str(record.get("key", ""))
    recorded = record.get("sha256")
    kwargs: dict[str, Any] = {"Bucket": record.get("bucket"), "Key": key}
    if record.get("versionId"):
        kwargs["VersionId"] = record["versionId"]
    try:
        body = s3.get_object(**kwargs)["Body"].read()
    except (ClientError, BotoCoreError) as exc:
        code = aws.error_code(exc) if isinstance(exc, ClientError) else type(exc).__name__
        return EvidenceCheck(key, record.get("versionId"), recorded, None, False, code)
    actual = hashlib.sha256(body).hexdigest()
    ok = actual == recorded
    if ok and record.get("sha256Base64"):
        ok = base64.b64encode(bytes.fromhex(actual)).decode() == record["sha256Base64"]
    return EvidenceCheck(
        key, record.get("versionId"), recorded, actual, ok, None if ok else "mismatch"
    )


def build_report(incident_id: str, incidents: IncidentRepository, s3: Any) -> IrReport:
    row = incidents.get(incident_id)
    event_time = _parse(row.get("eventTime"))
    created_at = _parse(row.get("findingCreatedAt"))
    contained_at = _parse(row.get("containedAt")) if row.get("status") == "CONTAINED" else None
    mttc = _seconds(event_time, contained_at)
    actions = sorted(
        (a for a in row.get("actions", []) if isinstance(a, dict)),
        key=lambda a: str(a.get("at", "")),
    )
    severity = row.get("severity")
    return IrReport(
        incident_id=incident_id,
        status=str(row.get("status", "UNKNOWN")),
        finding_type=row.get("findingType"),
        severity=float(severity) if severity is not None else None,
        resource_type=row.get("resourceType"),
        finding_created_at=row.get("findingCreatedAt"),
        event_time=row.get("eventTime"),
        contained_at=row.get("containedAt") if contained_at else None,
        containment_verified=row.get("containmentVerified"),
        mttc_seconds=mttc,
        detection_latency_seconds=_seconds(created_at, event_time),
        mttc_target_met=None if mttc is None else mttc < MTTC_TARGET_SECONDS,
        execution_arn=row.get("executionArn"),
        actions=actions,
        evidence=[
            _check_evidence(s3, r) for r in row.get("evidenceRecords", []) if isinstance(r, dict)
        ],
        guard_reason=row.get("guardReason"),
        failure=row.get("failure"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CloudShield incident response report")
    parser.add_argument("incident_id")
    parser.add_argument(
        "--table",
        default=os.environ.get("INCIDENTS_TABLE"),
        help="incidents table (default: $INCIDENTS_TABLE)",
    )
    parser.add_argument("--format", choices=("md", "json"), default="md")
    parser.add_argument("--output", help="write here instead of stdout")
    args = parser.parse_args(argv)
    if not args.table:
        parser.error("--table or INCIDENTS_TABLE is required")

    try:
        report = build_report(
            args.incident_id,
            IncidentRepository(args.table, aws.client("dynamodb")),
            aws.client("s3"),
        )
    except LookupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    text = (
        json.dumps(report.to_dict(), indent=2, default=str) + "\n"
        if args.format == "json"
        else report.to_markdown()
    )
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 2 if report.chain_of_custody_ok is False else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
