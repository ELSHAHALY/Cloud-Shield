"""Playbook: the abstract base every PB-xx Lambda implements (plan §8.6).

The base class owns the rules that must hold for every playbook:

* It acts only when the guard said dry_run is boolean False AND a fresh read
  of the dry-run switch says "false". Anything else is a dry run that makes no
  AWS change (defence in depth on top of the router's own check).
* `contained` is True only when the subclass's verification passed.
* AWS errors propagate: the router records FAILED. Nothing is swallowed into a
  false "contained".
"""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, ClassVar

from core import aws
from core.config import Settings
from core.finding import Finding, iso
from core.guard import read_dry_run
from core.incidents import IncidentRepository

logger = logging.getLogger("cloudshield.soar.playbook")
logger.setLevel(logging.INFO)


class PlaybookError(RuntimeError):
    """The playbook refuses to act, or a precondition for containment failed."""


REVOKE_POLICY_NAME = "cloudshield-soar-revoke-older-sessions"
REVOKE_SID = "CloudShieldRevokeOlderSessions"


def utcnow() -> datetime:
    return datetime.now(UTC)


def session_revoke_policy(now: datetime) -> str:
    """Inline deny on every session issued before now (the console's "Revoke
    active sessions"). The cutoff is rounded UP to whole seconds in the
    `...SSZ` form AWS itself uses, so no session issued this second survives."""
    cutoff = now.astimezone(UTC)
    if cutoff.microsecond:
        cutoff = cutoff.replace(microsecond=0) + timedelta(seconds=1)
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": REVOKE_SID,
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "DateLessThan": {
                            "aws:TokenIssueTime": cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
                        }
                    },
                }
            ],
        }
    )


def is_revoke_policy(document: Any) -> bool:
    """True if a GetRole/UserPolicy document is our session-revocation deny."""
    if isinstance(document, str):
        document = json.loads(document)
    statements = document.get("Statement", []) if isinstance(document, dict) else []
    return any(st.get("Sid") == REVOKE_SID and st.get("Effect") == "Deny" for st in statements)


class Playbook(ABC):
    name: ClassVar[str]
    actions: ClassVar[frozenset[str]]

    def __init__(
        self,
        settings: Settings,
        clients: aws.ClientFactory = aws.client,
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], None] = time.sleep,
        *,
        dry_run_reader: Callable[[], bool | None] | None = None,
    ) -> None:
        self.settings = settings
        self.clients = clients
        self.clock = clock
        self.sleep = sleep
        # Default: a fresh read of the SSM switch on every invocation. The
        # local replay of the dry-run-only scenarios D/E passes `lambda: True`
        # so flipping the switch mid-run cannot make them act (audit A10).
        self._dry_run_reader = dry_run_reader or (
            lambda: read_dry_run(self.clients("ssm"), self.settings.dry_run_param)
        )
        self.incidents = IncidentRepository(settings.incidents_table, clients("dynamodb"))

    @classmethod
    def lambda_handler(cls, event: Any, context: Any) -> dict[str, Any]:
        return cls(Settings.from_env()).handle(event)

    # ------------------------------------------------------------------ entry
    def handle(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise PlaybookError("payload is not an object")
        action, state = payload.get("action"), payload.get("event")
        if action not in self.actions:
            raise PlaybookError(f"{self.name} does not handle action {action!r}")
        if not isinstance(state, dict):
            raise PlaybookError("payload.event is not an object")
        finding = Finding.from_event(state)

        if not self._live(state):
            result = {
                "contained": False,
                "would": action,
                "dry_run": True,
                "plan": self.plan(action, finding),
            }
            self._log(finding, action, result)
            return result

        result = self.run(action, finding, state)
        self._log(finding, action, result)
        return result

    def _live(self, state: dict[str, Any]) -> bool:
        guard = state.get("guard")
        decision = guard.get("decision") if isinstance(guard, dict) else None
        if not isinstance(decision, dict) or decision.get("dry_run") is not False:
            return False
        return self._dry_run_reader() is False

    # ---------------------------------------------------------- for subclasses
    @abstractmethod
    def plan(self, action: str, finding: Finding) -> list[str]:
        """What `run` would do. Must not call AWS."""

    @abstractmethod
    def run(self, action: str, finding: Finding, state: dict[str, Any]) -> dict[str, Any]:
        """Act, verify, and return {"contained": bool, ...}. `state` is the router state."""

    def verify_with_retry(
        self, check: Callable[[], dict[str, bool]], attempts: int = 3, delay: float = 1.0
    ) -> dict[str, bool]:
        """EC2/IAM reads are eventually consistent: re-check a few times before
        declaring "not contained" (fail closed, but no spurious FAILED)."""
        verified = check()
        for _ in range(attempts - 1):
            if verified and all(v is True for v in verified.values()):
                break
            self.sleep(delay)
            verified = check()
        return verified

    def record(self, finding: Finding, step: str, **details: Any) -> None:
        self.incidents.append_action(
            finding.id,
            {"playbook": self.name, "step": step, "at": iso(self.clock()), **details},
        )

    def contained_result(
        self, finding: Finding, action: str, verified: dict[str, bool], **details: Any
    ) -> dict[str, Any]:
        contained = bool(verified) and all(v is True for v in verified.values())
        now = self.clock()
        fields: dict[str, Any] = {
            "containmentVerified": contained,
            "containmentCheckedAt": iso(now),
        }
        if contained:
            fields["containmentVerifiedAt"] = iso(now)
            fields["playbookSecondsSinceEvent"] = Decimal(
                str(round(finding.seconds_since_event(now), 3))
            )
        self.incidents.set_fields(finding.id, fields)
        return {"contained": contained, "action": action, "verified": verified, **details}

    def _log(self, finding: Finding, action: str, result: dict[str, Any]) -> None:
        logger.info(
            json.dumps(
                {
                    "playbook": self.name,
                    "incidentId": finding.id,
                    "action": action,
                    "result": result,
                },
                default=str,
            )
        )
