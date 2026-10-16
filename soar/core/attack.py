"""Deterministic triage table: finding type -> ATT&CK, impact, eradication, recovery.

Shared by the IR report's executive summary and the ChatOps notifier card
(plan §5.2). Pure data and string matching: no AWS calls, no network, and the
same finding type always yields the same triage, so the report is reproducible.

Rules are checked in order; the first match wins. Scenario A's exfiltration
type must precede the generic IAM-user rule (as the router's own ordering does).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

# Recovery references (relative to the repository root).
ADR_PB01 = "docs/adr/0003-pb01-nacl-quarantine.md"
ADR_PB04_PB05 = "docs/adr/0005-pb04-pb05-edge-and-ecs-containment.md"
RUNBOOK_PB04_PB05 = "docs/runbooks/pb04-pb05-recovery.md"
PLAN_PB04 = "docs/plans/s1-s2-edge-identity-waf.md §4.1"
PLAN_PB05 = "docs/plans/s1-s2-edge-identity-waf.md §4.2"


@dataclass(frozen=True)
class Triage:
    scenario: str  # "A", "A-recon", "B", "C", "D", "E" or "default"
    techniques: tuple[str, ...]
    tactic: str
    impact: str
    eradication: tuple[str, ...]
    recovery: tuple[str, ...]
    references: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "scenario": self.scenario,
            "attack_techniques": list(self.techniques),
            "tactic": self.tactic,
            "impact": self.impact,
            "eradication": list(self.eradication),
            "recovery": list(self.recovery),
            "references": list(self.references),
        }


_SCENARIO_A = Triage(
    scenario="A",
    techniques=("T1552.005",),
    tactic="Credential Access",
    impact=(
        "Instance-role credentials were used from outside AWS: the attacker held the "
        "report-worker's permissions until the sessions were revoked."
    ),
    eradication=(
        "Confirm the revoke-older-sessions deny is on the instance role (PB-01).",
        "Find the IMDS access path (SSRF or a shell) on the instance from the EBS snapshot.",
        "Enforce IMDSv2 with hop limit 1 on the launch template.",
        "Review CloudTrail for every call made with the stolen session.",
    ),
    recovery=(
        "Replace the quarantined instance from a clean launch template (ADR-0003).",
        "Remove the quarantine NACL entries only after the replacement is healthy.",
        "Keep the snapshot and manifest until the case is closed.",
    ),
    references=(ADR_PB01,),
)

_SCENARIO_A_RECON = Triage(
    scenario="A-recon",
    techniques=("T1046",),
    tactic="Discovery",
    impact="An instance scanned other hosts: likely an early foothold looking for lateral targets.",
    eradication=(
        "Identify the scanning process from the EBS snapshot (PB-01 evidence).",
        "Check the scanned targets' logs for follow-up connections.",
    ),
    recovery=(
        "Replace the quarantined instance from a clean launch template (ADR-0003).",
        "Remove the quarantine NACL entries only after the replacement is healthy.",
    ),
    references=(ADR_PB01,),
)

_SCENARIO_B = Triage(
    scenario="B",
    techniques=("T1078", "T1552.001"),
    tactic="Initial Access / Credential Access",
    impact="A long-term IAM access key was used by an untrusted caller.",
    eradication=(
        "Confirm the key is Inactive and the session-revocation deny is on the user (PB-02).",
        "Find where the key leaked (repository, CI log, workstation) and purge it.",
        "Review CloudTrail for every call made with the key.",
    ),
    recovery=(
        "Delete the deactivated key once the investigation no longer needs it.",
        "Issue a replacement credential only if the user still needs one (prefer a role).",
    ),
    references=(),
)

_SCENARIO_C = Triage(
    scenario="C",
    techniques=("T1530",),
    tactic="Collection",
    impact=(
        "A project bucket's public-access protection was disabled: its objects may have "
        "been readable."
    ),
    eradication=(
        "Confirm all four Block Public Access flags are on (PB-03 read-back).",
        "Review S3 data events for anonymous GetObject during the exposure window.",
        "Codify the block in Terraform (the report adds a ready-to-apply block when "
        "PB-03 recorded a valid bucket name) so drift is visible.",
    ),
    recovery=(
        "Remove or rewrite the bucket policy statements that granted public access.",
        "Rotate any secret that was stored in the exposed objects.",
    ),
    references=(),
)

_SCENARIO_E = Triage(
    scenario="E",
    techniques=("T1190", "T1595", "T1499"),
    tactic="Initial Access / Reconnaissance / Impact",
    impact=(
        "A client exceeded the edge rate limit or hit a decoy route: probing or abuse of "
        "the public app."
    ),
    eradication=(
        "Review WAF logs (query 04) for the client's URIs and terminating rules.",
        "Check the application audit trail for requests from the address that succeeded.",
    ),
    recovery=(
        "The PB-05 sweeper lifts the block automatically once blockExpiresAt has passed "
        "(D15); tools/list_expired_blocks.py cross-checks expired, lost and orphan entries.",
        "Lift it early by hand if the address is shared (NAT, carrier gateway) or a false "
        f"positive ({RUNBOOK_PB04_PB05}).",
    ),
    references=(PLAN_PB05, ADR_PB04_PB05, RUNBOOK_PB04_PB05),
)

_DEFAULT = Triage(
    scenario="default",
    techniques=(),
    tactic="Unclassified",
    impact="No automated triage for this finding type: analyst review required.",
    eradication=("Review the finding in GuardDuty and decide whether it is a true positive.",),
    recovery=("Record the outcome on the incident before closing it.",),
    references=(),
)


def _runtime(finding_type: str) -> Triage:
    techniques = ("T1610", "T1059")
    if "CryptoCurrency" in finding_type:
        techniques = (*techniques, "T1496")
    return Triage(
        scenario="D",
        techniques=techniques,
        tactic="Execution",
        impact=(
            "Unexpected code ran inside an application container. Containment stopped the "
            "task and redeployed the service from the SAME image digest (D12)."
        ),
        eradication=(
            "Capture volatile state with ECS Exec from a sibling task BEFORE approving "
            "eradication (the runbook's human step).",
            "Build and scan a new image; deploy it by digest. Replacements of a compromised "
            "image are compromised too.",
            "Review the task-definition environment and task role for exposed secrets.",
        ),
        recovery=(
            "Confirm the new deployment is PRIMARY and healthy.",
            f"Keep the PB-04 prestate evidence object for the case ({RUNBOOK_PB04_PB05}).",
        ),
        references=(PLAN_PB04, ADR_PB04_PB05, RUNBOOK_PB04_PB05),
    )


_Rule = tuple[Callable[[str], bool], Callable[[str], Triage]]

_RULES: tuple[_Rule, ...] = (
    (
        lambda t: t.startswith("UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"),
        lambda _t: _SCENARIO_A,
    ),
    (lambda t: t.startswith("Recon:"), lambda _t: _SCENARIO_A_RECON),
    (lambda t: t.startswith("UnauthorizedAccess:IAMUser/"), lambda _t: _SCENARIO_B),
    (lambda t: t.startswith("Policy:S3/"), lambda _t: _SCENARIO_C),
    (lambda t: ":Runtime/" in t, _runtime),
    (lambda t: t.startswith("CloudShield:IPAddress/"), lambda _t: _SCENARIO_E),
)


def triage(finding_type: str | None) -> Triage:
    """The triage entry for a finding type; the default entry when nothing matches."""
    if isinstance(finding_type, str):
        for matches, build in _RULES:
            if matches(finding_type):
                return build(finding_type)
    return _DEFAULT
