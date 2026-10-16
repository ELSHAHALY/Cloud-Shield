"""IR report generator (tools/generate_ir_report.py)."""

from __future__ import annotations

import json
from typing import Any

import boto3
import pytest

from core.attack import triage
from core.incidents import IncidentRepository
from tests.conftest import EVIDENCE_BUCKET, INCIDENTS_TABLE
from tests.fake_https import FakeHttps, install
from tools import ai_summary
from tools import generate_ir_report as ir
from tools.generate_ir_report import build_report, iac_remediation, main, valid_bucket_name


def repo() -> IncidentRepository:
    return IncidentRepository(INCIDENTS_TABLE, boto3.client("dynamodb"))


def put_evidence(key: str, body: bytes) -> dict[str, Any]:
    import base64
    import hashlib

    boto3.client("s3").put_object(Bucket=EVIDENCE_BUCKET, Key=key, Body=body)
    digest = hashlib.sha256(body).digest()
    return {
        "bucket": EVIDENCE_BUCKET,
        "key": key,
        "versionId": None,
        "sha256": digest.hex(),
        "sha256Base64": base64.b64encode(digest).decode(),
    }


def contained_row(world: Any, **extra: Any) -> str:
    incident_id = "f-report-contained"
    world.seed_incident(
        incident_id,
        status={"S": "CONTAINED"},
        findingType={"S": "Recon:EC2/Portscan"},
        severity={"N": "5"},
        resourceType={"S": "Instance"},
        findingCreatedAt={"S": "2026-10-14T09:59:58.000Z"},
        eventTime={"S": "2026-10-14T10:00:00.000Z"},
        containedAt={"S": "2026-10-14T10:00:12.500Z"},
        containmentVerified={"BOOL": True},
    )
    r = repo()
    r.append_action(
        incident_id,
        {
            "playbook": "pb01-ec2-isolate",
            "step": "nacl-deny",
            "at": "2026-10-14T10:00:05.000Z",
            "networkAclId": "acl-1",
        },
    )
    for k, v in extra.items():
        r.set_fields(incident_id, {k: v})
    return incident_id


def test_contained_report_computes_mttc(world: Any) -> None:
    incident_id = contained_row(world)
    report = build_report(incident_id, repo(), boto3.client("s3"))
    assert report.status == "CONTAINED"
    assert report.mttc_seconds == 12.5
    assert report.mttc_target_met is True
    assert report.detection_latency_seconds == 2.0
    assert report.chain_of_custody_ok is None  # no evidence recorded
    md = report.to_markdown()
    assert "12.500 s (meets" in md
    assert "nacl-deny" in md


def test_evidence_hash_match_passes(world: Any) -> None:
    incident_id = contained_row(world)
    record = put_evidence("incidents/f-report-contained/manifest.json", b'{"ok":1}')
    repo().add_evidence(incident_id, record)
    report = build_report(incident_id, repo(), boto3.client("s3"))
    assert report.chain_of_custody_ok is True
    assert report.evidence[0].ok is True
    assert main([incident_id, "--table", INCIDENTS_TABLE]) == 0


def test_tampered_evidence_fails_and_exits_2(world: Any, capsys: Any) -> None:
    incident_id = contained_row(world)
    record = put_evidence("incidents/f-report-contained/m.json", b'{"original":1}')
    repo().add_evidence(incident_id, record)
    # Tamper: overwrite the object after the hash was recorded.
    boto3.client("s3").put_object(Bucket=EVIDENCE_BUCKET, Key=record["key"], Body=b'{"tampered":1}')

    report = build_report(incident_id, repo(), boto3.client("s3"))
    assert report.chain_of_custody_ok is False
    assert report.evidence[0].ok is False
    assert "BROKEN" in report.to_markdown()
    assert main([incident_id, "--table", INCIDENTS_TABLE]) == 2


def test_missing_evidence_object_is_marked(world: Any) -> None:
    incident_id = contained_row(world)
    repo().add_evidence(
        incident_id, {"bucket": EVIDENCE_BUCKET, "key": "incidents/gone.json", "sha256": "deadbeef"}
    )
    report = build_report(incident_id, repo(), boto3.client("s3"))
    assert report.evidence[0].ok is False
    assert report.evidence[0].error == "NoSuchKey"


def test_not_contained_has_no_mttc(world: Any) -> None:
    world.seed_incident(
        "f-failed",
        status={"S": "FAILED"},
        eventTime={"S": "2026-10-14T10:00:00Z"},
        failure={"S": "PlaybookDidNotContain"},
    )
    report = build_report("f-failed", repo(), boto3.client("s3"))
    assert report.mttc_seconds is None
    assert report.mttc_target_met is None
    assert "not contained" in report.to_markdown()


def test_json_output(world: Any, tmp_path: Any) -> None:
    incident_id = contained_row(world)
    out = tmp_path / "r.json"
    assert (
        main([incident_id, "--table", INCIDENTS_TABLE, "--format", "json", "--output", str(out)])
        == 0
    )
    data = json.loads(out.read_text())
    assert data["mttc_seconds"] == 12.5
    assert data["chain_of_custody_ok"] is None


def test_unknown_incident_exits_1(world: Any) -> None:
    assert main(["does-not-exist", "--table", INCIDENTS_TABLE]) == 1


def test_table_required(monkeypatch: Any) -> None:
    monkeypatch.delenv("INCIDENTS_TABLE", raising=False)
    with pytest.raises(SystemExit):
        main(["f-1"])


def test_mttc_target_missed(world: Any) -> None:
    world.seed_incident(
        "f-slow",
        status={"S": "CONTAINED"},
        eventTime={"S": "2026-10-14T10:00:00Z"},
        containedAt={"S": "2026-10-14T10:02:00Z"},
    )
    report = build_report("f-slow", repo(), boto3.client("s3"))
    assert report.mttc_seconds == 120.0
    assert report.mttc_target_met is False
    assert "MISSES" in report.to_markdown()


def test_target_constant() -> None:
    assert ir.MTTC_TARGET_SECONDS == 60.0


# =============================================================================
# Phase D (plan §5.2, §7): executive summary, IaC snippet, optional LLM hook.
# The AI hook must never touch the network: real sockets and urlopen raise in
# every test of this module, and the opt-in path uses an in-process fake.
# =============================================================================
@pytest.fixture(autouse=True)
def _offline(no_network: None, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (ai_summary.PROVIDER_ENV, ai_summary.API_KEY_ENV):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    ("finding_type", "scenario", "techniques"),
    [
        (
            "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
            "A",
            ("T1552.005",),
        ),
        ("Recon:EC2/Portscan", "A-recon", ("T1046",)),
        ("UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom", "B", ("T1078", "T1552.001")),
        ("Policy:S3/BucketBlockPublicAccessDisabled", "C", ("T1530",)),
        ("Execution:Runtime/NewBinaryExecuted", "D", ("T1610", "T1059")),
        ("CryptoCurrency:Runtime/BitcoinTool.B", "D", ("T1610", "T1059", "T1496")),
        ("CloudShield:IPAddress/WafRateLimitExceeded", "E", ("T1190", "T1595", "T1499")),
        ("CloudShield:IPAddress/DecoyRouteHit", "E", ("T1190", "T1595", "T1499")),
        ("Backdoor:EC2/C&CActivity.B", "default", ()),
    ],
)
def test_triage_per_scenario(
    world: Any, finding_type: str, scenario: str, techniques: tuple[str, ...]
) -> None:
    assert triage(finding_type).techniques == techniques
    world.seed_incident(
        "f-triage",
        status={"S": "CONTAINED"},
        findingType={"S": finding_type},
        eventTime={"S": "2026-10-14T10:00:00Z"},
        containedAt={"S": "2026-10-14T10:00:30Z"},
    )
    report = build_report("f-triage", repo(), boto3.client("s3"))
    summary = report.executive_summary
    assert summary["scenario"] == scenario
    assert tuple(summary["attack_techniques"]) == techniques
    assert summary["mttc_verdict"] == "met: 30.000 s against the 60 s target"
    assert summary["eradication"]
    assert summary["recovery"]
    md = report.to_markdown()
    assert md.index("## Executive summary") < md.index("## Incident record")
    assert f"**Scenario:** {scenario}" in md
    for technique in techniques:
        assert technique in md


def test_scenarios_and_triage_agree() -> None:
    from sims.scenarios import SCENARIOS

    expected = {"a": "A", "a-recon": "A-recon", "b": "B", "c": "C", "d": "D", "e": "E"}
    for key, scenario in SCENARIOS.items():
        result = triage(scenario.finding_type)
        assert result.scenario == expected[key]
        assert set(result.techniques) <= set(scenario.attack_techniques) | {"T1499"}


def test_triage_default_for_missing_type(world: Any) -> None:
    assert triage(None).scenario == "default"
    world.seed_incident("f-no-type", status={"S": "FAILED"})
    report = build_report("f-no-type", repo(), boto3.client("s3"))
    assert report.executive_summary["scenario"] == "default"
    assert report.executive_summary["mttc_verdict"] == "not contained: no MTTC is recorded"
    assert "ATT&CK:** analyst review" in report.to_markdown()


def test_recovery_links_adr_and_runbook() -> None:
    assert "docs/adr/0003-pb01-nacl-quarantine.md" in triage("Recon:EC2/Portscan").references
    for finding_type in ("Execution:Runtime/X", "CloudShield:IPAddress/WafRateLimitExceeded"):
        refs = triage(finding_type).references
        assert "docs/runbooks/pb04-pb05-recovery.md" in refs
        assert "docs/adr/0005-pb04-pb05-edge-and-ecs-containment.md" in refs


def test_mttc_missed_verdict(world: Any) -> None:
    world.seed_incident(
        "f-slow2",
        status={"S": "CONTAINED"},
        findingType={"S": "Recon:EC2/Portscan"},
        eventTime={"S": "2026-10-14T10:00:00Z"},
        containedAt={"S": "2026-10-14T10:01:30Z"},
    )
    report = build_report("f-slow2", repo(), boto3.client("s3"))
    assert report.executive_summary["mttc_verdict"] == "MISSED: 90.000 s against the 60 s target"


PB03_SNIPPET = (
    'resource "aws_s3_bucket_public_access_block" "bpa_cs_dev_lab_123456789012" {\n'
    '  bucket                  = "cs-dev-lab-123456789012"\n'
    "  block_public_acls       = true\n"
    "  block_public_policy     = true\n"
    "  ignore_public_acls      = true\n"
    "  restrict_public_buckets = true\n"
    "}\n"
    "\n"
    "# terraform import aws_s3_bucket_public_access_block.bpa_cs_dev_lab_123456789012"
    " cs-dev-lab-123456789012\n"
)


def pb03_row(world: Any, bucket: str, incident_id: str = "f-pb03") -> str:
    world.seed_incident(
        incident_id,
        status={"S": "CONTAINED"},
        findingType={"S": "Policy:S3/BucketBlockPublicAccessDisabled"},
        resourceType={"S": "S3Bucket"},
        eventTime={"S": "2026-10-14T10:00:00Z"},
        containedAt={"S": "2026-10-14T10:00:09Z"},
    )
    for step in ("capture-prestate", "restore-bpa"):
        repo().append_action(
            incident_id,
            {
                "playbook": "pb03-s3-restore-bpa",
                "step": step,
                "at": "2026-10-14T10:00:05Z",
                "bucket": bucket,
            },
        )
    return incident_id


def test_pb03_snippet_exact_text(world: Any) -> None:
    incident_id = pb03_row(world, "cs-dev-lab-123456789012")
    report = build_report(incident_id, repo(), boto3.client("s3"))
    assert report.iac_remediation == PB03_SNIPPET
    md = report.to_markdown()
    assert "## IaC remediation (PB-03 posture loop)" in md
    assert "```hcl\n" + PB03_SNIPPET.rstrip("\n") + "\n```" in md
    assert report.to_dict()["iac_remediation"] == PB03_SNIPPET


def test_dotted_bucket_label_is_sanitised() -> None:
    snippet = iac_remediation(
        "Policy:S3/BucketAnonymousAccessGranted",
        [{"playbook": "pb03-s3-restore-bpa", "bucket": "cs-dev.logs.example"}],
    )
    assert snippet is not None
    assert '"bpa_cs_dev_logs_example"' in snippet
    assert 'bucket                  = "cs-dev.logs.example"' in snippet


@pytest.mark.parametrize(
    "bucket",
    [
        'x" } resource "aws_iam_user" "evil" { name = "x',
        "cs-dev-lab\nevil",
        "Cs-Dev-Lab",
        "cs_dev_lab",
        "ab",
        "a" * 64,
        "-cs-dev",
        "cs-dev-",
        "cs..dev",
        "192.168.10.20",
        "xn--cs-dev",
        "sthree-cs",
        "cs-dev-s3alias",
        "cs-dev--ol-s3",
        "${var.x}",
        "",
        None,
        42,
    ],
)
def test_invalid_bucket_means_no_snippet(bucket: Any) -> None:
    assert valid_bucket_name(bucket) is False
    actions = [{"playbook": "pb03-s3-restore-bpa", "bucket": bucket}]
    assert iac_remediation("Policy:S3/BucketBlockPublicAccessDisabled", actions) is None


def test_invalid_bucket_report_has_no_iac_section(world: Any) -> None:
    incident_id = pb03_row(world, "Bad_Bucket")
    report = build_report(incident_id, repo(), boto3.client("s3"))
    assert report.iac_remediation is None
    assert "## IaC remediation" not in report.to_markdown()


EXPOSURE = "Policy:S3/BucketBlockPublicAccessDisabled"


@pytest.mark.parametrize(
    ("finding_type", "actions"),
    [
        ("Recon:EC2/Portscan", [{"playbook": "pb03-s3-restore-bpa", "bucket": "cs-dev-a"}]),
        ("Exfiltration:S3/AnomalousBehavior", [{"playbook": "pb03-x", "bucket": "cs-dev-a"}]),
        (None, [{"playbook": "pb03-s3-restore-bpa", "bucket": "cs-dev-a"}]),
        (EXPOSURE, []),
        (EXPOSURE, [{"playbook": "pb01", "bucket": "cs-dev-a"}]),
        (
            EXPOSURE,
            [
                {"playbook": "pb03-a", "bucket": "cs-dev-a"},
                {"playbook": "pb03-a", "bucket": "cs-dev-b"},
            ],
        ),
    ],
)
def test_no_snippet_without_one_pb03_bucket(
    finding_type: Any, actions: list[dict[str, Any]]
) -> None:
    assert iac_remediation(finding_type, actions) is None


# ------------------------------------------------------------------ LLM hook
AI_RESPONSE = json.dumps(
    {
        "type": "message",
        "role": "assistant",
        "stop_reason": "end_turn",
        "content": [
            {"type": "thinking", "thinking": "", "signature": "sig"},
            {"type": "text", "text": "The bucket exposure was contained in 9 s."},
        ],
    }
).encode()


def opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ai_summary.PROVIDER_ENV, "anthropic")
    monkeypatch.setenv(ai_summary.API_KEY_ENV, "test-only-not-a-key")


def test_ai_hook_is_off_by_default(
    world: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    opt_in(monkeypatch)  # even fully configured: no flag means no call
    fake = FakeHttps(200, AI_RESPONSE)
    built = install(monkeypatch, fake)
    incident_id = pb03_row(world, "cs-dev-lab-123456789012")
    out = tmp_path / "r.md"
    assert main([incident_id, "--table", INCIDENTS_TABLE, "--output", str(out)]) == 0
    assert "AI summary" not in out.read_text(encoding="utf-8")
    assert built == []
    assert fake.requests == []


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"CLOUDSHIELD_LLM_PROVIDER": "anthropic"},
        {"ANTHROPIC_API_KEY": "test-only-not-a-key"},
        {"CLOUDSHIELD_LLM_PROVIDER": "other", "ANTHROPIC_API_KEY": "test-only-not-a-key"},
        {"CLOUDSHIELD_LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "  "},
    ],
)
def test_ai_flag_without_full_opt_in_makes_no_call(
    world: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Any, env: dict[str, str]
) -> None:
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    built = install(monkeypatch, FakeHttps(200, AI_RESPONSE))
    incident_id = pb03_row(world, "cs-dev-lab-123456789012")
    out = tmp_path / "r.json"
    args = [incident_id, "--table", INCIDENTS_TABLE, "--ai-summary", "--format", "json"]
    assert main([*args, "--output", str(out)]) == 0
    summary = json.loads(out.read_text())["ai_summary"]
    assert summary.startswith("AI summary unavailable (not configured")
    assert built == []


def test_enabled_requires_the_flag() -> None:
    env = {"CLOUDSHIELD_LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test-only-not-a-key"}
    assert ai_summary.enabled(False, env) is False
    assert ai_summary.enabled(True, env) is True


def test_ai_opt_in_uses_the_allow_listed_endpoint(
    world: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    opt_in(monkeypatch)
    fake = FakeHttps(200, AI_RESPONSE)
    install(monkeypatch, fake)
    incident_id = pb03_row(world, "cs-dev-lab-123456789012")
    out = tmp_path / "r.md"
    args = [incident_id, "--table", INCIDENTS_TABLE, "--ai-summary", "--output", str(out)]
    assert main(args) == 0

    md = out.read_text(encoding="utf-8")
    assert "## AI summary (AI-generated, advisory)" in md
    assert "> The bucket exposure was contained in 9 s." in md
    (req,) = fake.requests
    assert req.full_url == "https://api.anthropic.com/v1/messages"
    assert req.get_header("X-api-key") == "test-only-not-a-key"
    assert req.get_header("Anthropic-version") == "2023-06-01"
    assert req.get_header("Anthropic-beta") == "server-side-fallback-2026-07-01"
    body = json.loads(req.data)
    assert body["model"] == "claude-opus-5-5"
    assert body["fallbacks"] == "default"
    assert body["output_config"] == {"effort": "low"}
    assert "thinking" not in body
    sent = json.loads(body["messages"][0]["content"])
    assert set(sent) == {
        "findingType",
        "resourceType",
        "status",
        "mttcSeconds",
        "mttcTargetMet",
        "actionSteps",
    }
    assert "cs-dev-lab-123456789012" not in req.data.decode()
    assert "123456789012" not in req.data.decode()


def test_redaction_removes_identifiers() -> None:
    key_id = "AK" + "IA" + "TESTONLY0000ABCD"  # built at runtime: no key-shaped literal
    session_key = "AS" + "IA" + "TESTONLY0000WXYZ"
    text = (
        "arn:aws:iam::123456789012:role/cs-dev-report-worker acct 210987654321 "
        "ip 203.0.113.9 v6 2001:db8::1 mapped ::ffff:198.51.100.7 "
        f"mail soc.analyst@example.com key {key_id} sess {session_key} "
        "bucket cs-dev-lab-bucket uri s3://cs-dev-other/x time 2026-10-14T10:00:12.500Z"
    )
    out = ai_summary.redact(text, {"cs-dev-lab-bucket"})
    for secret in (
        "arn:aws",
        "123456789012",
        "210987654321",
        "203.0.113.9",
        "2001:db8::1",
        "198.51.100.7",
        "soc.analyst@example.com",
        key_id,
        session_key,
        "cs-dev-lab-bucket",
        "cs-dev-other",
    ):
        assert secret not in out, secret
    for placeholder in ("<arn>", "<account>", "<ip>", "<email>", "<access-key-id>", "<bucket>"):
        assert placeholder in out
    assert "2026-10-14T10:00:12.500Z" in out  # timestamps are not addresses


def test_redaction_applies_to_what_is_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    opt_in(monkeypatch)
    fake = FakeHttps(200, AI_RESPONSE)
    install(monkeypatch, fake)
    key_id = "AK" + "IA" + "TESTONLY0000ABCD"
    report = {
        "finding_type": "Policy:S3/Bucket arn:aws:s3:::cs-dev-secret-bucket",
        "resource_type": "S3Bucket",
        "status": "CONTAINED",
        "mttc_seconds": 9.0,
        "mttc_target_met": True,
        "actions": [
            {
                "playbook": "pb03-s3-restore-bpa",
                "step": f"restore cs-dev-secret-bucket 10.0.0.5 a@b.example {key_id} 123456789012",
                "bucket": "cs-dev-secret-bucket",
            }
        ],
        "evidence": [{"key": "incidents/x/raw.json", "raw": "must never be sent"}],
    }
    assert ai_summary.summarise(report) == "The bucket exposure was contained in 9 s."
    sent = fake.requests[0].data.decode()
    for secret in ("cs-dev-secret-bucket", "10.0.0.5", "a@b.example", key_id, "123456789012"):
        assert secret not in sent, secret
    assert "must never be sent" not in sent
    assert "incidents/x/raw.json" not in sent


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (500, b'{"type":"error"}'),
        (429, b"{}"),
        (302, b""),
        (204, b""),
        (200, b"not json"),
        (200, b'{"stop_reason":"refusal","content":[]}'),
        (200, b'{"stop_reason":"end_turn","content":[{"type":"text","text":"   "}]}'),
        (200, b'{"stop_reason":"end_turn","content":"x"}'),
        (200, b"[]"),
        (200, b'{"content":[{"type":"text","text":"' + b"a" * 70_000 + b'"}]}'),
    ],
    ids=[
        "500",
        "429",
        "302",
        "204",
        "not-json",
        "refusal",
        "blank",
        "bad-content",
        "list",
        "oversized",
    ],
)
def test_ai_failure_degrades_without_changing_exit_code(
    world: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Any, status: int, body: bytes
) -> None:
    opt_in(monkeypatch)
    install(monkeypatch, FakeHttps(status, body, {"Location": "https://evil.example.test/"}))
    incident_id = pb03_row(world, "cs-dev-lab-123456789012")
    out = tmp_path / "r.json"
    args = [incident_id, "--table", INCIDENTS_TABLE, "--ai-summary", "--format", "json"]
    assert main([*args, "--output", str(out)]) == 0
    assert json.loads(out.read_text())["ai_summary"] == "AI summary unavailable"


def test_ai_network_error_degrades(monkeypatch: pytest.MonkeyPatch) -> None:
    # No fake installed: the real opener reaches the socket guard, which raises.
    opt_in(monkeypatch)
    assert ai_summary.summarise({"status": "CONTAINED"}) == ai_summary.UNAVAILABLE


def test_ai_summary_is_sanitised_and_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    opt_in(monkeypatch)
    text = "line one\x1b[31m\nline two" + "z" * 5000
    payload = {"stop_reason": "end_turn", "content": [{"type": "text", "text": text}]}
    install(monkeypatch, FakeHttps(200, json.dumps(payload).encode()))
    summary = ai_summary.summarise({"status": "CONTAINED"})
    assert "\x1b" not in summary
    assert len(summary) == ai_summary.MAX_SUMMARY_CHARS
    assert summary.startswith("line one [31m\nline two")
