"""Code and Terraform must agree: handler paths, env vars, return types."""

from __future__ import annotations

import importlib
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from core.config import ConfigError, Settings

SOAR = Path(__file__).resolve().parent.parent
REPO = SOAR.parent
SOAR_TF = REPO / "infra" / "terraform" / "modules" / "soar"
PLAYBOOKS_TF = SOAR_TF / "playbooks.tf"
EDGE_BUS_TF = SOAR_TF / "edge-bus.tf"
NOTIFY_TF = SOAR_TF / "notify.tf"


def tf_handlers() -> list[str]:
    return [
        handler
        for tf in (PLAYBOOKS_TF, EDGE_BUS_TF, NOTIFY_TF)
        for handler in re.findall(r'handler\s*=\s*"([^"]+)"', tf.read_text(encoding="utf-8"))
    ]


def lambda_env_block(tf: Path) -> set[str]:
    text = tf.read_text(encoding="utf-8")
    block = re.search(r"variables = \{\n(.*?)^\s*\}\s*$", text, flags=re.MULTILINE | re.DOTALL)
    assert block, f"environment block not found in {tf.name}"
    return set(re.findall(r"^\s*([A-Z_]+)\s*=", block.group(1), flags=re.MULTILINE))


def tf_env_vars() -> set[str]:
    # The block ends at the first line that is only "}" (audit A10: "${...}"
    # inside a value must not end it early).
    text = PLAYBOOKS_TF.read_text(encoding="utf-8")
    block = re.search(r"lambda_env = \{\n(.*?)^\s*\}\s*$", text, flags=re.MULTILINE | re.DOTALL)
    assert block, "lambda_env block not found"
    return set(re.findall(r"^\s*([A-Z_]+)\s*=", block.group(1), flags=re.MULTILINE))


def test_every_terraform_handler_resolves() -> None:
    handlers = tf_handlers()
    # safety guard, PB-01..PB-05, the PB-05 harvester and the ChatOps notifier
    assert len(handlers) == 8
    assert "playbooks.pb04_ecs_task_contain.lambda_handler" in handlers
    assert "playbooks.pb05_waf_ip_block.lambda_handler" in handlers
    assert "playbooks.pb05_waf_ip_block.harvest_handler" in handlers
    assert "notifier.handler.lambda_handler" in handlers
    for handler in handlers:
        module, function = handler.rsplit(".", 1)
        assert callable(getattr(importlib.import_module(module), function)), handler


def test_settings_reads_every_variable_terraform_sets() -> None:
    read_by_code = {
        "DRY_RUN_PARAM",
        "SCOPE_TAG_KEY",
        "SCOPE_TAG_VALUE",
        "INCIDENTS_TABLE",
        "EVIDENCE_BUCKET",
        "QUARANTINE_SG_ID",
        "QUARANTINE_NACL_IDS",
        "QUARANTINE_NACL_RULE",
        "REVOCABLE_ROLE_ARNS",
        "BUCKET_NAME_PREFIX",
        "ECS_CLUSTER_ARN",
        "ECS_SERVICE_NAMES",
        "BLOCK_IP_SET_ARNS",
        "BLOCK_IP_SET_MAX",
        "BLOCK_TTL_HOURS",
        "WAF_REGION",
        "NEVER_BLOCK_PARAM",
        "EDGE_EVENT_SOURCE",
    }
    # SCOPE_TAG_PARAM is set for operators; the code reads the same tag from env.
    assert tf_env_vars() - {"SCOPE_TAG_PARAM"} == read_by_code


def test_harvester_reads_every_variable_terraform_sets() -> None:
    from playbooks.pb05_waf_ip_block import HarvestSettings

    read_by_code = {
        "EDGE_BUS_NAME",
        "EDGE_EVENT_SOURCE",
        "WAF_WEB_ACL_NAME",
        "WAF_WEB_ACL_ID",
        "WAF_RATE_RULE_NAME",
        "WAF_SCOPE",
        "WAF_REGION",
    }
    assert lambda_env_block(EDGE_BUS_TF) == read_by_code
    settings = HarvestSettings.from_env(dict.fromkeys(read_by_code, "CLOUDFRONT"))
    assert settings.scope == "CLOUDFRONT"


def test_notifier_reads_every_variable_terraform_sets() -> None:
    from core.notifier import NotifierSettings

    read_by_code = {"INCIDENTS_TABLE", "CHATOPS_WEBHOOK_PARAM", "CHATOPS_ALLOWED_HOSTS"}
    assert lambda_env_block(NOTIFY_TF) == read_by_code
    settings = NotifierSettings.from_env(
        {
            "INCIDENTS_TABLE": "t",
            "CHATOPS_WEBHOOK_PARAM": "/p",
            "CHATOPS_ALLOWED_HOSTS": "a.example",
        }
    )
    assert settings.allowed_hosts == ("a.example",)


def test_edge_event_source_matches_the_finding_parser() -> None:
    from core.finding import EDGE_SOURCE

    main_tf = (SOAR_TF / "main.tf").read_text(encoding="utf-8")
    assert f'edge_event_source = "{EDGE_SOURCE}"' in main_tf


BASE_ENV = {
    "DRY_RUN_PARAM": "/p",
    "SCOPE_TAG_KEY": "k",
    "SCOPE_TAG_VALUE": "v",
    "INCIDENTS_TABLE": "t",
    "EVIDENCE_BUCKET": "b",
    "QUARANTINE_SG_ID": "sg-1",
    "BUCKET_NAME_PREFIX": "cs-dev-",
}


def test_settings_defaults_and_lists() -> None:
    settings = Settings.from_env(
        {**BASE_ENV, "QUARANTINE_NACL_IDS": " acl-1, ,acl-2 ", "REVOCABLE_ROLE_ARNS": ""}
    )
    assert settings.quarantine_nacl_ids == ("acl-1", "acl-2")
    assert settings.revocable_role_arns == ()
    assert settings.quarantine_nacl_rule == 10
    # Phase D settings are optional: empty means the feature is off.
    assert settings.ecs_cluster_arn == ""
    assert settings.ecs_service_names == ()
    assert settings.block_ip_set_arns == ()
    assert settings.block_ip_set_max == 1000
    assert settings.block_ttl_hours == 24
    assert settings.waf_region == ""
    assert settings.never_block_param == ""
    assert settings.edge_event_source == ""


def test_settings_phase_d_values() -> None:
    settings = Settings.from_env(
        {
            **BASE_ENV,
            "ECS_CLUSTER_ARN": " arn:aws:ecs:us-east-1:123456789012:cluster/c ",
            "ECS_SERVICE_NAMES": "docs-api, other",
            "BLOCK_IP_SET_ARNS": "a,b",
            "BLOCK_IP_SET_MAX": "10000",
            "BLOCK_TTL_HOURS": "168",
            "WAF_REGION": "us-east-1",
            "NEVER_BLOCK_PARAM": "/p/nb",
            "EDGE_EVENT_SOURCE": "cloudshield.edge",
        }
    )
    assert settings.ecs_cluster_arn == "arn:aws:ecs:us-east-1:123456789012:cluster/c"
    assert settings.ecs_service_names == ("docs-api", "other")
    assert settings.block_ip_set_arns == ("a", "b")
    assert (settings.block_ip_set_max, settings.block_ttl_hours) == (10000, 168)


@pytest.mark.parametrize(
    "change",
    [
        {"DRY_RUN_PARAM": ""},
        {"QUARANTINE_SG_ID": "  "},
        {"QUARANTINE_NACL_RULE": "100"},
        {"QUARANTINE_NACL_RULE": "0"},
        {"QUARANTINE_NACL_RULE": "-5"},
        {"QUARANTINE_NACL_RULE": "ten"},
        {"BLOCK_IP_SET_MAX": "0"},
        {"BLOCK_IP_SET_MAX": "10001"},
        {"BLOCK_TTL_HOURS": "169"},
        {"BLOCK_TTL_HOURS": "1.5"},
    ],
)
def test_settings_rejects_bad_env(change: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        Settings.from_env({**BASE_ENV, **change})


def test_package_is_deterministic_and_minimal(tmp_path: Path) -> None:
    sys.path.insert(0, str(REPO / "scripts"))
    try:
        package_soar: Any = importlib.import_module("package_soar")
    finally:
        sys.path.pop(0)
    first = package_soar.build(SOAR, tmp_path / "a.zip")
    second = package_soar.build(SOAR, tmp_path / "b.zip")
    assert first == second

    with zipfile.ZipFile(tmp_path / "a.zip") as archive:
        names = archive.namelist()
        infos = archive.infolist()
    assert names == sorted(names)
    assert {n.split("/", 1)[0] for n in names} == {"core", "safety_guard", "playbooks", "notifier"}
    # The LLM hook and the report tools are operator-side only (D17).
    assert not [n for n in names if n.startswith("tools/") or "ai_summary" in n]
    assert not [n for n in names if "test" in n or "__pycache__" in n]
    assert {i.date_time for i in infos} == {(1980, 1, 1, 0, 0, 0)}
    for handler in tf_handlers():
        module = handler.rsplit(".", 1)[0]
        assert module.replace(".", "/") + ".py" in names


def test_lambda_packages_never_import_the_llm_hook() -> None:
    # D17: the LLM hook is never reachable from a Lambda.
    for package in ("core", "safety_guard", "playbooks", "notifier"):
        for path in (SOAR / package).rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert "ai_summary" not in text, path
            assert "from tools" not in text, path
