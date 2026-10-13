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
PLAYBOOKS_TF = REPO / "infra" / "terraform" / "modules" / "soar" / "playbooks.tf"


def tf_handlers() -> list[str]:
    return re.findall(r'handler\s*=\s*"([^"]+)"', PLAYBOOKS_TF.read_text(encoding="utf-8"))


def tf_env_vars() -> set[str]:
    # The block ends at the first line that is only "}" (audit A10: "${...}"
    # inside a value must not end it early).
    text = PLAYBOOKS_TF.read_text(encoding="utf-8")
    block = re.search(r"lambda_env = \{\n(.*?)^\s*\}\s*$", text, flags=re.MULTILINE | re.DOTALL)
    assert block, "lambda_env block not found"
    return set(re.findall(r"^\s*([A-Z_]+)\s*=", block.group(1), flags=re.MULTILINE))


def test_every_terraform_handler_resolves() -> None:
    handlers = tf_handlers()
    assert len(handlers) == 4
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
    }
    # SCOPE_TAG_PARAM is set for operators; the code reads the same tag from env.
    assert tf_env_vars() - {"SCOPE_TAG_PARAM"} == read_by_code


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


@pytest.mark.parametrize(
    "change",
    [
        {"DRY_RUN_PARAM": ""},
        {"QUARANTINE_SG_ID": "  "},
        {"QUARANTINE_NACL_RULE": "100"},
        {"QUARANTINE_NACL_RULE": "0"},
        {"QUARANTINE_NACL_RULE": "-5"},
        {"QUARANTINE_NACL_RULE": "ten"},
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
    assert {n.split("/", 1)[0] for n in names} == {"core", "safety_guard", "playbooks"}
    assert not [n for n in names if "test" in n or "__pycache__" in n]
    assert {i.date_time for i in infos} == {(1980, 1, 1, 0, 0, 0)}
    for handler in tf_handlers():
        module = handler.rsplit(".", 1)[0]
        assert module.replace(".", "/") + ".py" in names
