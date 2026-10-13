"""Runtime settings: the environment every SOAR function receives (soar/README.md)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass


class ConfigError(RuntimeError):
    """A required environment variable is missing or invalid."""


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    dry_run_param: str
    scope_tag_key: str
    scope_tag_value: str
    incidents_table: str
    evidence_bucket: str
    quarantine_sg_id: str
    quarantine_nacl_ids: tuple[str, ...]
    quarantine_nacl_rule: int
    revocable_role_arns: tuple[str, ...]
    bucket_name_prefix: str

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env

        def required(name: str) -> str:
            value = env.get(name, "").strip()
            if not value:
                raise ConfigError(f"missing environment variable {name}")
            return value

        raw_rule = env.get("QUARANTINE_NACL_RULE", "10").strip()
        if not raw_rule.isdigit() or not 1 <= int(raw_rule) <= 99:
            # Must stay below the worker NACL's allow rules at 100 (ADR-0003).
            raise ConfigError("QUARANTINE_NACL_RULE must be an integer from 1 to 99")

        return cls(
            dry_run_param=required("DRY_RUN_PARAM"),
            scope_tag_key=required("SCOPE_TAG_KEY"),
            scope_tag_value=required("SCOPE_TAG_VALUE"),
            incidents_table=required("INCIDENTS_TABLE"),
            evidence_bucket=required("EVIDENCE_BUCKET"),
            quarantine_sg_id=required("QUARANTINE_SG_ID"),
            quarantine_nacl_ids=_csv(env.get("QUARANTINE_NACL_IDS", "")),
            quarantine_nacl_rule=int(raw_rule),
            revocable_role_arns=_csv(env.get("REVOCABLE_ROLE_ARNS", "")),
            bucket_name_prefix=required("BUCKET_NAME_PREFIX"),
        )
