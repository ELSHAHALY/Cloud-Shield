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
    # Phase D, all OPTIONAL: empty = the feature is off, and the guard and
    # PB-04 / PB-05 refuse (fail closed).
    ecs_cluster_arn: str = ""
    ecs_service_names: tuple[str, ...] = ()
    block_ip_set_arns: tuple[str, ...] = ()
    block_ip_set_max: int = 1000
    block_ttl_hours: int = 24
    waf_region: str = ""
    never_block_param: str = ""
    edge_event_source: str = ""

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

        def bounded(name: str, default: int, low: int, high: int) -> int:
            raw = env.get(name, "").strip() or str(default)
            if not raw.isdigit() or not low <= int(raw) <= high:
                raise ConfigError(f"{name} must be an integer from {low} to {high}")
            return int(raw)

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
            ecs_cluster_arn=env.get("ECS_CLUSTER_ARN", "").strip(),
            ecs_service_names=_csv(env.get("ECS_SERVICE_NAMES", "")),
            block_ip_set_arns=_csv(env.get("BLOCK_IP_SET_ARNS", "")),
            # WAF caps an IP set at 10,000 addresses (F23).
            block_ip_set_max=bounded("BLOCK_IP_SET_MAX", 1000, 1, 10000),
            block_ttl_hours=bounded("BLOCK_TTL_HOURS", 24, 1, 168),
            waf_region=env.get("WAF_REGION", "").strip(),
            never_block_param=env.get("NEVER_BLOCK_PARAM", "").strip(),
            edge_event_source=env.get("EDGE_EVENT_SOURCE", "").strip(),
        )
