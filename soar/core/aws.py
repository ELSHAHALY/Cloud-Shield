"""boto3 clients with a time budget that fits the 60 s MTTC target."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# Short timeouts, few retries: the router (Step Functions) owns retries of the
# whole invocation, and a hung call must not eat the Lambda's 30 s timeout.
_CONFIG = Config(
    connect_timeout=2,
    read_timeout=5,
    retries={"max_attempts": 3, "mode": "standard"},
)

# For best-effort reads that must never eat the containment budget (PB-03's
# pre-state capture): one attempt, short timeouts.
QUICK = Config(connect_timeout=1, read_timeout=2, retries={"max_attempts": 1, "mode": "standard"})

ClientFactory = Callable[..., Any]


def client(service: str, config: Config | None = None) -> Any:
    return boto3.client(service, config=config or _CONFIG)


def error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))
