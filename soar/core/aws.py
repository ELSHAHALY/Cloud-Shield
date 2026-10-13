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

ClientFactory = Callable[[str], Any]


def client(service: str) -> Any:
    return boto3.client(service, config=_CONFIG)


def error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))
