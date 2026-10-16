"""ChatOps notifier Lambda: lambda_handler(event, ctx) -> {"posted": bool, ...}.

Subscribed to the incidents SNS topic (modules/soar/notify.tf). SNS invokes
Lambda asynchronously, so an exception here would only cause retries (and
duplicate cards): the contract is that this handler NEVER raises. Every failure
becomes {"posted": false, "reason": ...} plus a log line with the exception
type name only (never its message, which could carry the webhook URL).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from core.notifier import Notifier, NotifierSettings

logger = logging.getLogger("cloudshield.soar.notifier")
logger.setLevel(logging.INFO)


def lambda_handler(event: Any, context: Any) -> dict[str, Any]:
    try:
        return Notifier(NotifierSettings.from_env()).handle(event)
    except Exception as exc:  # noqa: BLE001 - contract: never raise into SNS (async retries would re-post); type name only
        logger.error(json.dumps({"notifier": "error", "error": type(exc).__name__}))
        return {"posted": False, "reason": f"error: {type(exc).__name__}"}
