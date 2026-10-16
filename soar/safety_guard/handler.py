"""safety_guard Lambda: lambda_handler(event, ctx) -> {"allowed", "dry_run", "reason"}.

Invoked by cs-ir-router with the raw EventBridge event as its payload.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from core import aws
from core.config import Settings
from core.guard import AwsTagReader, Decision, SafetyGuard, read_dry_run, read_never_block

logger = logging.getLogger("cloudshield.soar.guard")
logger.setLevel(logging.INFO)


def lambda_handler(event: Any, context: Any) -> dict[str, Any]:
    try:
        settings = Settings.from_env()
        ssm = aws.client("ssm")
        guard = SafetyGuard(
            settings,
            AwsTagReader(aws.client),
            lambda: read_dry_run(ssm, settings.dry_run_param),
            # Read on every evaluation of an IP target (plan §4.2 rule 4).
            lambda: read_never_block(ssm, settings.never_block_param),
        )
        decision = guard.evaluate(event)
    except Exception as exc:  # fail closed on ANY guard error
        logger.exception("safety guard error")
        decision = Decision(False, True, f"guard error: {type(exc).__name__}")

    result = decision.to_dict()
    logger.info(json.dumps({"guardDecision": result}))
    return result
