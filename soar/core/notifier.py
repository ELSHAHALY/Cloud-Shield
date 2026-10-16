"""ChatOps notifier core (plan §5.1): SNS message -> incident card -> webhook.

Two message shapes reach the incidents topic (F26), and each is parsed strictly:

* the router's Notify string ``Incident <id> | <type> | resource <rt> | ...``;
* while playbooks are off, the raw GuardDuty EventBridge event (JSON, ``detail.id``).

Anything else is logged and ignored. The webhook URL is a credential (D16): it
is read from an SSM SecureString with decryption, cached for 5 minutes per
container, sent only through `core.http.post_json` (exact-host allow-list,
https, no redirects, no proxies) and NEVER logged: logs carry the host only.
Exceptions never escape `Notifier.handle_record` with a message that could
contain the URL; only exception type names are recorded.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from botocore.exceptions import BotoCoreError, ClientError

from core import aws
from core.attack import triage
from core.http import HttpPolicyError, post_json, validate_url
from core.incidents import IncidentRepository

logger = logging.getLogger("cloudshield.soar.notifier")
logger.setLevel(logging.INFO)

# botocore logs full response bodies at DEBUG, which would include the
# DECRYPTED webhook URL from ssm:GetParameter. Pin the SDK loggers to INFO so a
# DEBUG application log level (Lambda advanced logging controls) can never
# write the secret to CloudWatch.
for _sdk_logger in ("botocore", "boto3", "urllib3", "s3transfer"):
    logging.getLogger(_sdk_logger).setLevel(logging.INFO)

ROUTER_MESSAGE = re.compile(r"^Incident ([\w.:-]{1,128}) \|")
_FINDING_ID = re.compile(r"^[\w.:-]{1,128}$")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+\Z")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

WEBHOOK_CACHE_SECONDS = 300.0
MAX_RECORDS = 10
_FIELD_MAX = 200


class NotifierConfigError(RuntimeError):
    """The notifier's environment is missing or invalid."""


@dataclass(frozen=True)
class NotifierSettings:
    incidents_table: str
    webhook_param: str
    allowed_hosts: tuple[str, ...]

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> NotifierSettings:
        env = os.environ if env is None else env
        table = env.get("INCIDENTS_TABLE", "").strip()
        param = env.get("CHATOPS_WEBHOOK_PARAM", "").strip()
        hosts = tuple(
            h.strip().lower() for h in env.get("CHATOPS_ALLOWED_HOSTS", "").split(",") if h.strip()
        )
        if not table or not param:
            raise NotifierConfigError("INCIDENTS_TABLE and CHATOPS_WEBHOOK_PARAM are required")
        if not hosts or not all(_HOSTNAME.match(h) for h in hosts):
            raise NotifierConfigError("CHATOPS_ALLOWED_HOSTS must list plain host names")
        return cls(table, param, hosts)


@dataclass(frozen=True)
class ParsedMessage:
    incident_id: str
    shape: str  # "router" or "guardduty"
    event: dict[str, Any] | None = None  # the raw event, for the "guardduty" shape


def parse_message(message: Any) -> ParsedMessage | None:
    """Strictly parse an SNS message body; None = not a message we handle."""
    if not isinstance(message, str) or len(message) > 256 * 1024:
        return None
    match = ROUTER_MESSAGE.match(message)
    if match:
        return ParsedMessage(match.group(1), "router")
    try:
        event = json.loads(message)
    except ValueError:
        return None
    if not isinstance(event, dict) or event.get("source") != "aws.guardduty":
        return None
    detail = event.get("detail")
    finding_id = detail.get("id") if isinstance(detail, dict) else None
    if not isinstance(finding_id, str) or not _FINDING_ID.match(finding_id):
        return None
    return ParsedMessage(finding_id, "guardduty", event)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo else None


def _clean(value: Any) -> str:
    """One line and bounded: control characters (newlines included) become spaces."""
    if value is None or value == "":
        return "—"
    return _CONTROL.sub(" ", str(value))[:_FIELD_MAX]


def _slack_escape(text: str) -> str:
    # Slack's three control characters; stops <!channel> / <url|label> injection.
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


@dataclass(frozen=True)
class Card:
    incident_id: str
    finding_type: str | None
    attack: tuple[str, ...]
    status: str
    mttc: str
    resource_type: str | None

    def text(self) -> str:
        attack = ", ".join(self.attack) if self.attack else "analyst review"
        return "\n".join(
            [
                f"CloudShield incident {_clean(self.incident_id)}",
                f"Finding: {_clean(self.finding_type)}",
                f"ATT&CK: {_clean(attack)}",
                f"Status: {_clean(self.status)}",
                f"MTTC: {_clean(self.mttc)}",
                f"Resource: {_clean(self.resource_type)}",
            ]
        )

    def payload(self, host: str) -> dict[str, Any]:
        if host == "discord.com" or host.endswith(".discord.com"):
            # Discord shows entities literally; mentions are disabled instead.
            return {"content": self.text(), "allowed_mentions": {"parse": []}}
        return {"text": _slack_escape(self.text())}


def build_card(parsed: ParsedMessage, row: Mapping[str, Any] | None) -> Card:
    if row is not None:
        finding_type = row.get("findingType")
        status = str(row.get("status", "UNKNOWN"))
        resource_type = row.get("resourceType")
        event_time = _parse_time(row.get("eventTime"))
        contained_at = _parse_time(row.get("containedAt")) if status == "CONTAINED" else None
        mttc = (
            f"{(contained_at - event_time).total_seconds():.1f} s"
            if event_time and contained_at
            else "—"
        )
    else:
        detail = (parsed.event or {}).get("detail") or {}
        resource = detail.get("resource") if isinstance(detail.get("resource"), dict) else {}
        finding_type = detail.get("type")
        resource_type = resource.get("resourceType")
        # Raw GuardDuty event: playbooks are off, so nothing was automated.
        status = "NOTIFIED (no automation)" if parsed.shape == "guardduty" else "UNKNOWN (no row)"
        mttc = "—"
    finding_type = finding_type if isinstance(finding_type, str) else None
    return Card(
        incident_id=parsed.incident_id,
        finding_type=finding_type,
        attack=triage(finding_type).techniques,
        status=status,
        mttc=mttc,
        resource_type=resource_type if isinstance(resource_type, str) else None,
    )


def _host_of(url: str) -> str:
    try:
        return urlsplit(url).hostname or "?"
    except ValueError:
        return "?"


# Per-container cache: {parameter name: (fetched at (monotonic), value)}.
_WEBHOOK_CACHE: dict[str, tuple[float, str]] = {}


def clear_webhook_cache() -> None:
    _WEBHOOK_CACHE.clear()


class Notifier:
    def __init__(
        self,
        settings: NotifierSettings,
        clients: aws.ClientFactory = aws.client,
        monotonic: Callable[[], float] = time.monotonic,
        post: Callable[..., Any] | None = None,
    ) -> None:
        self.settings = settings
        self.clients = clients
        self.monotonic = monotonic
        self.post = post or post_json

    def webhook_url(self) -> str:
        now = self.monotonic()
        cached = _WEBHOOK_CACHE.get(self.settings.webhook_param)
        if cached and now - cached[0] < WEBHOOK_CACHE_SECONDS:
            return cached[1]
        value = self.clients("ssm").get_parameter(
            Name=self.settings.webhook_param, WithDecryption=True
        )["Parameter"]["Value"]
        if not isinstance(value, str) or not value.strip():
            raise NotifierConfigError("webhook parameter is empty")
        _WEBHOOK_CACHE[self.settings.webhook_param] = (now, value.strip())
        return value.strip()

    def _row(self, incident_id: str) -> dict[str, Any] | None:
        repo = IncidentRepository(self.settings.incidents_table, self.clients("dynamodb"))
        try:
            return repo.get(incident_id)
        except LookupError:
            return None
        except (ClientError, BotoCoreError) as exc:
            # Degrade to a card from the message itself; the analyst still hears.
            logger.warning(json.dumps({"notifier": "row-unavailable", "error": type(exc).__name__}))
            return None

    def handle_record(self, record: Any) -> dict[str, Any]:
        sns = record.get("Sns") if isinstance(record, dict) else None
        parsed = parse_message(sns.get("Message") if isinstance(sns, dict) else None)
        if parsed is None:
            logger.info(json.dumps({"notifier": "ignored", "reason": "unrecognised message"}))
            return {"posted": False, "reason": "ignored: unrecognised message"}

        try:
            url = self.webhook_url()
        except (ClientError, BotoCoreError, NotifierConfigError, KeyError, TypeError) as exc:
            logger.error(
                json.dumps({"notifier": "webhook-unreadable", "error": type(exc).__name__})
            )
            return {"posted": False, "reason": "webhook parameter unreadable"}

        try:
            host = validate_url(url, self.settings.allowed_hosts)
        except HttpPolicyError:
            # Only the host is logged, never the URL (its path is the secret).
            logger.error(json.dumps({"notifier": "webhook-refused", "host": _host_of(url)}))
            return {"posted": False, "reason": "webhook URL refused by the outbound policy"}

        card = build_card(parsed, self._row(parsed.incident_id))
        try:
            result = self.post(url, card.payload(host), self.settings.allowed_hosts)
        except Exception as exc:  # noqa: BLE001 - any send failure is reported, never raised into SNS; type name only, so the URL never reaches the logs
            logger.error(
                json.dumps({"notifier": "post-failed", "host": host, "error": type(exc).__name__})
            )
            return {"posted": False, "reason": f"post failed: {type(exc).__name__}"}

        posted = 200 <= int(result.status) < 300
        logger.info(
            json.dumps(
                {
                    "notifier": "posted" if posted else "rejected",
                    "host": host,
                    "status": int(result.status),
                    "incidentId": parsed.incident_id,
                }
            )
        )
        return {"posted": posted, "reason": f"http {int(result.status)}"}

    def handle(self, event: Any) -> dict[str, Any]:
        records = event.get("Records") if isinstance(event, dict) else None
        if not isinstance(records, list) or not records:
            logger.info(json.dumps({"notifier": "ignored", "reason": "no SNS records"}))
            return {"posted": False, "reason": "ignored: no SNS records"}
        results = [self.handle_record(r) for r in records[:MAX_RECORDS]]
        return {"posted": all(r["posted"] for r in results), "results": results}
