"""Optional LLM summary for the IR report (plan §5.2, D17). OFF by default.

Runs only when ALL of these hold: the analyst passed `--ai-summary`,
`CLOUDSHIELD_LLM_PROVIDER=anthropic`, and `ANTHROPIC_API_KEY` is set.
Otherwise nothing here makes a call.

What leaves the machine is a small, REDACTED projection of the incident:
finding type, resource type, status, MTTC and the playbook step names. Raw
rows and evidence are never sent. Regex scrubbing then replaces ARNs, 12-digit
account ids, IPv4/IPv6 addresses, emails, AWS access key ids and every bucket
name seen on the row with placeholders.

The call goes through `core.http.post_json` with the allow-list
{"api.anthropic.com"} (https, exact host, no redirects, no proxies). Any error,
refusal or unexpected response degrades to "AI summary unavailable"; the
report's exit code never changes. This module lives under tools/, which the
Lambda zip does not contain (scripts/package_soar.py), so no Lambda can import it.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from core.http import post_json

PROVIDER_ENV = "CLOUDSHIELD_LLM_PROVIDER"
API_KEY_ENV = "ANTHROPIC_API_KEY"
PROVIDER = "anthropic"

# Messages API, per the claude-api skill (cURL reference).
ENDPOINT = "https://api.anthropic.com/v1/messages"
ALLOWED_HOSTS = frozenset({"api.anthropic.com"})
MODEL = "claude-opus-5-5"
API_VERSION = "2023-06-01"
# Server-side refusal fallback ("default" routing), opted in per the skill.
FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_TOKENS = 1024
TIMEOUT_SECONDS = 30.0
MAX_RESPONSE_BYTES = 64 * 1024
MAX_SUMMARY_CHARS = 2000

LABEL = "AI-generated, advisory"
UNAVAILABLE = "AI summary unavailable"

SYSTEM_PROMPT = (
    "You are assisting a security analyst. You receive a redacted summary of one "
    "cloud security incident handled by an automated containment pipeline. Write at "
    "most five short sentences for an executive reader: what happened, whether "
    "containment met the 60-second target, and the next human step. Placeholders in "
    "angle brackets are redacted values; do not guess them. Plain text only."
)

_ARN = re.compile(r"arn:aws[\w-]*:[^\s\"',;|]+")
_KEY_ID = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_IPV6_CANDIDATE = re.compile(r"[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_ACCOUNT = re.compile(r"(?<!\d)\d{12}(?!\d)")
_S3_URI = re.compile(r"s3://[^\s\"']+")
_CONTROL = re.compile(r"[\x00-\x09\x0b-\x1f\x7f]")


def _ipv6(match: re.Match[str]) -> str:
    try:
        ipaddress.ip_address(match.group(0))
    except ValueError:
        return match.group(0)
    return "<ip>"


def redact(text: str, bucket_names: Iterable[str] = ()) -> str:
    """Replace identifying values with placeholders. Order matters: ARNs embed
    account ids and bucket names, so they go first."""
    text = _ARN.sub("<arn>", text)
    text = _S3_URI.sub("s3://<bucket>", text)
    for name in sorted({b for b in bucket_names if b}, key=len, reverse=True):
        text = text.replace(name, "<bucket>")
    text = _KEY_ID.sub("<access-key-id>", text)
    text = _EMAIL.sub("<email>", text)
    text = _IPV6_CANDIDATE.sub(_ipv6, text)
    text = _IPV4.sub("<ip>", text)
    return _ACCOUNT.sub("<account>", text)


def bucket_names_in(value: Any) -> set[str]:
    """Every string stored under a key containing "bucket", at any depth."""
    found: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            if "bucket" in str(key).lower() and isinstance(item, str):
                found.add(item)
            else:
                found |= bucket_names_in(item)
    elif isinstance(value, list | tuple):
        for item in value:
            found |= bucket_names_in(item)
    return found


def projection(report: Mapping[str, Any]) -> dict[str, Any]:
    """The ONLY fields that may be sent (before redaction)."""
    steps = [
        f"{a.get('playbook', '?')}:{a.get('step', '?')}"
        for a in report.get("actions", [])
        if isinstance(a, Mapping)
    ]
    return {
        "findingType": report.get("finding_type"),
        "resourceType": report.get("resource_type"),
        "status": report.get("status"),
        "mttcSeconds": report.get("mttc_seconds"),
        "mttcTargetMet": report.get("mttc_target_met"),
        "actionSteps": steps[:20],
    }


def enabled(requested: bool, env: Mapping[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return (
        requested
        and env.get(PROVIDER_ENV, "").strip().lower() == PROVIDER
        and bool(env.get(API_KEY_ENV, "").strip())
    )


def _text_of(response: bytes) -> str | None:
    data = json.loads(response.decode("utf-8"))
    if not isinstance(data, dict) or data.get("stop_reason") == "refusal":
        return None
    blocks = data.get("content")
    if not isinstance(blocks, list):
        return None
    text = "".join(
        b["text"]
        for b in blocks
        if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str)
    ).strip()
    return _CONTROL.sub(" ", text)[:MAX_SUMMARY_CHARS] or None


def summarise(
    report: Mapping[str, Any],
    env: Mapping[str, str] | None = None,
    post: Callable[..., Any] = post_json,
) -> str:
    """Return the advisory summary, or UNAVAILABLE. Never raises. Callers must
    check `enabled()` first; this function assumes the opt-in was given."""
    env = os.environ if env is None else env
    try:
        buckets = bucket_names_in(report)
        content = redact(json.dumps(projection(report), default=str), buckets)
        result = post(
            ENDPOINT,
            {
                "model": MODEL,
                "max_tokens": MAX_TOKENS,
                "output_config": {"effort": "low"},
                "fallbacks": "default",
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": content}],
            },
            ALLOWED_HOSTS,
            TIMEOUT_SECONDS,
            headers={
                "x-api-key": env.get(API_KEY_ENV, "").strip(),
                "anthropic-version": API_VERSION,
                "anthropic-beta": FALLBACK_BETA,
            },
            max_response=MAX_RESPONSE_BYTES,
        )
        if not 200 <= int(result.status) < 300 or result.truncated:
            return UNAVAILABLE
        return _text_of(result.body) or UNAVAILABLE
    except Exception:  # noqa: BLE001 - D17: any failure degrades to "unavailable"; the report and its exit code are unaffected
        return UNAVAILABLE
