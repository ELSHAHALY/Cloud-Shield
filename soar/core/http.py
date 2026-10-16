"""The one outbound-HTTPS call site in the SOAR package (plan §5.1, F27).

Every non-AWS request (the ChatOps notifier, the optional LLM hook in the IR
report tool) goes through `post_json`, which refuses anything but:

* scheme `https`, a host EXACTLY in the caller's allow-list (no suffix or
  wildcard matching), no userinfo, and no port other than 443;
* a JSON body of at most 8 KiB.

The opener ignores `*_proxy` environment variables (`ProxyHandler({})`) and
never follows a redirect (a 3xx becomes an `HTTPError`), so an allow-listed
host cannot bounce the request, or the body, anywhere else. The response is
read up to a cap (4 KiB by default) and never parsed here.
"""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request

MAX_BODY_BYTES = 8 * 1024
MAX_RESPONSE_BYTES = 4 * 1024
# Callers that need the response (the LLM hook) may raise the read cap, never
# beyond this.
RESPONSE_CAP_LIMIT = 64 * 1024
DEFAULT_TIMEOUT = 3.0
TIMEOUT_LIMIT = 60.0


class HttpPolicyError(ValueError):
    """The request breaks the outbound policy; nothing was sent."""


@dataclass(frozen=True)
class HttpResult:
    status: int
    body: bytes  # at most the read cap
    truncated: bool  # the server sent more than the cap


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: returning None makes urllib raise HTTPError(3xx)."""

    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def _build_opener() -> urllib.request.OpenerDirector:
    # Passing a ProxyHandler and an HTTPRedirectHandler subclass REPLACES the
    # defaults build_opener would add (env proxies, redirect following).
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def validate_url(url: str, allowed_hosts: Iterable[str]) -> str:
    """Return the host if `url` may be called, else raise HttpPolicyError."""
    allowed = {h.strip().lower() for h in allowed_hosts if h and h.strip()}
    if not allowed:
        raise HttpPolicyError("empty host allow-list")
    if not isinstance(url, str) or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in url):
        raise HttpPolicyError("URL contains whitespace or control characters")
    try:
        parts = urlsplit(url)
    except ValueError as exc:  # e.g. "Invalid IPv6 URL"
        raise HttpPolicyError("unparseable URL") from exc
    if parts.scheme != "https":
        raise HttpPolicyError("only https is allowed")
    if "@" in parts.netloc:
        raise HttpPolicyError("userinfo is not allowed")
    try:
        port = parts.port
    except ValueError as exc:
        raise HttpPolicyError("invalid port") from exc
    if port not in (None, 443):
        raise HttpPolicyError("only port 443 is allowed")
    host = (parts.hostname or "").lower()
    if host not in allowed:
        raise HttpPolicyError(f"host {host!r} is not allow-listed")
    return host


def post_json(
    url: str,
    body: Mapping[str, Any],
    allowed_hosts: Iterable[str],
    timeout: float = DEFAULT_TIMEOUT,
    *,
    headers: Mapping[str, str] | None = None,
    max_response: int = MAX_RESPONSE_BYTES,
) -> HttpResult:
    """POST `body` as JSON. Raises HttpPolicyError before sending anything that
    breaks the policy; network and HTTP errors (including any 3xx) propagate."""
    validate_url(url, allowed_hosts)
    if not 0 < timeout <= TIMEOUT_LIMIT:
        raise HttpPolicyError(f"timeout must be in (0, {TIMEOUT_LIMIT:.0f}] seconds")
    if not 0 < max_response <= RESPONSE_CAP_LIMIT:
        raise HttpPolicyError(f"max_response must be in (0, {RESPONSE_CAP_LIMIT}] bytes")
    data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(data) > MAX_BODY_BYTES:
        raise HttpPolicyError(f"body is {len(data)} bytes; the limit is {MAX_BODY_BYTES}")
    hdrs = {**(headers or {}), "Content-Type": "application/json"}

    opener = _build_opener()
    with opener.open(Request(url, data, hdrs, method="POST"), timeout=timeout) as resp:  # noqa: S310 - scheme and host validated above  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected - allow-listed https host
        raw = resp.read(max_response + 1)
        status = int(resp.status)
    return HttpResult(status, raw[:max_response], len(raw) > max_response)
