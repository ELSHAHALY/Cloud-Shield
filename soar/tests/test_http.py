"""core/http.py: the single outbound HTTPS call site (F27). No test touches the network."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

import pytest

from core import http
from core.http import HttpPolicyError, post_json, validate_url
from tests.fake_https import FakeHttps, install

HOSTS = ("chat.example.test",)
URL = "https://chat.example.test/hook/abc"


@pytest.fixture(autouse=True)
def _offline(no_network: None) -> None:
    """Every test here runs with real sockets and urlopen disabled."""


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://chat.example.test/hook", "only https"),
        ("ftp://chat.example.test/hook", "only https"),
        ("file:///etc/passwd", "only https"),
        ("https://evil.example.test/hook", "not allow-listed"),
        ("https://chat.example.test.evil.test/hook", "not allow-listed"),
        ("https://example.test/hook", "not allow-listed"),
        ("https://user:pw@chat.example.test/hook", "userinfo"),
        ("https://@chat.example.test/hook", "userinfo"),
        ("https://evil.test@chat.example.test/hook", "userinfo"),
        ("https://chat.example.test:8443/hook", "port 443"),
        ("https://chat.example.test:80/hook", "port 443"),
        ("https://chat.example.test:abc/hook", "invalid port"),
        ("https://chat.example.test/ho ok", "whitespace"),
        ("https://chat.example.test/hook\r\nX-Injected: 1", "whitespace"),
        ("https:///hook", "not allow-listed"),
        ("https://[::1/hook", "unparseable"),
    ],
)
def test_validate_url_rejects(url: str, reason: str) -> None:
    with pytest.raises(HttpPolicyError, match=reason):
        validate_url(url, HOSTS)


@pytest.mark.parametrize(
    "url",
    [URL, "https://CHAT.example.test/hook", "https://chat.example.test:443/hook"],
)
def test_validate_url_accepts_exact_host(url: str) -> None:
    assert validate_url(url, HOSTS) == "chat.example.test"


def test_empty_allow_list_refuses_everything() -> None:
    with pytest.raises(HttpPolicyError, match="empty"):
        validate_url(URL, ["", "  "])


def test_non_string_url_is_refused() -> None:
    with pytest.raises(HttpPolicyError):
        validate_url(None, HOSTS)  # type: ignore[arg-type]


def test_post_sends_json_through_the_real_opener(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeHttps(200, b'{"ok":true}')
    install(monkeypatch, fake)
    result = post_json(URL, {"text": "hi ü"}, HOSTS, headers={"X-Extra": "1"})

    assert (result.status, result.body, result.truncated) == (200, b'{"ok":true}', False)
    (req,) = fake.requests
    assert req.get_method() == "POST"
    assert req.full_url == URL
    assert req.get_header("Content-type") == "application/json"
    assert req.get_header("X-extra") == "1"
    assert json.loads(req.data) == {"text": "hi ü"}


def test_content_type_cannot_be_overridden(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeHttps()
    install(monkeypatch, fake)
    post_json(URL, {}, HOSTS, headers={"Content-Type": "text/html"})
    assert fake.requests[0].get_header("Content-type") == "application/json"


def test_redirect_is_not_followed(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeHttps(302, b"", {"Location": "https://chat.example.test/elsewhere"})
    install(monkeypatch, fake)
    with pytest.raises(urllib.error.HTTPError) as caught:
        post_json(URL, {"a": 1}, HOSTS)
    assert caught.value.code == 302
    assert len(fake.requests) == 1  # never re-sent to the Location


@pytest.mark.parametrize("code", [301, 303, 307, 308])
def test_no_redirect_code_is_followed(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    fake = FakeHttps(code, b"", {"Location": "https://evil.example.test/"})
    install(monkeypatch, fake)
    with pytest.raises(urllib.error.HTTPError):
        post_json(URL, {"a": 1}, HOSTS)
    assert [r.full_url for r in fake.requests] == [URL]


def test_redirect_handler_returns_none() -> None:
    handler = http._NoRedirect()
    req = urllib.request.Request(URL)
    assert handler.redirect_request(req, None, 302, "Found", {}, "https://x.test/") is None


def test_proxies_from_the_environment_are_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://proxy.example.test:3128")
    # Control: urllib's default opener WOULD route through the env proxy...
    default = urllib.request.build_opener()
    assert any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in default.handlers)
    # ...ours passes ProxyHandler({}), which replaces it and registers no
    # protocol handler at all, so no proxy is ever consulted.
    opener = http._build_opener()
    assert not [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
    redirects = [h for h in opener.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)]
    assert redirects
    assert all(isinstance(h, http._NoRedirect) for h in redirects)

    fake = FakeHttps()
    install(monkeypatch, fake)
    post_json(URL, {}, HOSTS)
    (req,) = fake.requests
    assert req.host == "chat.example.test"  # not rewritten to the proxy
    assert req._tunnel_host is None  # type: ignore[attr-defined]


def test_response_read_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, FakeHttps(200, b"x" * 10_000))
    result = post_json(URL, {}, HOSTS)
    assert len(result.body) == http.MAX_RESPONSE_BYTES
    assert result.truncated is True


def test_larger_cap_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, FakeHttps(200, b"y" * 5000))
    result = post_json(URL, {}, HOSTS, max_response=8192)
    assert (len(result.body), result.truncated) == (5000, False)
    with pytest.raises(HttpPolicyError, match="max_response"):
        post_json(URL, {}, HOSTS, max_response=http.RESPONSE_CAP_LIMIT + 1)
    with pytest.raises(HttpPolicyError, match="max_response"):
        post_json(URL, {}, HOSTS, max_response=0)


@pytest.mark.parametrize("timeout", [0, -1, 61])
def test_timeout_is_bounded(timeout: float) -> None:
    with pytest.raises(HttpPolicyError, match="timeout"):
        post_json(URL, {}, HOSTS, timeout)


def test_default_timeout_is_three_seconds(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    class Recorder(urllib.request.OpenerDirector):
        def open(self, req: Any, data: Any = None, timeout: Any = None) -> Any:
            seen["timeout"] = timeout
            raise urllib.error.URLError("stop")

    monkeypatch.setattr(http, "_build_opener", Recorder)
    with pytest.raises(urllib.error.URLError):
        post_json(URL, {}, HOSTS)
    assert seen["timeout"] == 3.0


def test_oversized_body_is_refused_before_sending(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeHttps()
    install(monkeypatch, fake)
    with pytest.raises(HttpPolicyError, match="body"):
        post_json(URL, {"text": "z" * http.MAX_BODY_BYTES}, HOSTS)
    assert fake.requests == []


def test_policy_violation_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeHttps()
    install(monkeypatch, fake)
    with pytest.raises(HttpPolicyError):
        post_json("https://evil.example.test/", {}, HOSTS)
    assert fake.requests == []


def test_the_network_guard_is_active() -> None:
    from tests.conftest import NetworkBlockedError

    with pytest.raises(NetworkBlockedError):
        urllib.request.urlopen("https://chat.example.test/")
