"""ChatOps notifier (plan §5.1, §7): parsing, card, secret handling, never-raise.

Webhook hosts are fake (`*.example.test`) and enter only through the allow-list
mechanism; no test touches the network.
"""

from __future__ import annotations

import json
import logging
import urllib.error
from collections.abc import Iterator
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError

from core import notifier as nt
from core.http import HttpResult
from core.notifier import (
    Card,
    Notifier,
    NotifierConfigError,
    NotifierSettings,
    ParsedMessage,
    build_card,
    parse_message,
)
from notifier import handler
from tests.conftest import INCIDENTS_TABLE
from tests.fake_https import FakeHttps, install

PARAM = "/cs-dev/soar/chatops_webhook"
HOST = "chat.example.test"
# The path segment stands in for the secret part of a real webhook URL.
SECRET_PATH = "hook/T0-not-a-real-secret-path"
WEBHOOK = f"https://{HOST}/{SECRET_PATH}"
ENV = {
    "INCIDENTS_TABLE": INCIDENTS_TABLE,
    "CHATOPS_WEBHOOK_PARAM": PARAM,
    "CHATOPS_ALLOWED_HOSTS": HOST,
}
ROUTER_MSG = (
    "Incident f-notify-1 | Recon:EC2/Portscan | resource Instance | see table cs-dev-soar-incidents"
)


@pytest.fixture(autouse=True)
def _offline(no_network: None) -> Iterator[None]:
    nt.clear_webhook_cache()
    yield
    nt.clear_webhook_cache()


def settings() -> NotifierSettings:
    return NotifierSettings.from_env(ENV)


def put_webhook(value: str = WEBHOOK) -> None:
    boto3.client("ssm").put_parameter(Name=PARAM, Value=value, Type="SecureString", Overwrite=True)


def sns(message: str) -> dict[str, Any]:
    return {"Records": [{"EventSource": "aws:sns", "Sns": {"Message": message}}]}


def guardduty_event(finding_id: str = "f-gd-raw-1") -> dict[str, Any]:
    return {
        "source": "aws.guardduty",
        "detail-type": "GuardDuty Finding",
        "detail": {
            "id": finding_id,
            "type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
            "resource": {"resourceType": "AccessKey"},
        },
    }


class Poster:
    def __init__(self, status: int = 200, exc: Exception | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any], tuple[str, ...]]] = []
        self.status, self.exc = status, exc

    def __call__(self, url: str, body: dict[str, Any], hosts: Any, *_: Any, **__: Any) -> Any:
        self.calls.append((url, body, tuple(hosts)))
        if self.exc:
            raise self.exc
        return HttpResult(self.status, b"", False)


# ------------------------------------------------------------------ parsing
def test_router_string_is_parsed() -> None:
    assert parse_message(ROUTER_MSG) == ParsedMessage("f-notify-1", "router")


def test_raw_guardduty_event_is_parsed() -> None:
    parsed = parse_message(json.dumps(guardduty_event()))
    assert parsed is not None
    assert (parsed.incident_id, parsed.shape) == ("f-gd-raw-1", "guardduty")


@pytest.mark.parametrize(
    "message",
    [
        "hello",
        "",
        None,
        42,
        "Incident  | x",
        "Incident ../../etc | x",
        "Incident a/b | x",
        "incident f-1 | lower-case prefix",
        "Incident " + "x" * 129 + " | too long",
        json.dumps({"source": "aws.config", "detail": {"id": "c-1"}}),  # Config: ignored
        json.dumps({"source": "aws.guardduty", "detail": {"id": "bad id/../"}}),
        json.dumps({"source": "aws.guardduty", "detail": "nope"}),
        json.dumps({"source": "aws.guardduty", "detail": {"id": 7}}),
        json.dumps(["Incident f-1 | list"]),
        "{not json",
    ],
)
def test_anything_else_is_ignored(message: Any) -> None:
    assert parse_message(message) is None


def test_oversized_message_is_ignored() -> None:
    assert parse_message("Incident f-1 | " + "x" * (256 * 1024)) is None


# ------------------------------------------------------------------ settings
@pytest.mark.parametrize(
    "change",
    [
        {"INCIDENTS_TABLE": ""},
        {"CHATOPS_WEBHOOK_PARAM": " "},
        {"CHATOPS_ALLOWED_HOSTS": ""},
        {"CHATOPS_ALLOWED_HOSTS": "https://chat.example.test"},
        {"CHATOPS_ALLOWED_HOSTS": "*.example.test"},
        {"CHATOPS_ALLOWED_HOSTS": "localhost"},
        {"CHATOPS_ALLOWED_HOSTS": "chat.example.test:443"},
    ],
)
def test_settings_reject_bad_env(change: dict[str, str]) -> None:
    with pytest.raises(NotifierConfigError):
        NotifierSettings.from_env({**ENV, **change})


def test_settings_normalise_hosts() -> None:
    s = NotifierSettings.from_env(
        {**ENV, "CHATOPS_ALLOWED_HOSTS": " Chat.Example.Test , b.example.test"}
    )
    assert s.allowed_hosts == ("chat.example.test", "b.example.test")


# ------------------------------------------------------------------ card
def test_card_from_contained_row(world: Any) -> None:
    world.seed_incident(
        "f-notify-1",
        status={"S": "CONTAINED"},
        findingType={"S": "Recon:EC2/Portscan"},
        resourceType={"S": "Instance"},
        eventTime={"S": "2026-10-14T10:00:00.000Z"},
        containedAt={"S": "2026-10-14T10:00:12.500Z"},
    )
    put_webhook()
    post = Poster()
    result = Notifier(settings(), post=post).handle(sns(ROUTER_MSG))

    assert result["posted"] is True
    ((url, body, hosts),) = post.calls
    assert (url, hosts) == (WEBHOOK, (HOST,))
    text = body["text"]
    assert "CloudShield incident f-notify-1" in text
    assert "Finding: Recon:EC2/Portscan" in text
    assert "T1046" in text
    assert "Status: CONTAINED" in text
    assert "MTTC: 12.5 s" in text
    assert "Resource: Instance" in text


def test_card_without_mttc_when_not_contained(world: Any) -> None:
    world.seed_incident(
        "f-notify-1", status={"S": "FAILED"}, eventTime={"S": "2026-10-14T10:00:00Z"}
    )
    card = build_card(ParsedMessage("f-notify-1", "router"), world.incident("f-notify-1"))
    assert (card.status, card.mttc, card.attack) == ("FAILED", "—", ())
    assert "ATT&CK: analyst review" in card.text()


def test_card_from_raw_guardduty_event_without_row(world: Any) -> None:
    put_webhook()
    post = Poster()
    result = Notifier(settings(), post=post).handle(sns(json.dumps(guardduty_event())))
    assert result["posted"] is True
    text = post.calls[0][1]["text"]
    assert "NOTIFIED (no automation)" in text
    assert "T1078, T1552.001" in text
    assert "Resource: AccessKey" in text


def test_router_message_without_row_still_notifies(world: Any) -> None:
    put_webhook()
    post = Poster()
    assert Notifier(settings(), post=post).handle(sns(ROUTER_MSG))["posted"] is True
    assert "UNKNOWN (no row)" in post.calls[0][1]["text"]


def test_row_read_error_degrades_to_message_card(world: Any) -> None:
    put_webhook()

    class BrokenTable:
        def get_item(self, **_: Any) -> Any:
            raise ClientError({"Error": {"Code": "AccessDeniedException"}}, "GetItem")

    def clients(service: str, *_: Any) -> Any:
        return BrokenTable() if service == "dynamodb" else boto3.client(service)

    post = Poster()
    result = Notifier(settings(), clients=clients, post=post).handle(sns(ROUTER_MSG))
    assert result["posted"] is True
    assert "UNKNOWN (no row)" in post.calls[0][1]["text"]


def test_slack_markup_is_escaped_and_lines_flattened() -> None:
    card = Card("f-1", "Evil:<!channel>/A&B\nInjected: line", (), "DETECTED", "—", "<@U1>")
    text = card.payload(HOST)["text"]
    assert "<!channel>" not in text
    assert "&lt;!channel&gt;" in text
    assert "A&amp;B" in text
    assert "&lt;@U1&gt;" in text
    assert "\nInjected" not in text
    assert len(text.splitlines()) == 6


def test_discord_payload_disables_mentions() -> None:
    card = Card("f-1", "@everyone", ("T1046",), "CONTAINED", "1.0 s", "Instance")
    payload = card.payload("discord.com")
    assert payload["allowed_mentions"] == {"parse": []}
    assert "@everyone" in payload["content"]
    assert "ATT&CK: T1046" in payload["content"]


def test_fields_are_bounded() -> None:
    card = Card("f-1", "T" * 5000, (), "S", "—", None)
    assert len(card.text()) < 1000


# ------------------------------------------------------------------ secret
def test_webhook_is_read_with_decryption_and_cached(world: Any) -> None:
    put_webhook()
    calls: list[dict[str, Any]] = []
    real_ssm = boto3.client("ssm")

    class CountingSsm:
        def get_parameter(self, **kwargs: Any) -> Any:
            calls.append(kwargs)
            return real_ssm.get_parameter(**kwargs)

    clock = [1000.0]

    def clients(service: str, *_: Any) -> Any:
        return CountingSsm() if service == "ssm" else boto3.client(service)

    n = Notifier(settings(), clients=clients, monotonic=lambda: clock[0], post=Poster())
    n.handle(sns(ROUTER_MSG))
    clock[0] += 299
    n.handle(sns(ROUTER_MSG))
    assert calls == [{"Name": PARAM, "WithDecryption": True}]
    clock[0] += 2  # 301 s after the first read: the cache has expired
    n.handle(sns(ROUTER_MSG))
    assert len(calls) == 2


def test_ssm_failure_returns_posted_false(world: Any) -> None:
    post = Poster()  # no parameter exists
    result = Notifier(settings(), post=post).handle(sns(ROUTER_MSG))
    assert result["posted"] is False
    assert result["results"][0]["reason"] == "webhook parameter unreadable"
    assert post.calls == []


def test_blank_parameter_is_unreadable(world: Any) -> None:
    put_webhook("   ")
    result = Notifier(settings(), post=Poster()).handle(sns(ROUTER_MSG))
    assert result["results"][0]["reason"] == "webhook parameter unreadable"


@pytest.mark.parametrize(
    "url",
    [
        f"http://{HOST}/{SECRET_PATH}",
        f"https://evil.example.test/{SECRET_PATH}",
        f"https://user@{HOST}/{SECRET_PATH}",
        f"https://{HOST}:8443/{SECRET_PATH}",
        f"https://[::1/{SECRET_PATH}",
    ],
)
def test_webhook_outside_the_policy_is_refused(
    world: Any, url: str, caplog: pytest.LogCaptureFixture
) -> None:
    put_webhook(url)
    post = Poster()
    with caplog.at_level(logging.DEBUG):
        result = Notifier(settings(), post=post).handle(sns(ROUTER_MSG))
    assert result["results"][0]["reason"] == "webhook URL refused by the outbound policy"
    assert post.calls == []
    assert SECRET_PATH not in caplog.text


@pytest.mark.parametrize(
    "exc",
    [
        urllib.error.HTTPError(WEBHOOK, 302, "Found", None, None),  # type: ignore[arg-type]
        urllib.error.URLError(f"cannot reach {WEBHOOK}"),
        TimeoutError(f"timed out: {WEBHOOK}"),
        RuntimeError(WEBHOOK),
    ],
)
def test_post_failure_is_reported_never_raised(
    world: Any, exc: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    put_webhook()
    with caplog.at_level(logging.DEBUG):
        result = Notifier(settings(), post=Poster(exc=exc)).handle(sns(ROUTER_MSG))
    assert result["posted"] is False
    assert result["results"][0]["reason"] == f"post failed: {type(exc).__name__}"
    assert SECRET_PATH not in caplog.text
    assert HOST in caplog.text  # the host, and only the host, is logged


def test_non_2xx_is_not_posted(world: Any) -> None:
    put_webhook()
    result = Notifier(settings(), post=Poster(status=404)).handle(sns(ROUTER_MSG))
    assert result == {"posted": False, "results": [{"posted": False, "reason": "http 404"}]}


def test_webhook_value_never_logged_on_success(
    world: Any, caplog: pytest.LogCaptureFixture
) -> None:
    put_webhook()
    with caplog.at_level(logging.DEBUG):
        Notifier(settings(), post=Poster()).handle(sns(ROUTER_MSG))
    assert "posted" in caplog.text
    assert SECRET_PATH not in caplog.text
    assert WEBHOOK not in caplog.text


# ------------------------------------------------------------------ handler
@pytest.mark.parametrize(
    "event",
    [
        None,
        "x",
        {},
        {"Records": []},
        {"Records": "x"},
        {"Records": [{"Sns": {"Message": "hi"}}]},
        {"Records": [42]},
    ],
)
def test_unhandled_events_are_ignored(world: Any, event: Any) -> None:
    put_webhook()
    post = Poster()
    result = Notifier(settings(), post=post).handle(event)
    assert result["posted"] is False
    assert post.calls == []


def test_handler_end_to_end_through_post_json(
    world: Any, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    put_webhook()
    fake = FakeHttps(200, b"ok")
    install(monkeypatch, fake)
    with caplog.at_level(logging.DEBUG):
        result = handler.lambda_handler(sns(ROUTER_MSG), None)
    assert result["posted"] is True
    (req,) = fake.requests
    assert req.full_url == WEBHOOK
    assert json.loads(req.data)["text"].startswith("CloudShield incident f-notify-1")
    assert SECRET_PATH not in caplog.text


def test_handler_redirect_is_not_followed(world: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    put_webhook()
    fake = FakeHttps(302, b"", {"Location": "https://evil.example.test/"})
    install(monkeypatch, fake)
    result = handler.lambda_handler(sns(ROUTER_MSG), None)
    assert result["posted"] is False
    assert result["results"][0]["reason"] == "post failed: HTTPError"
    assert len(fake.requests) == 1


def test_handler_never_raises_on_bad_config(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ENV:
        monkeypatch.delenv(key, raising=False)
    result = handler.lambda_handler(sns(ROUTER_MSG), None)
    assert result == {"posted": False, "reason": "error: NotifierConfigError"}


def test_handler_never_raises_on_unexpected_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: Any, **__: Any) -> Any:
        raise ValueError(WEBHOOK)

    monkeypatch.setattr(handler.Notifier, "handle", boom)
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    assert handler.lambda_handler(sns(ROUTER_MSG), None) == {
        "posted": False,
        "reason": "error: ValueError",
    }


@pytest.mark.parametrize(
    "times",
    [
        {"eventTime": "garbage", "containedAt": "2026-10-14T10:00:12Z"},
        {"eventTime": "2026-10-14T10:00:00", "containedAt": "2026-10-14T10:00:12Z"},
        {"containedAt": "2026-10-14T10:00:12Z"},
    ],
)
def test_unparseable_times_give_no_mttc(times: dict[str, str]) -> None:
    row = {"status": "CONTAINED", "findingType": "Recon:EC2/Portscan", **times}
    assert build_card(ParsedMessage("f-1", "router"), row).mttc == "—"
