"""An in-process HTTPS endpoint for urllib: no socket is ever opened.

`install(monkeypatch, fake)` makes `core.http._build_opener` return the REAL
opener (ProxyHandler({}), _NoRedirect, default HTTPS handler) plus `fake`,
which runs before the real HTTPSHandler and answers every request itself. So
the tests exercise post_json's actual opener, redirect and proxy behaviour.
"""

from __future__ import annotations

import email.message
import io
import urllib.request
import urllib.response
from typing import Any

import pytest

from core import http


class FakeHttps(urllib.request.BaseHandler):
    handler_order = 100  # before urllib's own HTTPSHandler (500)

    def __init__(
        self, status: int = 200, body: bytes = b"ok", headers: dict[str, str] | None = None
    ) -> None:
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.requests: list[urllib.request.Request] = []

    def https_open(self, req: urllib.request.Request) -> Any:
        self.requests.append(req)
        msg = email.message.Message()
        for key, value in self.headers.items():
            msg[key] = value
        response = urllib.response.addinfourl(io.BytesIO(self.body), msg, req.full_url, self.status)
        response.msg = "fake"  # read by urllib's HTTPErrorProcessor
        return response


def install(
    monkeypatch: pytest.MonkeyPatch, fake: FakeHttps
) -> list[urllib.request.OpenerDirector]:
    real_build = http._build_opener
    built: list[urllib.request.OpenerDirector] = []

    def build() -> urllib.request.OpenerDirector:
        opener = real_build()
        opener.add_handler(fake)
        built.append(opener)
        return opener

    monkeypatch.setattr(http, "_build_opener", build)
    return built
