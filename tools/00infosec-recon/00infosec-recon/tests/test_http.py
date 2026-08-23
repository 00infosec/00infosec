from __future__ import annotations

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from infosec_recon.core.config import Config
from infosec_recon.core.http import HttpClient
from infosec_recon.core.scope import Scope, ScopeBlocked


class _FakeResponse:
    status = 200
    headers = {}
    cookies = {}

    def __init__(self):
        self.content = self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def read(self, _max_body):
        return b"ok"


class _FakeSession:
    closed = False

    def __init__(self):
        self.kwargs = None

    def request(self, _method, _url, **kwargs):
        self.kwargs = kwargs
        return _FakeResponse()

    async def close(self):
        self.closed = True


class _RetryHandler(BaseHTTPRequestHandler):
    calls = 0

    def do_GET(self):  # noqa: N802
        type(self).calls += 1
        if type(self).calls == 1:
            self.send_response(429)
            self.send_header("Retry-After", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args):
        pass


def test_retryable_status_retries_before_returning():
    _RetryHandler.calls = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RetryHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        async def run():
            async with HttpClient(Config(SimpleNamespace(proxy=None)),
                                  max_requests=2) as client:
                response = await client.get(
                    f"http://127.0.0.1:{server.server_port}/", retries=1)
                assert response.status == 200
                assert client.requests_made == 2
                assert client.metrics.requests == 2
                assert client.metrics.retries == 1

        asyncio.run(run())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_scoped_dns_private_address_is_blocked(monkeypatch):
    async def run():
        scope = Scope("example.com")
        async with HttpClient(Config(SimpleNamespace(proxy=None)),
                              scope=scope) as client:
            async def private_ips(_host):
                return ["127.0.0.1"]

            monkeypatch.setattr(client, "_resolve_ips", private_ips)
            with pytest.raises(ScopeBlocked, match="dns_loopback"):
                await client.get("http://api.example.com/", scoped=True)
            assert client.requests_made == 0

    asyncio.run(run())


def test_scoped_request_passes_http_proxy():
    async def run():
        client = HttpClient(
            Config(SimpleNamespace(proxy="http://proxy.test:8080")))
        fake = _FakeSession()
        client._session = fake
        try:
            response = await client.get(
                "http://example.com/", scoped=True, retries=0)
            assert response.status == 200
            assert fake.kwargs["proxy"] == "http://proxy.test:8080"
        finally:
            await client.close()

    asyncio.run(run())
