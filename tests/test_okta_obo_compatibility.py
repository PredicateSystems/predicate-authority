from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

import pytest

# pylint: disable=import-error
from predicate_authority import (
    OktaCompatibilityConfig,
    OktaTenantCapabilities,
    parse_bool,
    run_okta_obo_compatibility_check,
)


@dataclass
class _Recorder:
    token_requests: list[dict[str, str]]


class _OktaCompatHandler(BaseHTTPRequestHandler):
    recorder: _Recorder
    supports_token_exchange: bool

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/.well-known/openid-configuration":
            self._send_json(
                200,
                {"token_endpoint": f"http://127.0.0.1:{self.server.server_port}/oauth2/v1/token"},
            )
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/oauth2/v1/token":
            self._send_json(404, {"error": "not_found"})
            return
        raw_len = self.headers.get("Content-Length", "0")
        content_length = int(raw_len) if raw_len.isdigit() else 0
        payload = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""
        parsed = {k: v[0] for k, v in parse_qs(payload).items() if len(v) > 0}
        self.recorder.token_requests.append(parsed)
        grant_type = parsed.get("grant_type", "")
        if grant_type == "client_credentials":
            self._send_json(
                200, {"access_token": "cc-token", "token_type": "Bearer", "expires_in": 300}
            )
            return
        if grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
            if self.supports_token_exchange:
                self._send_json(
                    200,
                    {"access_token": "delegated-token", "token_type": "Bearer", "expires_in": 300},
                )
                return
            self._send_json(
                400,
                {
                    "error": "unsupported_grant_type",
                    "error_description": "token exchange not enabled",
                },
            )
            return
        self._send_json(400, {"error": "invalid_request"})

    def log_message(
        self, fmt: str, *args: Any
    ) -> None:  # noqa: A003  # pylint: disable=arguments-differ
        _ = fmt
        return

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def _start_server(
    supports_token_exchange: bool,
) -> tuple[ThreadingHTTPServer, threading.Thread, _Recorder]:
    recorder = _Recorder(token_requests=[])

    class _BoundHandler(_OktaCompatHandler):
        pass

    _BoundHandler.recorder = recorder
    _BoundHandler.supports_token_exchange = supports_token_exchange
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BoundHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, recorder


def test_parse_bool_common_values() -> None:
    assert parse_bool("true") is True
    assert parse_bool("1") is True
    assert parse_bool("false") is False
    assert parse_bool("0") is False
    assert parse_bool(None, default=True) is True


def test_okta_obo_check_gates_on_tenant_capability() -> None:
    server, _, recorder = _start_server(supports_token_exchange=False)
    try:
        result = run_okta_obo_compatibility_check(
            config=OktaCompatibilityConfig(
                issuer=f"http://127.0.0.1:{server.server_port}",
                client_id="client-id",
                client_secret="client-secret",
                audience="api://predicate-authority",
            ),
            capabilities=OktaTenantCapabilities(supports_token_exchange=False),
            timeout_s=2.0,
        )
        assert result["client_credentials_ok"] is True
        assert result["token_exchange_ok"] is False
        assert result["token_exchange_reason"] == "tenant_capability_disabled"
        # Ensure no token-exchange call is attempted when capability is disabled.
        grant_types = [item.get("grant_type", "") for item in recorder.token_requests]
        assert grant_types.count("client_credentials") == 1
        assert grant_types.count("urn:ietf:params:oauth:grant-type:token-exchange") == 0
    finally:
        server.shutdown()
        server.server_close()


def test_okta_obo_check_succeeds_when_tenant_supports_exchange() -> None:
    server, _, recorder = _start_server(supports_token_exchange=True)
    try:
        result = run_okta_obo_compatibility_check(
            config=OktaCompatibilityConfig(
                issuer=f"http://127.0.0.1:{server.server_port}",
                client_id="client-id",
                client_secret="client-secret",
                audience="api://predicate-authority",
            ),
            capabilities=OktaTenantCapabilities(supports_token_exchange=True),
            timeout_s=2.0,
        )
        assert result["client_credentials_ok"] is True
        assert result["token_exchange_ok"] is True
        assert result["token_exchange_reason"] == "ok"
        grant_types = [item.get("grant_type", "") for item in recorder.token_requests]
        assert grant_types.count("client_credentials") == 1
        assert grant_types.count("urn:ietf:params:oauth:grant-type:token-exchange") == 1
    finally:
        server.shutdown()
        server.server_close()


def test_okta_obo_live_check_when_enabled() -> None:
    if os.getenv("OKTA_OBO_COMPAT_CHECK_ENABLED") != "1":
        pytest.skip("Set OKTA_OBO_COMPAT_CHECK_ENABLED=1 to run live Okta compatibility check.")
    issuer = os.getenv("OKTA_ISSUER")
    client_id = os.getenv("OKTA_CLIENT_ID")
    client_secret = os.getenv("OKTA_CLIENT_SECRET")
    audience = os.getenv("OKTA_AUDIENCE")
    if not all([issuer, client_id, client_secret, audience]):
        pytest.skip("Missing required live Okta env vars.")
    supports_exchange = parse_bool(os.getenv("OKTA_SUPPORTS_TOKEN_EXCHANGE"), default=False)
    result = run_okta_obo_compatibility_check(
        config=OktaCompatibilityConfig(
            issuer=str(issuer),
            client_id=str(client_id),
            client_secret=str(client_secret),
            audience=str(audience),
            scope=os.getenv("OKTA_SCOPE", "authority:check"),
        ),
        capabilities=OktaTenantCapabilities(supports_token_exchange=supports_exchange),
        timeout_s=float(os.getenv("OKTA_HTTP_TIMEOUT_S", "5.0")),
    )
    assert result["client_credentials_ok"] is True
    if supports_exchange:
        assert result["token_exchange_ok"] is True
    else:
        assert result["token_exchange_reason"] == "tenant_capability_disabled"
