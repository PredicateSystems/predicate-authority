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
    OidcCompatibilityConfig,
    OidcProviderCapabilities,
    parse_bool,
    run_oidc_token_exchange_compatibility_check,
)


@dataclass
class _Recorder:
    requests: list[tuple[str, dict[str, str]]]


class _OidcCompatHandler(BaseHTTPRequestHandler):
    recorder: _Recorder
    supports_token_exchange: bool

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/.well-known/openid-configuration":
            self._send_json(
                200, {"token_endpoint": f"http://127.0.0.1:{self.server.server_port}/oauth2/token"}
            )
            return
        self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/oauth2/token":
            self._send_json(404, {"error": "not_found"})
            return
        raw_len = self.headers.get("Content-Length", "0")
        content_length = int(raw_len) if raw_len.isdigit() else 0
        payload = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""
        parsed = {k: v[0] for k, v in parse_qs(payload).items() if len(v) > 0}
        self.recorder.requests.append((self.path, parsed))
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
    recorder = _Recorder(requests=[])

    class _BoundHandler(_OidcCompatHandler):
        pass

    _BoundHandler.recorder = recorder
    _BoundHandler.supports_token_exchange = supports_token_exchange
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BoundHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, recorder


def test_parse_bool_common_values_for_oidc() -> None:
    assert parse_bool("true") is True
    assert parse_bool("false") is False
    assert parse_bool("1") is True
    assert parse_bool("0") is False


def test_oidc_exchange_check_gates_when_capability_disabled() -> None:
    server, _, recorder = _start_server(supports_token_exchange=False)
    try:
        result = run_oidc_token_exchange_compatibility_check(
            config=OidcCompatibilityConfig(
                issuer=f"http://127.0.0.1:{server.server_port}",
                client_id="client-id",
                client_secret="client-secret",
                audience="api://predicate-authority",
            ),
            capabilities=OidcProviderCapabilities(supports_token_exchange=False),
            timeout_s=2.0,
        )
        assert result["client_credentials_ok"] is True
        assert result["token_exchange_ok"] is False
        assert result["token_exchange_reason"] == "provider_capability_disabled"
        grants = [payload.get("grant_type", "") for _, payload in recorder.requests]
        assert grants.count("client_credentials") == 1
        assert grants.count("urn:ietf:params:oauth:grant-type:token-exchange") == 0
    finally:
        server.shutdown()
        server.server_close()


def test_oidc_exchange_requires_subject_token_when_enabled() -> None:
    server, _, recorder = _start_server(supports_token_exchange=True)
    try:
        result = run_oidc_token_exchange_compatibility_check(
            config=OidcCompatibilityConfig(
                issuer=f"http://127.0.0.1:{server.server_port}",
                client_id="client-id",
                client_secret="client-secret",
                audience="api://predicate-authority",
            ),
            capabilities=OidcProviderCapabilities(supports_token_exchange=True),
            subject_token=None,
            timeout_s=2.0,
        )
        assert result["client_credentials_ok"] is True
        assert result["token_exchange_ok"] is False
        assert result["token_exchange_reason"] == "subject_token_required"
        grants = [payload.get("grant_type", "") for _, payload in recorder.requests]
        assert grants.count("client_credentials") == 1
        assert grants.count("urn:ietf:params:oauth:grant-type:token-exchange") == 0
    finally:
        server.shutdown()
        server.server_close()


def test_oidc_exchange_succeeds_when_supported_and_subject_present() -> None:
    server, _, recorder = _start_server(supports_token_exchange=True)
    try:
        result = run_oidc_token_exchange_compatibility_check(
            config=OidcCompatibilityConfig(
                issuer=f"http://127.0.0.1:{server.server_port}",
                client_id="client-id",
                client_secret="client-secret",
                audience="api://predicate-authority",
            ),
            capabilities=OidcProviderCapabilities(supports_token_exchange=True),
            subject_token="subject-token",
            timeout_s=2.0,
        )
        assert result["client_credentials_ok"] is True
        assert result["token_exchange_ok"] is True
        assert result["token_exchange_reason"] == "ok"
        grants = [payload.get("grant_type", "") for _, payload in recorder.requests]
        assert grants.count("client_credentials") == 1
        assert grants.count("urn:ietf:params:oauth:grant-type:token-exchange") == 1
    finally:
        server.shutdown()
        server.server_close()


def test_oidc_live_check_when_enabled() -> None:
    if os.getenv("OIDC_COMPAT_CHECK_ENABLED") != "1":
        pytest.skip("Set OIDC_COMPAT_CHECK_ENABLED=1 to run live OIDC compatibility check.")
    issuer = os.getenv("OIDC_ISSUER")
    client_id = os.getenv("OIDC_CLIENT_ID")
    client_secret = os.getenv("OIDC_CLIENT_SECRET")
    audience = os.getenv("OIDC_AUDIENCE")
    if not all([issuer, client_id, client_secret, audience]):
        pytest.skip("Missing required live OIDC env vars.")
    supports_exchange = parse_bool(os.getenv("OIDC_SUPPORTS_TOKEN_EXCHANGE"), default=False)
    subject_token = os.getenv("OIDC_SUBJECT_TOKEN")
    result = run_oidc_token_exchange_compatibility_check(
        config=OidcCompatibilityConfig(
            issuer=str(issuer),
            client_id=str(client_id),
            client_secret=str(client_secret),
            audience=str(audience),
            scope=os.getenv("OIDC_SCOPE", "authority:check"),
        ),
        capabilities=OidcProviderCapabilities(supports_token_exchange=supports_exchange),
        subject_token=subject_token,
        timeout_s=float(os.getenv("OIDC_HTTP_TIMEOUT_S", "5.0")),
    )
    assert result["client_credentials_ok"] is True
    if supports_exchange:
        if subject_token is None or subject_token.strip() == "":
            assert result["token_exchange_reason"] == "subject_token_required"
        else:
            assert result["token_exchange_ok"] is True
    else:
        assert result["token_exchange_reason"] == "provider_capability_disabled"
