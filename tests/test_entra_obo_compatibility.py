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
    EntraCompatibilityConfig,
    EntraTenantCapabilities,
    parse_bool,
    run_entra_obo_compatibility_check,
)


@dataclass
class _Recorder:
    token_requests: list[dict[str, str]]


class _EntraCompatHandler(BaseHTTPRequestHandler):
    recorder: _Recorder
    supports_obo: bool

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/test-tenant/oauth2/v2.0/token":
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
        if grant_type == "urn:ietf:params:oauth:grant-type:jwt-bearer":
            if self.supports_obo:
                self._send_json(
                    200,
                    {"access_token": "obo-token", "token_type": "Bearer", "expires_in": 300},
                )
                return
            self._send_json(
                400,
                {
                    "error": "unauthorized_client",
                    "error_description": "configured grants do not allow OBO",
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


def _start_server(supports_obo: bool) -> tuple[ThreadingHTTPServer, threading.Thread, _Recorder]:
    recorder = _Recorder(token_requests=[])

    class _BoundHandler(_EntraCompatHandler):
        pass

    _BoundHandler.recorder = recorder
    _BoundHandler.supports_obo = supports_obo
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BoundHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, recorder


def test_parse_bool_common_values_for_entra() -> None:
    assert parse_bool("true") is True
    assert parse_bool("1") is True
    assert parse_bool("false") is False
    assert parse_bool("0") is False


def test_entra_obo_check_gates_on_tenant_capability() -> None:
    server, _, recorder = _start_server(supports_obo=False)
    try:
        result = run_entra_obo_compatibility_check(
            config=EntraCompatibilityConfig(
                tenant_id="test-tenant",
                client_id="client-id",
                client_secret="client-secret",
                authority_host=f"127.0.0.1:{server.server_port}",
                authority_scheme="http",
            ),
            capabilities=EntraTenantCapabilities(supports_obo=False),
            timeout_s=2.0,
        )
        assert result["client_credentials_ok"] is True
        assert result["obo_ok"] is False
        assert result["obo_reason"] == "tenant_capability_disabled"
        grant_types = [item.get("grant_type", "") for item in recorder.token_requests]
        assert grant_types.count("client_credentials") == 1
        assert grant_types.count("urn:ietf:params:oauth:grant-type:jwt-bearer") == 0
    finally:
        server.shutdown()
        server.server_close()


def test_entra_obo_check_requires_user_assertion_when_enabled() -> None:
    server, _, recorder = _start_server(supports_obo=True)
    try:
        result = run_entra_obo_compatibility_check(
            config=EntraCompatibilityConfig(
                tenant_id="test-tenant",
                client_id="client-id",
                client_secret="client-secret",
                authority_host=f"127.0.0.1:{server.server_port}",
                authority_scheme="http",
            ),
            capabilities=EntraTenantCapabilities(supports_obo=True),
            user_assertion=None,
            timeout_s=2.0,
        )
        assert result["client_credentials_ok"] is True
        assert result["obo_ok"] is False
        assert result["obo_reason"] == "user_assertion_required"
        grant_types = [item.get("grant_type", "") for item in recorder.token_requests]
        assert grant_types.count("client_credentials") == 1
        assert grant_types.count("urn:ietf:params:oauth:grant-type:jwt-bearer") == 0
    finally:
        server.shutdown()
        server.server_close()


def test_entra_obo_check_succeeds_with_assertion_when_supported() -> None:
    server, _, recorder = _start_server(supports_obo=True)
    try:
        result = run_entra_obo_compatibility_check(
            config=EntraCompatibilityConfig(
                tenant_id="test-tenant",
                client_id="client-id",
                client_secret="client-secret",
                authority_host=f"127.0.0.1:{server.server_port}",
                authority_scheme="http",
            ),
            capabilities=EntraTenantCapabilities(supports_obo=True),
            user_assertion="user-assertion-token",
            timeout_s=2.0,
        )
        assert result["client_credentials_ok"] is True
        assert result["obo_ok"] is True
        assert result["obo_reason"] == "ok"
        grant_types = [item.get("grant_type", "") for item in recorder.token_requests]
        assert grant_types.count("client_credentials") == 1
        assert grant_types.count("urn:ietf:params:oauth:grant-type:jwt-bearer") == 1
    finally:
        server.shutdown()
        server.server_close()


def test_entra_obo_live_check_when_enabled() -> None:
    if os.getenv("ENTRA_OBO_COMPAT_CHECK_ENABLED") != "1":
        pytest.skip("Set ENTRA_OBO_COMPAT_CHECK_ENABLED=1 to run live Entra compatibility check.")

    tenant_id = os.getenv("ENTRA_TENANT_ID")
    client_id = os.getenv("ENTRA_CLIENT_ID")
    client_secret = os.getenv("ENTRA_CLIENT_SECRET")
    if not all([tenant_id, client_id, client_secret]):
        pytest.skip("Missing required live Entra env vars.")

    supports_obo = parse_bool(os.getenv("ENTRA_SUPPORTS_OBO"), default=False)
    user_assertion = os.getenv("ENTRA_USER_ASSERTION")
    result = run_entra_obo_compatibility_check(
        config=EntraCompatibilityConfig(
            tenant_id=str(tenant_id),
            client_id=str(client_id),
            client_secret=str(client_secret),
            scope=os.getenv("ENTRA_SCOPE", "api://predicate-authority/.default"),
        ),
        capabilities=EntraTenantCapabilities(supports_obo=supports_obo),
        user_assertion=user_assertion,
        timeout_s=float(os.getenv("ENTRA_HTTP_TIMEOUT_S", "5.0")),
    )
    assert result["client_credentials_ok"] is True
    if supports_obo:
        if user_assertion is None or user_assertion.strip() == "":
            assert result["obo_reason"] == "user_assertion_required"
        else:
            assert result["obo_ok"] is True
    else:
        assert result["obo_reason"] == "tenant_capability_disabled"
