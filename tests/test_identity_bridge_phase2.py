from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from predicate_authority import (
    EntraBridgeConfig,
    EntraIdentityBridge,
    LocalIdPBridge,
    LocalIdPBridgeConfig,
    OIDCBridgeConfig,
    OIDCIdentityBridge,
    OktaBridgeConfig,
    OktaIdentityBridge,
    TokenValidationError,
)
from predicate_contracts import PrincipalRef, StateEvidence

# pylint: disable=import-error


def test_oidc_bridge_exchange_and_refresh() -> None:
    bridge = OIDCIdentityBridge(
        OIDCBridgeConfig(
            issuer="https://issuer.example.com",
            client_id="client-a",
            audience="api://service",
            token_ttl_seconds=120,
        )
    )
    subject = PrincipalRef(principal_id="agent:web")
    state = StateEvidence(source="sdk-python", state_hash="state-1")

    access = bridge.exchange_token(subject, state)
    refreshed = bridge.refresh_token("refresh-token-xyz", subject, state)

    assert access.provider.value == "oidc"
    assert access.access_token.startswith("oidc.")
    assert refreshed.access_token.startswith("oidc-refresh.")


def test_entra_bridge_marks_provider() -> None:
    bridge = EntraIdentityBridge(
        EntraBridgeConfig(
            tenant_id="tenant-123",
            client_id="client-entra",
            audience="api://predicate",
            token_ttl_seconds=120,
        )
    )
    subject = PrincipalRef(principal_id="agent:backend")
    state = StateEvidence(source="backend", state_hash="state-2")

    result = bridge.exchange_token(subject, state)

    assert result.provider.value == "entra"


def test_local_idp_bridge_issues_jwt_like_token() -> None:
    bridge = LocalIdPBridge(
        LocalIdPBridgeConfig(
            issuer="http://localhost/local-idp",
            audience="api://predicate-authority",
            signing_key="dev-signing-key",
            token_ttl_seconds=120,
        )
    )
    subject = PrincipalRef(principal_id="agent:local", tenant_id="tenant-a")
    state = StateEvidence(source="backend", state_hash="state-abc")

    token_result = bridge.exchange_token(subject, state)
    token = token_result.access_token
    segments = token.split(".")
    assert len(segments) == 3
    payload = _decode_jwt_payload(segments[1])
    assert payload["iss"] == "http://localhost/local-idp"
    assert payload["aud"] == "api://predicate-authority"
    assert payload["sub"] == "agent:local"
    assert payload["state_hash"] == "state-abc"
    assert token_result.provider.value == "local_idp"

    refreshed = bridge.refresh_token("refresh-123", subject, state)
    refreshed_payload = _decode_jwt_payload(refreshed.access_token.split(".")[1])
    assert refreshed_payload["token_kind"] == "refresh_access"


def test_okta_bridge_marks_provider() -> None:
    bridge = OktaIdentityBridge(
        OktaBridgeConfig(
            issuer="https://dev-123456.okta.com/oauth2/default",
            client_id="okta-client-id",
            audience="api://predicate-authority",
            token_ttl_seconds=120,
        )
    )
    subject = PrincipalRef(principal_id="agent:okta")
    state = StateEvidence(source="backend", state_hash="state-okta")

    result = bridge.exchange_token(subject, state)

    assert result.provider.value == "okta"


def test_okta_bridge_validates_issuer_audience_and_required_claims() -> None:
    bridge = OktaIdentityBridge(
        OktaBridgeConfig(
            issuer="https://dev-123456.okta.com/oauth2/default",
            client_id="okta-client-id",
            audience="api://predicate-authority",
            required_claims=("sub", "tenant_id"),
            allowed_signing_algs=("HS256",),
            clock_skew_leeway_seconds=5,
        )
    )
    token = _build_test_jwt(
        {
            "iss": "https://dev-123456.okta.com/oauth2/default",
            "aud": "api://predicate-authority",
            "sub": "agent:okta",
            "tenant_id": "tenant-a",
            "exp": 1100,
            "iat": 1000,
            "nbf": 995,
        }
    )
    claims = bridge.validate_token_claims(token, now_epoch_s=1000)
    assert claims.subject == "agent:okta"
    assert "api://predicate-authority" in claims.audience


def test_okta_bridge_fails_closed_on_issuer_mismatch() -> None:
    bridge = OktaIdentityBridge(
        OktaBridgeConfig(
            issuer="https://dev-123456.okta.com/oauth2/default",
            client_id="okta-client-id",
            audience="api://predicate-authority",
            allowed_signing_algs=("HS256",),
            clock_skew_leeway_seconds=5,
        )
    )
    token = _build_test_jwt(
        {
            "iss": "https://evil.okta.com/oauth2/default",
            "aud": "api://predicate-authority",
            "sub": "agent:okta",
            "exp": 1100,
            "iat": 1000,
        }
    )
    with pytest.raises(TokenValidationError):
        bridge.validate_token_claims(token, now_epoch_s=1000)


def test_okta_bridge_fails_closed_on_audience_mismatch() -> None:
    bridge = OktaIdentityBridge(
        OktaBridgeConfig(
            issuer="https://dev-123456.okta.com/oauth2/default",
            client_id="okta-client-id",
            audience="api://predicate-authority",
            allowed_signing_algs=("HS256",),
            clock_skew_leeway_seconds=5,
        )
    )
    token = _build_test_jwt(
        {
            "iss": "https://dev-123456.okta.com/oauth2/default",
            "aud": "api://wrong-audience",
            "sub": "agent:okta",
            "exp": 1100,
            "iat": 1000,
        }
    )
    with pytest.raises(TokenValidationError):
        bridge.validate_token_claims(token, now_epoch_s=1000)


def test_okta_bridge_fails_closed_on_missing_required_claims() -> None:
    bridge = OktaIdentityBridge(
        OktaBridgeConfig(
            issuer="https://dev-123456.okta.com/oauth2/default",
            client_id="okta-client-id",
            audience="api://predicate-authority",
            required_claims=("sub", "tenant_id"),
            allowed_signing_algs=("HS256",),
            clock_skew_leeway_seconds=5,
        )
    )
    token = _build_test_jwt(
        {
            "iss": "https://dev-123456.okta.com/oauth2/default",
            "aud": "api://predicate-authority",
            "sub": "agent:okta",
            "exp": 1100,
            "iat": 1000,
        }
    )
    with pytest.raises(TokenValidationError):
        bridge.validate_token_claims(token, now_epoch_s=1000)


def test_okta_bridge_fails_closed_on_algorithm_none() -> None:
    bridge = OktaIdentityBridge(
        OktaBridgeConfig(
            issuer="https://dev-123456.okta.com/oauth2/default",
            client_id="okta-client-id",
            audience="api://predicate-authority",
            allowed_signing_algs=("RS256",),
            clock_skew_leeway_seconds=5,
        )
    )
    token = _build_test_jwt(
        {
            "iss": "https://dev-123456.okta.com/oauth2/default",
            "aud": "api://predicate-authority",
            "sub": "agent:okta",
            "exp": 1100,
            "iat": 1000,
        },
        alg="none",
    )
    with pytest.raises(TokenValidationError):
        bridge.validate_token_claims(token, now_epoch_s=1000)


def test_okta_bridge_fails_closed_on_algorithm_not_allowlisted() -> None:
    bridge = OktaIdentityBridge(
        OktaBridgeConfig(
            issuer="https://dev-123456.okta.com/oauth2/default",
            client_id="okta-client-id",
            audience="api://predicate-authority",
            allowed_signing_algs=("RS256",),
            clock_skew_leeway_seconds=5,
        )
    )
    token = _build_test_jwt(
        {
            "iss": "https://dev-123456.okta.com/oauth2/default",
            "aud": "api://predicate-authority",
            "sub": "agent:okta",
            "exp": 1100,
            "iat": 1000,
        },
        alg="HS256",
    )
    with pytest.raises(TokenValidationError):
        bridge.validate_token_claims(token, now_epoch_s=1000)


def test_okta_bridge_fails_closed_on_expired_token() -> None:
    bridge = OktaIdentityBridge(
        OktaBridgeConfig(
            issuer="https://dev-123456.okta.com/oauth2/default",
            client_id="okta-client-id",
            audience="api://predicate-authority",
            allowed_signing_algs=("HS256",),
            clock_skew_leeway_seconds=5,
        )
    )
    token = _build_test_jwt(
        {
            "iss": "https://dev-123456.okta.com/oauth2/default",
            "aud": "api://predicate-authority",
            "sub": "agent:okta",
            "exp": 900,
            "iat": 800,
        }
    )
    with pytest.raises(TokenValidationError):
        bridge.validate_token_claims(token, now_epoch_s=1000)


def test_okta_bridge_fails_closed_when_nbf_is_too_far_in_future() -> None:
    bridge = OktaIdentityBridge(
        OktaBridgeConfig(
            issuer="https://dev-123456.okta.com/oauth2/default",
            client_id="okta-client-id",
            audience="api://predicate-authority",
            allowed_signing_algs=("HS256",),
            clock_skew_leeway_seconds=5,
        )
    )
    token = _build_test_jwt(
        {
            "iss": "https://dev-123456.okta.com/oauth2/default",
            "aud": "api://predicate-authority",
            "sub": "agent:okta",
            "exp": 1100,
            "iat": 1000,
            "nbf": 1010,
        }
    )
    with pytest.raises(TokenValidationError):
        bridge.validate_token_claims(token, now_epoch_s=1000)


def test_okta_bridge_fails_closed_when_iat_is_too_far_in_future() -> None:
    bridge = OktaIdentityBridge(
        OktaBridgeConfig(
            issuer="https://dev-123456.okta.com/oauth2/default",
            client_id="okta-client-id",
            audience="api://predicate-authority",
            allowed_signing_algs=("HS256",),
            clock_skew_leeway_seconds=5,
        )
    )
    token = _build_test_jwt(
        {
            "iss": "https://dev-123456.okta.com/oauth2/default",
            "aud": "api://predicate-authority",
            "sub": "agent:okta",
            "exp": 1100,
            "iat": 1010,
        }
    )
    with pytest.raises(TokenValidationError):
        bridge.validate_token_claims(token, now_epoch_s=1000)


def test_okta_bridge_enforces_tenant_scope_and_role_guards() -> None:
    bridge = OktaIdentityBridge(
        OktaBridgeConfig(
            issuer="https://dev-123456.okta.com/oauth2/default",
            client_id="okta-client-id",
            audience="api://predicate-authority",
            allowed_signing_algs=("HS256",),
            clock_skew_leeway_seconds=5,
            allowed_tenants=("tenant-a",),
            required_scopes=("authority:check",),
            required_roles=("authority-operator",),
        )
    )
    token = _build_test_jwt(
        {
            "iss": "https://dev-123456.okta.com/oauth2/default",
            "aud": "api://predicate-authority",
            "sub": "agent:okta",
            "tenant_id": "tenant-a",
            "scope": "authority:check authority:read",
            "groups": ["authority-operator", "auditor"],
            "exp": 1100,
            "iat": 1000,
        }
    )
    claims = bridge.validate_token_claims(token, now_epoch_s=1000)
    assert claims.claims["tenant_id"] == "tenant-a"


def test_okta_bridge_fails_closed_when_tenant_not_allowed() -> None:
    bridge = OktaIdentityBridge(
        OktaBridgeConfig(
            issuer="https://dev-123456.okta.com/oauth2/default",
            client_id="okta-client-id",
            audience="api://predicate-authority",
            allowed_signing_algs=("HS256",),
            clock_skew_leeway_seconds=5,
            allowed_tenants=("tenant-a",),
        )
    )
    token = _build_test_jwt(
        {
            "iss": "https://dev-123456.okta.com/oauth2/default",
            "aud": "api://predicate-authority",
            "sub": "agent:okta",
            "tenant_id": "tenant-z",
            "exp": 1100,
            "iat": 1000,
        }
    )
    with pytest.raises(TokenValidationError):
        bridge.validate_token_claims(token, now_epoch_s=1000)


def test_okta_bridge_fails_closed_when_required_scope_missing() -> None:
    bridge = OktaIdentityBridge(
        OktaBridgeConfig(
            issuer="https://dev-123456.okta.com/oauth2/default",
            client_id="okta-client-id",
            audience="api://predicate-authority",
            allowed_signing_algs=("HS256",),
            clock_skew_leeway_seconds=5,
            required_scopes=("authority:check",),
        )
    )
    token = _build_test_jwt(
        {
            "iss": "https://dev-123456.okta.com/oauth2/default",
            "aud": "api://predicate-authority",
            "sub": "agent:okta",
            "scope": "authority:read",
            "exp": 1100,
            "iat": 1000,
        }
    )
    with pytest.raises(TokenValidationError):
        bridge.validate_token_claims(token, now_epoch_s=1000)


def test_okta_bridge_fails_closed_when_required_role_missing() -> None:
    bridge = OktaIdentityBridge(
        OktaBridgeConfig(
            issuer="https://dev-123456.okta.com/oauth2/default",
            client_id="okta-client-id",
            audience="api://predicate-authority",
            allowed_signing_algs=("HS256",),
            clock_skew_leeway_seconds=5,
            required_roles=("authority-operator",),
        )
    )
    token = _build_test_jwt(
        {
            "iss": "https://dev-123456.okta.com/oauth2/default",
            "aud": "api://predicate-authority",
            "sub": "agent:okta",
            "groups": ["auditor"],
            "exp": 1100,
            "iat": 1000,
        }
    )
    with pytest.raises(TokenValidationError):
        bridge.validate_token_claims(token, now_epoch_s=1000)


class _OktaJwksHandler(BaseHTTPRequestHandler):
    jwks_keys: list[dict[str, object]] = [{"kid": "kid-1", "kty": "RSA"}]
    fail_mode: bool = False
    hits_discovery: int = 0
    hits_jwks: int = 0

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/.well-known/openid-configuration":
            self.__class__.hits_discovery += 1
            self._send_json(200, {"jwks_uri": f"http://127.0.0.1:{self.server.server_port}/jwks"})
            return
        if self.path == "/jwks":
            self.__class__.hits_jwks += 1
            if self.__class__.fail_mode:
                self._send_json(503, {"error": "unavailable"})
                return
            self._send_json(200, {"keys": self.__class__.jwks_keys})
            return
        self._send_json(404, {"error": "not_found"})

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        _ = fmt
        return

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def _start_okta_jwks_server() -> tuple[ThreadingHTTPServer, threading.Thread]:
    _OktaJwksHandler.jwks_keys = [{"kid": "kid-1", "kty": "RSA"}]
    _OktaJwksHandler.fail_mode = False
    _OktaJwksHandler.hits_discovery = 0
    _OktaJwksHandler.hits_jwks = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OktaJwksHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_okta_bridge_jwks_discovery_fetch_and_cache() -> None:
    server, _ = _start_okta_jwks_server()
    try:
        bridge = OktaIdentityBridge(
            OktaBridgeConfig(
                issuer="https://dev-123456.okta.com/oauth2/default",
                client_id="okta-client-id",
                audience="api://predicate-authority",
                allowed_signing_algs=("RS256",),
                clock_skew_leeway_seconds=5,
                enable_jwks_validation=True,
                discovery_url=(
                    f"http://127.0.0.1:{server.server_port}/.well-known/openid-configuration"
                ),
                jwks_cache_ttl_seconds=60,
            )
        )
        token = _build_test_jwt(
            {
                "iss": "https://dev-123456.okta.com/oauth2/default",
                "aud": "api://predicate-authority",
                "sub": "agent:okta",
                "exp": 1100,
                "iat": 1000,
            },
            alg="RS256",
            kid="kid-1",
        )

        bridge.validate_token_claims(token, now_epoch_s=1000)
        bridge.validate_token_claims(token, now_epoch_s=1001)

        assert _OktaJwksHandler.hits_discovery == 1
        assert _OktaJwksHandler.hits_jwks == 1
    finally:
        server.shutdown()
        server.server_close()


def test_okta_bridge_jwks_kid_rollover_refreshes_without_restart() -> None:
    server, _ = _start_okta_jwks_server()
    try:
        bridge = OktaIdentityBridge(
            OktaBridgeConfig(
                issuer="https://dev-123456.okta.com/oauth2/default",
                client_id="okta-client-id",
                audience="api://predicate-authority",
                allowed_signing_algs=("RS256",),
                clock_skew_leeway_seconds=5,
                enable_jwks_validation=True,
                jwks_url=f"http://127.0.0.1:{server.server_port}/jwks",
                jwks_cache_ttl_seconds=60,
            )
        )
        token_k1 = _build_test_jwt(
            {
                "iss": "https://dev-123456.okta.com/oauth2/default",
                "aud": "api://predicate-authority",
                "sub": "agent:okta",
                "exp": 1100,
                "iat": 1000,
            },
            alg="RS256",
            kid="kid-1",
        )
        bridge.validate_token_claims(token_k1, now_epoch_s=1000)

        _OktaJwksHandler.jwks_keys = [{"kid": "kid-2", "kty": "RSA"}]
        token_k2 = _build_test_jwt(
            {
                "iss": "https://dev-123456.okta.com/oauth2/default",
                "aud": "api://predicate-authority",
                "sub": "agent:okta",
                "exp": 1101,
                "iat": 1001,
            },
            alg="RS256",
            kid="kid-2",
        )
        bridge.validate_token_claims(token_k2, now_epoch_s=1001)
        assert _OktaJwksHandler.hits_jwks == 2
    finally:
        server.shutdown()
        server.server_close()


def test_okta_bridge_jwks_stale_cache_and_outage_fails_closed_with_diagnostics() -> None:
    server, _ = _start_okta_jwks_server()
    try:
        bridge = OktaIdentityBridge(
            OktaBridgeConfig(
                issuer="https://dev-123456.okta.com/oauth2/default",
                client_id="okta-client-id",
                audience="api://predicate-authority",
                allowed_signing_algs=("RS256",),
                clock_skew_leeway_seconds=5,
                enable_jwks_validation=True,
                jwks_url=f"http://127.0.0.1:{server.server_port}/jwks",
                jwks_cache_ttl_seconds=1,
                jwks_timeout_s=0.5,
                jwks_max_retries=2,
                jwks_backoff_initial_s=0.0,
            )
        )
        token_k1 = _build_test_jwt(
            {
                "iss": "https://dev-123456.okta.com/oauth2/default",
                "aud": "api://predicate-authority",
                "sub": "agent:okta",
                "exp": 1100,
                "iat": 1000,
            },
            alg="RS256",
            kid="kid-1",
        )
        bridge.validate_token_claims(token_k1, now_epoch_s=1000)

        _OktaJwksHandler.fail_mode = True
        token_k2 = _build_test_jwt(
            {
                "iss": "https://dev-123456.okta.com/oauth2/default",
                "aud": "api://predicate-authority",
                "sub": "agent:okta",
                "exp": 1102,
                "iat": 1002,
            },
            alg="RS256",
            kid="kid-2",
        )
        with pytest.raises(TokenValidationError) as exc:
            bridge.validate_token_claims(token_k2, now_epoch_s=1002)
        assert "JWKS fetch failed after retries" in str(exc.value)
        assert "attempts=3" in str(exc.value)
        assert "timeout_s=0.5" in str(exc.value)
    finally:
        server.shutdown()
        server.server_close()


def test_okta_validation_error_is_reasonful_and_redacted() -> None:
    bridge = OktaIdentityBridge(
        OktaBridgeConfig(
            issuer="https://dev-123456.okta.com/oauth2/default",
            client_id="okta-client-id",
            audience="api://predicate-authority",
            allowed_signing_algs=("HS256",),
            clock_skew_leeway_seconds=5,
        )
    )
    token = _build_test_jwt(
        {
            "iss": "https://evil.okta.com/oauth2/default",
            "aud": "api://predicate-authority",
            "sub": "secret-principal-token-material",
            "exp": 1100,
            "iat": 1000,
        },
        alg="HS256",
        kid="secret-kid-material",
    )
    with pytest.raises(TokenValidationError) as exc:
        bridge.validate_token_claims(token, now_epoch_s=1000)
    message = str(exc.value)
    assert "issuer mismatch" in message.lower()
    # Ensure we do not leak raw token/claim values in validation errors.
    assert token not in message
    assert "secret-principal-token-material" not in message
    assert "secret-kid-material" not in message


def _decode_jwt_payload(payload_segment: str) -> dict[str, object]:
    # Pad URL-safe base64 to standard length.
    padding = "=" * (-len(payload_segment) % 4)
    decoded = base64.urlsafe_b64decode((payload_segment + padding).encode("utf-8"))
    loaded = json.loads(decoded.decode("utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _build_test_jwt(payload: dict[str, object], alg: str = "HS256", kid: str = "test-kid") -> str:
    header = {"alg": alg, "typ": "JWT", "kid": kid}
    header_segment = _encode_json_segment(header)
    payload_segment = _encode_json_segment(payload)
    signature_segment = _encode_json_segment({"sig": "test"})
    return f"{header_segment}.{payload_segment}.{signature_segment}"


def _encode_json_segment(value: dict[str, object]) -> str:
    encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("utf-8")
