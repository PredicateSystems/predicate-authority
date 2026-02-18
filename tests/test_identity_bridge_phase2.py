from __future__ import annotations

import base64
import json

from predicate_authority import (
    EntraBridgeConfig,
    EntraIdentityBridge,
    LocalIdPBridge,
    LocalIdPBridgeConfig,
    OIDCBridgeConfig,
    OIDCIdentityBridge,
    OktaBridgeConfig,
    OktaIdentityBridge,
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


def _decode_jwt_payload(payload_segment: str) -> dict[str, object]:
    # Pad URL-safe base64 to standard length.
    padding = "=" * (-len(payload_segment) % 4)
    decoded = base64.urlsafe_b64decode((payload_segment + padding).encode("utf-8"))
    loaded = json.loads(decoded.decode("utf-8"))
    assert isinstance(loaded, dict)
    return loaded
