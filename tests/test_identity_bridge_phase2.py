from __future__ import annotations

from predicate_authority import (
    EntraBridgeConfig,
    EntraIdentityBridge,
    OIDCBridgeConfig,
    OIDCIdentityBridge,
)
from predicate_contracts import PrincipalRef, StateEvidence


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
