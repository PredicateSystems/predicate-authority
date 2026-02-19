from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from predicate_authority import (
    ActionGuard,
    AuthorityMode,
    IdentityBridge,
    InMemoryProofLedger,
    LocalCredentialStore,
    LocalMandateSigner,
    LocalRevocationCache,
    OIDCBridgeConfig,
    OIDCIdentityBridge,
    OktaBridgeConfig,
    OktaIdentityBridge,
    PolicyEngine,
    PredicateAuthoritySidecar,
    SidecarConfig,
)
from predicate_contracts import (
    ActionRequest,
    ActionSpec,
    AuthorizationReason,
    PolicyEffect,
    PolicyRule,
    PrincipalRef,
    StateEvidence,
    VerificationEvidence,
)


def _request() -> ActionRequest:
    return ActionRequest(
        principal=PrincipalRef(principal_id="agent:ops"),
        action_spec=ActionSpec(
            action="http.post",
            resource="https://api.vendor.com/orders",
            intent="create order",
        ),
        state_evidence=StateEvidence(source="backend", state_hash="state-abc"),
        verification_evidence=VerificationEvidence(),
    )


def _guard(policy_engine: PolicyEngine, proof_ledger: InMemoryProofLedger) -> ActionGuard:
    return ActionGuard(
        policy_engine=policy_engine,
        mandate_signer=LocalMandateSigner(secret_key="test-secret", ttl_seconds=60),
        proof_ledger=proof_ledger,
    )


def test_sidecar_connected_mode_requires_refresh_and_uses_bridge(tmp_path: Path) -> None:
    policy_engine = PolicyEngine(
        rules=(
            PolicyRule(
                name="allow-orders",
                effect=PolicyEffect.ALLOW,
                principals=("agent:*",),
                actions=("http.*",),
                resources=("https://api.vendor.com/*",),
            ),
        )
    )
    proof_ledger = InMemoryProofLedger()
    bridge = OIDCIdentityBridge(
        OIDCBridgeConfig(
            issuer="https://issuer.example.com",
            client_id="client-id",
            audience="api://orders",
            token_ttl_seconds=120,
        )
    )
    store = LocalCredentialStore(str(tmp_path / "credentials.json"))
    revocation = LocalRevocationCache()
    sidecar = PredicateAuthoritySidecar(
        config=SidecarConfig(mode=AuthorityMode.CLOUD_CONNECTED),
        action_guard=_guard(policy_engine, proof_ledger),
        proof_ledger=proof_ledger,
        identity_bridge=bridge,
        credential_store=store,
        revocation_cache=revocation,
        policy_engine=policy_engine,
    )
    sidecar.store_refresh_token(
        principal_id="agent:ops",
        refresh_token="refresh-123",
        expires_at_epoch_s=int(time.time()) + 300,
    )

    decision = sidecar.issue_mandate(_request())
    exchanged = sidecar.exchange_access_token(
        PrincipalRef(principal_id="agent:ops"),
        StateEvidence(source="backend", state_hash="state-abc"),
    )

    assert decision.allowed is True
    assert exchanged.access_token.startswith("oidc-refresh.")


def test_sidecar_revocation_and_policy_hot_reload(tmp_path: Path) -> None:
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "name": "allow-orders",
                        "effect": "allow",
                        "principals": ["agent:*"],
                        "actions": ["http.*"],
                        "resources": ["https://api.vendor.com/*"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    policy_engine = PolicyEngine(rules=())
    proof_ledger = InMemoryProofLedger()
    sidecar = PredicateAuthoritySidecar(
        config=SidecarConfig(mode=AuthorityMode.LOCAL_ONLY, policy_file_path=str(policy_file)),
        action_guard=_guard(policy_engine, proof_ledger),
        proof_ledger=proof_ledger,
        identity_bridge=IdentityBridge(),
        credential_store=LocalCredentialStore(str(tmp_path / "credentials.json")),
        revocation_cache=LocalRevocationCache(),
        policy_engine=policy_engine,
    )

    changed = sidecar.hot_reload_policy()
    allowed = sidecar.issue_mandate(_request())
    sidecar.revoke_by_invariant("agent:ops")
    revoked = sidecar.issue_mandate(_request())

    assert changed is True
    assert allowed.allowed is True
    assert revoked.allowed is False
    assert revoked.reason == AuthorizationReason.INVALID_MANDATE


def test_sidecar_okta_identity_revocation_and_killswitch_flow(tmp_path: Path) -> None:
    policy_engine = PolicyEngine(
        rules=(
            PolicyRule(
                name="allow-orders",
                effect=PolicyEffect.ALLOW,
                principals=("agent:*",),
                actions=("http.*",),
                resources=("https://api.vendor.com/*",),
            ),
        )
    )
    proof_ledger = InMemoryProofLedger()
    sidecar = PredicateAuthoritySidecar(
        config=SidecarConfig(mode=AuthorityMode.LOCAL_ONLY),
        action_guard=_guard(policy_engine, proof_ledger),
        proof_ledger=proof_ledger,
        identity_bridge=OktaIdentityBridge(
            OktaBridgeConfig(
                issuer="https://dev-123456.okta.com/oauth2/default",
                client_id="okta-client-id",
                audience="api://predicate-authority",
                allowed_signing_algs=("HS256",),
            )
        ),
        credential_store=LocalCredentialStore(str(tmp_path / "credentials.json")),
        revocation_cache=LocalRevocationCache(),
        policy_engine=policy_engine,
    )
    request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:okta-user-1"),
        action_spec=ActionSpec(
            action="http.post",
            resource="https://api.vendor.com/orders",
            intent="create order",
        ),
        state_evidence=StateEvidence(source="backend", state_hash="state-abc"),
        verification_evidence=VerificationEvidence(),
    )

    allowed = sidecar.issue_mandate(request)
    assert allowed.allowed is True
    sidecar.revoke_by_invariant("agent:okta-user-1")
    denied_principal = sidecar.issue_mandate(request)
    assert denied_principal.allowed is False
    assert denied_principal.reason == AuthorizationReason.INVALID_MANDATE

    # Intent-level kill-switch should also deny when principal is otherwise allowed.
    request_for_killswitch = ActionRequest(
        principal=PrincipalRef(principal_id="agent:okta-user-2"),
        action_spec=request.action_spec,
        state_evidence=request.state_evidence,
        verification_evidence=request.verification_evidence,
    )
    pre_killswitch = sidecar.issue_mandate(request_for_killswitch)
    assert pre_killswitch.allowed is True
    intent_hash = hashlib.sha256(
        request_for_killswitch.action_spec.intent.encode("utf-8")
    ).hexdigest()
    sidecar.revoke_intent_hash(intent_hash)
    denied_intent = sidecar.issue_mandate(request_for_killswitch)
    assert denied_intent.allowed is False
    assert denied_intent.reason == AuthorizationReason.INVALID_MANDATE


def test_sidecar_rate_limit_denies_when_principal_exceeds_burst(tmp_path: Path) -> None:
    policy_engine = PolicyEngine(
        rules=(
            PolicyRule(
                name="allow-orders",
                effect=PolicyEffect.ALLOW,
                principals=("agent:*",),
                actions=("http.*",),
                resources=("https://api.vendor.com/*",),
            ),
        )
    )
    proof_ledger = InMemoryProofLedger()
    sidecar = PredicateAuthoritySidecar(
        config=SidecarConfig(
            mode=AuthorityMode.LOCAL_ONLY,
            principal_rate_limit_enabled=True,
            principal_rate_limit_requests_per_second=0.0,
            principal_rate_limit_burst_size=1,
        ),
        action_guard=_guard(policy_engine, proof_ledger),
        proof_ledger=proof_ledger,
        identity_bridge=IdentityBridge(),
        credential_store=LocalCredentialStore(str(tmp_path / "credentials.json")),
        revocation_cache=LocalRevocationCache(),
        policy_engine=policy_engine,
    )

    first = sidecar.issue_mandate(_request())
    second = sidecar.issue_mandate(_request())

    assert first.allowed is True
    assert second.allowed is False
    assert second.reason == AuthorizationReason.RATE_LIMIT_EXCEEDED
    assert second.violated_rule == "principal_rate_limiter"
