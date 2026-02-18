from __future__ import annotations

import pytest

# pylint: disable=import-error
from predicate_authority import (
    ActionGuard,
    AuthorizationDeniedError,
    InMemoryProofLedger,
    LocalMandateSigner,
    PolicyEngine,
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
    VerificationSignal,
    VerificationStatus,
)


def _build_request(with_verified_label: bool) -> ActionRequest:
    signals = (
        VerificationSignal(
            label="postcondition.url_contains:/checkout",
            status=VerificationStatus.PASSED if with_verified_label else VerificationStatus.FAILED,
            required=True,
        ),
    )
    return ActionRequest(
        principal=PrincipalRef(principal_id="agent:checkout"),
        action_spec=ActionSpec(
            action="http.post",
            resource="https://api.vendor.com/orders",
            intent="submit order payload",
        ),
        state_evidence=StateEvidence(source="sdk-python", state_hash="abc123"),
        verification_evidence=VerificationEvidence(signals=signals),
    )


def _build_guard() -> ActionGuard:
    rules = (
        PolicyRule(
            name="allow-checkout",
            effect=PolicyEffect.ALLOW,
            principals=("agent:*",),
            actions=("http.*",),
            resources=("https://api.vendor.com/*",),
            required_labels=("postcondition.url_contains:/checkout",),
        ),
    )
    return ActionGuard(
        policy_engine=PolicyEngine(rules=rules),
        mandate_signer=LocalMandateSigner(secret_key="dev-secret", ttl_seconds=120),
        proof_ledger=InMemoryProofLedger(),
    )


def test_authorize_allows_and_issues_signed_mandate() -> None:
    guard = _build_guard()
    request = _build_request(with_verified_label=True)

    decision = guard.authorize(request)

    assert decision.allowed is True
    assert decision.reason == AuthorizationReason.ALLOWED
    assert decision.mandate is not None
    assert decision.mandate.claims.principal_id == "agent:checkout"
    assert decision.mandate.claims.action == "http.post"


def test_authorize_denies_when_required_label_missing() -> None:
    guard = _build_guard()
    request = _build_request(with_verified_label=False)

    decision = guard.authorize(request)

    assert decision.allowed is False
    assert decision.reason == AuthorizationReason.MISSING_REQUIRED_VERIFICATION
    assert decision.missing_labels == ("postcondition.url_contains:/checkout",)


def test_enforce_executes_callable_when_allowed() -> None:
    guard = _build_guard()
    request = _build_request(with_verified_label=True)

    result = guard.enforce(lambda: "ok", request)

    assert result.value == "ok"
    assert result.decision.allowed is True
    assert result.mandate.claims.resource == "https://api.vendor.com/orders"


def test_enforce_raises_when_denied() -> None:
    guard = _build_guard()
    request = _build_request(with_verified_label=False)

    with pytest.raises(AuthorizationDeniedError):
        guard.enforce(lambda: "should-not-run", request)


def test_authorize_denies_when_global_delegation_depth_exceeded() -> None:
    rules = (
        PolicyRule(
            name="allow-checkout",
            effect=PolicyEffect.ALLOW,
            principals=("agent:*",),
            actions=("http.*",),
            resources=("https://api.vendor.com/*",),
        ),
    )
    guard = ActionGuard(
        policy_engine=PolicyEngine(rules=rules, global_max_delegation_depth=0),
        mandate_signer=LocalMandateSigner(secret_key="dev-secret", ttl_seconds=120),
        proof_ledger=InMemoryProofLedger(),
    )
    root_request = _build_request(with_verified_label=True)
    root = guard.authorize(root_request)
    assert root.allowed is True
    assert root.mandate is not None

    child = guard.authorize(_build_request(with_verified_label=True), parent_mandate=root.mandate)
    assert child.allowed is False
    assert child.reason == AuthorizationReason.MAX_DELEGATION_DEPTH_EXCEEDED


def test_authorize_per_rule_depth_cap_overrides_higher_global() -> None:
    rules = (
        PolicyRule(
            name="allow-checkout",
            effect=PolicyEffect.ALLOW,
            principals=("agent:*",),
            actions=("http.*",),
            resources=("https://api.vendor.com/*",),
            max_delegation_depth=1,
        ),
    )
    guard = ActionGuard(
        policy_engine=PolicyEngine(rules=rules, global_max_delegation_depth=5),
        mandate_signer=LocalMandateSigner(secret_key="dev-secret", ttl_seconds=120),
        proof_ledger=InMemoryProofLedger(),
    )
    root = guard.authorize(_build_request(with_verified_label=True))
    assert root.allowed is True
    assert root.mandate is not None

    child = guard.authorize(_build_request(with_verified_label=True), parent_mandate=root.mandate)
    assert child.allowed is True
    assert child.mandate is not None

    grandchild = guard.authorize(
        _build_request(with_verified_label=True),
        parent_mandate=child.mandate,
    )
    assert grandchild.allowed is False
    assert grandchild.reason == AuthorizationReason.MAX_DELEGATION_DEPTH_EXCEEDED
