from __future__ import annotations

from predicate_authority import ActionGuard, InMemoryProofLedger, LocalMandateSigner, PolicyEngine
from predicate_authority.integrations import (
    SdkAssertionRecord,
    SdkStepEvidence,
    authorize_sdk_step,
    to_action_request,
)
from predicate_contracts import AuthorizationReason, PolicyEffect, PolicyRule


def _guard() -> ActionGuard:
    return ActionGuard(
        policy_engine=PolicyEngine(
            rules=(
                PolicyRule(
                    name="allow-browser-action-with-label",
                    effect=PolicyEffect.ALLOW,
                    principals=("agent:web",),
                    actions=("browser.click",),
                    resources=("https://example.com/*",),
                    required_labels=("postcondition.exists:#receipt",),
                ),
            )
        ),
        mandate_signer=LocalMandateSigner(secret_key="test-secret"),
        proof_ledger=InMemoryProofLedger(),
    )


def test_to_action_request_maps_assertions_to_verification_signals() -> None:
    step = SdkStepEvidence(
        principal_id="agent:web",
        action="browser.click",
        resource="https://example.com/checkout",
        intent="click pay",
        state_hash="hash-a",
        assertions=(
            SdkAssertionRecord(label="postcondition.exists:#receipt", passed=True),
            SdkAssertionRecord(label="postcondition.url_contains:/receipt", passed=False),
        ),
    )
    request = to_action_request(step)

    assert request.principal.principal_id == "agent:web"
    assert request.state_evidence.state_hash == "hash-a"
    assert len(request.verification_evidence.signals) == 2
    assert request.verification_evidence.is_label_passed("postcondition.exists:#receipt") is True


def test_authorize_sdk_step_uses_guard_and_returns_decision() -> None:
    guard = _guard()
    step = SdkStepEvidence(
        principal_id="agent:web",
        action="browser.click",
        resource="https://example.com/checkout",
        intent="click pay",
        state_hash="hash-a",
        assertions=(SdkAssertionRecord(label="postcondition.exists:#receipt", passed=True),),
    )

    result = authorize_sdk_step(guard, step)

    assert result.decision.allowed is True
    assert result.decision.reason == AuthorizationReason.ALLOWED
    assert result.decision.mandate is not None
