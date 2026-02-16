from __future__ import annotations

from dataclasses import dataclass

from predicate_authority.guard import ActionGuard
from predicate_contracts import (
    ActionRequest,
    ActionSpec,
    AuthorizationDecision,
    PrincipalRef,
    StateEvidence,
    VerificationEvidence,
    VerificationSignal,
    VerificationStatus,
)


@dataclass(frozen=True)
class SdkAssertionRecord:
    """Typed view of one sdk-python assertion result."""

    label: str
    passed: bool
    required: bool = True
    reason: str | None = None


@dataclass(frozen=True)
class SdkStepEvidence:
    """Runtime evidence needed by authority before a sensitive action."""

    principal_id: str
    action: str
    resource: str
    intent: str
    state_hash: str
    state_source: str = "sdk-python"
    assertions: tuple[SdkAssertionRecord, ...] = ()
    tenant_id: str | None = None
    session_id: str | None = None


def to_action_request(step: SdkStepEvidence) -> ActionRequest:
    verification_signals = tuple(
        VerificationSignal(
            label=assertion.label,
            status=VerificationStatus.PASSED if assertion.passed else VerificationStatus.FAILED,
            required=assertion.required,
            reason=assertion.reason,
        )
        for assertion in step.assertions
    )
    return ActionRequest(
        principal=PrincipalRef(
            principal_id=step.principal_id,
            tenant_id=step.tenant_id,
            session_id=step.session_id,
        ),
        action_spec=ActionSpec(
            action=step.action,
            resource=step.resource,
            intent=step.intent,
        ),
        state_evidence=StateEvidence(
            source=step.state_source,
            state_hash=step.state_hash,
        ),
        verification_evidence=VerificationEvidence(signals=verification_signals),
    )


@dataclass(frozen=True)
class SdkPreActionAuthResult:
    request: ActionRequest
    decision: AuthorizationDecision


def authorize_sdk_step(guard: ActionGuard, step: SdkStepEvidence) -> SdkPreActionAuthResult:
    request = to_action_request(step)
    decision = guard.authorize(request)
    return SdkPreActionAuthResult(request=request, decision=decision)
