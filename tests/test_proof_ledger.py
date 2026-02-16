from __future__ import annotations

from dataclasses import dataclass, field

from predicate_authority import InMemoryProofLedger
from predicate_contracts import (
    ActionRequest,
    ActionSpec,
    AuthorizationDecision,
    AuthorizationReason,
    PrincipalRef,
    ProofEvent,
    StateEvidence,
    TraceEmitter,
    VerificationEvidence,
)


@dataclass
class RecordingEmitter(TraceEmitter):
    events: list[ProofEvent] = field(default_factory=list)

    def emit(self, event: ProofEvent) -> None:
        self.events.append(event)


def test_proof_ledger_records_and_emits() -> None:
    emitter = RecordingEmitter()
    ledger = InMemoryProofLedger(trace_emitter=emitter)

    request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:ops"),
        action_spec=ActionSpec(
            action="infra.apply", resource="terraform://workspace/prod", intent="apply"
        ),
        state_evidence=StateEvidence(source="infra", state_hash="hash-infra-1"),
        verification_evidence=VerificationEvidence(),
    )
    decision = AuthorizationDecision(allowed=False, reason=AuthorizationReason.EXPLICIT_DENY)

    event = ledger.record(decision, request)

    assert event.allowed is False
    assert event.reason == AuthorizationReason.EXPLICIT_DENY
    assert len(ledger.events) == 1
    assert len(emitter.events) == 1
