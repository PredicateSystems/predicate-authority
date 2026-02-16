from __future__ import annotations

from typing import Protocol

from predicate_contracts.models import ProofEvent, StateEvidence, VerificationEvidence


class StateEvidenceProvider(Protocol):
    def get_state_evidence(self) -> StateEvidence: ...


class VerificationEvidenceProvider(Protocol):
    def get_verification_evidence(self) -> VerificationEvidence: ...


class TraceEmitter(Protocol):
    def emit(self, event: ProofEvent) -> None: ...
