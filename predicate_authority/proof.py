from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock

from predicate_contracts import ActionRequest, AuthorizationDecision, ProofEvent, TraceEmitter


@dataclass
class InMemoryProofLedger:
    trace_emitter: TraceEmitter | None = None
    events: list[ProofEvent] = field(default_factory=list)
    _lock: Lock = field(default_factory=Lock)

    def record(self, decision: AuthorizationDecision, request: ActionRequest) -> ProofEvent:
        event = ProofEvent(
            event_type="authority.decision",
            principal_id=request.principal.principal_id,
            action=request.action_spec.action,
            resource=request.action_spec.resource,
            reason=decision.reason,
            allowed=decision.allowed,
            mandate_id=decision.mandate.claims.mandate_id if decision.mandate else None,
            emitted_at_epoch_s=int(time.time()),
        )
        with self._lock:
            self.events.append(event)
            trace_emitter = self.trace_emitter
        if trace_emitter is not None:
            trace_emitter.emit(event)
        return event

    def event_count(self) -> int:
        with self._lock:
            return len(self.events)
