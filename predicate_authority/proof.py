from __future__ import annotations

import time
from dataclasses import dataclass, field

from predicate_contracts import ActionRequest, AuthorizationDecision, ProofEvent, TraceEmitter


@dataclass
class InMemoryProofLedger:
    trace_emitter: TraceEmitter | None = None
    events: list[ProofEvent] = field(default_factory=list)

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
        self.events.append(event)
        if self.trace_emitter is not None:
            self.trace_emitter.emit(event)
        return event
