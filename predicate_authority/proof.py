from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock

from predicate_contracts import (
    ActionRequest,
    AuthorizationDecision,
    AuthorizationReason,
    ProofEvent,
    TraceEmitter,
)


@dataclass(frozen=True)
class DecisionStats:
    total: int
    allowed: int
    denied: int
    deny_no_matching_policy: int
    deny_explicit_deny: int
    deny_missing_required_verification: int
    deny_max_delegation_depth: int
    deny_invalid_mandate: int
    deny_rate_limit_exceeded: int


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

    def decision_stats(self) -> DecisionStats:
        with self._lock:
            events = tuple(self.events)
        allowed = 0
        denied = 0
        deny_no_matching_policy = 0
        deny_explicit_deny = 0
        deny_missing_required_verification = 0
        deny_max_delegation_depth = 0
        deny_invalid_mandate = 0
        deny_rate_limit_exceeded = 0
        for event in events:
            if event.allowed:
                allowed += 1
                continue
            denied += 1
            if event.reason == AuthorizationReason.NO_MATCHING_POLICY:
                deny_no_matching_policy += 1
            elif event.reason == AuthorizationReason.EXPLICIT_DENY:
                deny_explicit_deny += 1
            elif event.reason == AuthorizationReason.MISSING_REQUIRED_VERIFICATION:
                deny_missing_required_verification += 1
            elif event.reason == AuthorizationReason.MAX_DELEGATION_DEPTH_EXCEEDED:
                deny_max_delegation_depth += 1
            elif event.reason == AuthorizationReason.INVALID_MANDATE:
                deny_invalid_mandate += 1
            elif event.reason == AuthorizationReason.RATE_LIMIT_EXCEEDED:
                deny_rate_limit_exceeded += 1
        return DecisionStats(
            total=len(events),
            allowed=allowed,
            denied=denied,
            deny_no_matching_policy=deny_no_matching_policy,
            deny_explicit_deny=deny_explicit_deny,
            deny_missing_required_verification=deny_missing_required_verification,
            deny_max_delegation_depth=deny_max_delegation_depth,
            deny_invalid_mandate=deny_invalid_mandate,
            deny_rate_limit_exceeded=deny_rate_limit_exceeded,
        )
