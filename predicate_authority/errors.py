from __future__ import annotations

from predicate_contracts import AuthorizationDecision


class AuthorizationDeniedError(RuntimeError):
    def __init__(self, decision: AuthorizationDecision) -> None:
        self.decision = decision
        super().__init__(f"Authorization denied: {decision.reason.value}")
