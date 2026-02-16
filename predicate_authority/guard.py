from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

from predicate_authority.errors import AuthorizationDeniedError
from predicate_authority.mandate import LocalMandateSigner
from predicate_authority.policy import PolicyEngine
from predicate_authority.proof import InMemoryProofLedger
from predicate_contracts import (
    ActionRequest,
    AuthorizationDecision,
    AuthorizationReason,
    SignedMandate,
)

T = TypeVar("T")


@dataclass(frozen=True)
class ActionExecutionResult(Generic[T]):
    value: T
    decision: AuthorizationDecision
    mandate: SignedMandate


class ActionGuard:
    def __init__(
        self,
        policy_engine: PolicyEngine,
        mandate_signer: LocalMandateSigner,
        proof_ledger: InMemoryProofLedger,
    ) -> None:
        self._policy_engine = policy_engine
        self._mandate_signer = mandate_signer
        self._proof_ledger = proof_ledger

    def authorize(self, request: ActionRequest) -> AuthorizationDecision:
        evaluation = self._policy_engine.evaluate(request)
        if not evaluation.allowed:
            decision = AuthorizationDecision(
                allowed=False,
                reason=evaluation.reason,
                violated_rule=evaluation.matched_rule,
                missing_labels=evaluation.missing_labels,
            )
            self._proof_ledger.record(decision, request)
            return decision

        mandate = self._mandate_signer.issue(request)
        decision = AuthorizationDecision(
            allowed=True,
            reason=AuthorizationReason.ALLOWED,
            mandate=mandate,
            violated_rule=evaluation.matched_rule,
        )
        self._proof_ledger.record(decision, request)
        return decision

    def enforce(
        self, action_callable: Callable[[], T], request: ActionRequest
    ) -> ActionExecutionResult[T]:
        decision = self.authorize(request)
        if not decision.allowed or decision.mandate is None:
            raise AuthorizationDeniedError(decision)
        value = action_callable()
        return ActionExecutionResult(value=value, decision=decision, mandate=decision.mandate)
