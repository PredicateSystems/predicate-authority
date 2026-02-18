from __future__ import annotations

import os
from dataclasses import dataclass

from predicate_authority.guard import ActionGuard
from predicate_authority.mandate import LocalMandateSigner
from predicate_authority.policy import PolicyEngine
from predicate_authority.policy_source import PolicyFileSource
from predicate_authority.proof import InMemoryProofLedger
from predicate_authority.revocation import LocalRevocationCache
from predicate_contracts import (
    ActionRequest,
    AuthorizationDecision,
    AuthorizationReason,
    SignedMandate,
)


@dataclass(frozen=True)
class LocalAuthorizationContext:
    client: AuthorityClient
    policy_file: str


class AuthorityClient:
    """Lightweight local authority client for pre-action authorization flows."""

    def __init__(
        self,
        action_guard: ActionGuard,
        mandate_signer: LocalMandateSigner,
        revocation_cache: LocalRevocationCache | None = None,
    ) -> None:
        self._action_guard = action_guard
        self._mandate_signer = mandate_signer
        self._revocation_cache = revocation_cache or LocalRevocationCache()

    @classmethod
    def from_policy_file(
        cls,
        policy_file: str,
        secret_key: str,
        ttl_seconds: int = 300,
    ) -> LocalAuthorizationContext:
        rules, global_max_delegation_depth = PolicyFileSource(policy_file).load_policy()
        policy_engine = PolicyEngine(
            rules=rules,
            global_max_delegation_depth=global_max_delegation_depth,
        )
        proof_ledger = InMemoryProofLedger()
        mandate_signer = LocalMandateSigner(secret_key=secret_key, ttl_seconds=ttl_seconds)
        action_guard = ActionGuard(
            policy_engine=policy_engine,
            mandate_signer=mandate_signer,
            proof_ledger=proof_ledger,
        )
        return LocalAuthorizationContext(
            client=cls(
                action_guard=action_guard,
                mandate_signer=mandate_signer,
                revocation_cache=LocalRevocationCache(),
            ),
            policy_file=policy_file,
        )

    @classmethod
    def from_env(cls) -> LocalAuthorizationContext:
        policy_file = os.getenv("PREDICATE_AUTHORITY_POLICY_FILE")
        secret_key = os.getenv("PREDICATE_AUTHORITY_SIGNING_KEY")
        ttl_seconds_raw = os.getenv("PREDICATE_AUTHORITY_MANDATE_TTL_SECONDS", "300")
        if policy_file is None or policy_file.strip() == "":
            raise RuntimeError("PREDICATE_AUTHORITY_POLICY_FILE is required.")
        if secret_key is None or secret_key.strip() == "":
            raise RuntimeError("PREDICATE_AUTHORITY_SIGNING_KEY is required.")
        try:
            ttl_seconds = int(ttl_seconds_raw)
        except ValueError as exc:
            raise RuntimeError(
                "PREDICATE_AUTHORITY_MANDATE_TTL_SECONDS must be an integer."
            ) from exc
        return cls.from_policy_file(
            policy_file=policy_file,
            secret_key=secret_key,
            ttl_seconds=ttl_seconds,
        )

    def authorize(
        self,
        request: ActionRequest,
        parent_mandate: SignedMandate | None = None,
    ) -> AuthorizationDecision:
        if self._revocation_cache.is_request_revoked(request):
            return AuthorizationDecision(
                allowed=False,
                reason=AuthorizationReason.INVALID_MANDATE,
                violated_rule="revocation_cache",
            )
        if parent_mandate is not None and self._revocation_cache.is_mandate_revoked(parent_mandate):
            return AuthorizationDecision(
                allowed=False,
                reason=AuthorizationReason.INVALID_MANDATE,
                violated_rule="revocation_cache",
            )
        decision = self._action_guard.authorize(request, parent_mandate=parent_mandate)
        if (
            decision.allowed
            and decision.mandate is not None
            and self._revocation_cache.is_mandate_revoked(decision.mandate)
        ):
            return AuthorizationDecision(
                allowed=False,
                reason=AuthorizationReason.INVALID_MANDATE,
                violated_rule="revocation_cache",
            )
        return decision

    def verify_token(self, token: str) -> SignedMandate | None:
        mandate = self._mandate_signer.verify(token)
        if mandate is None:
            return None
        if self._revocation_cache.is_mandate_revoked(mandate):
            return None
        return mandate

    def verify_delegation_chain(
        self,
        token: str,
        parent_token: str | None = None,
    ) -> bool:
        mandate = self.verify_token(token)
        if mandate is None:
            return False
        parent_mandate = self.verify_token(parent_token) if parent_token is not None else None
        if parent_token is not None and parent_mandate is None:
            return False
        return self._mandate_signer.verify_delegation(
            mandate=mandate,
            parent_mandate=parent_mandate,
        )

    def revoke_principal(self, principal_id: str) -> None:
        self._revocation_cache.revoke_principal(principal_id)

    def revoke_mandate(self, mandate_id: str) -> None:
        self._revocation_cache.revoke_mandate_id(mandate_id)
