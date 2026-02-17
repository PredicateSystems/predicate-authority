from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from predicate_authority.bridge import TokenExchangeResult
from predicate_authority.guard import ActionGuard
from predicate_authority.policy import PolicyEngine
from predicate_authority.policy_source import PolicyFileSource
from predicate_authority.proof import InMemoryProofLedger
from predicate_authority.revocation import LocalRevocationCache
from predicate_authority.sidecar_store import CredentialRecord, LocalCredentialStore
from predicate_contracts import (
    ActionRequest,
    AuthorizationDecision,
    AuthorizationReason,
    PrincipalRef,
    StateEvidence,
)


class AuthorityMode(str, Enum):
    LOCAL_ONLY = "local_only"
    CLOUD_CONNECTED = "cloud_connected"


@dataclass(frozen=True)
class SidecarConfig:
    mode: AuthorityMode = AuthorityMode.LOCAL_ONLY
    policy_file_path: str | None = None


@dataclass(frozen=True)
class SidecarStatus:
    mode: AuthorityMode
    policy_hot_reload_enabled: bool
    revoked_principal_count: int
    revoked_intent_count: int
    revoked_mandate_count: int
    proof_event_count: int


class SidecarError(RuntimeError):
    pass


class ExchangeTokenBridge(Protocol):
    def exchange_token(
        self, subject: PrincipalRef, state_evidence: StateEvidence
    ) -> TokenExchangeResult: ...


class RefreshTokenBridge(ExchangeTokenBridge, Protocol):
    def refresh_token(
        self, refresh_token: str, subject: PrincipalRef, state_evidence: StateEvidence
    ) -> TokenExchangeResult: ...


class PredicateAuthoritySidecar:
    def __init__(
        self,
        config: SidecarConfig,
        action_guard: ActionGuard,
        proof_ledger: InMemoryProofLedger,
        identity_bridge: ExchangeTokenBridge,
        credential_store: LocalCredentialStore,
        revocation_cache: LocalRevocationCache,
        policy_engine: PolicyEngine,
    ) -> None:
        self._config = config
        self._action_guard = action_guard
        self._proof_ledger = proof_ledger
        self._identity_bridge = identity_bridge
        self._credential_store = credential_store
        self._revocation_cache = revocation_cache
        self._policy_engine = policy_engine
        self._policy_source = (
            PolicyFileSource(config.policy_file_path)
            if config.policy_file_path is not None
            else None
        )

    def issue_mandate(self, request: ActionRequest) -> AuthorizationDecision:
        if self._revocation_cache.is_request_revoked(request):
            decision = AuthorizationDecision(
                allowed=False,
                reason=AuthorizationReason.INVALID_MANDATE,
                violated_rule="revocation_cache",
            )
            self._proof_ledger.record(decision, request)
            return decision
        decision = self._action_guard.authorize(request)
        if decision.allowed and decision.mandate is not None:
            if self._revocation_cache.is_mandate_revoked(decision.mandate):
                revoked_decision = AuthorizationDecision(
                    allowed=False,
                    reason=AuthorizationReason.INVALID_MANDATE,
                    violated_rule="revocation_cache",
                )
                self._proof_ledger.record(revoked_decision, request)
                return revoked_decision
        return decision

    def store_refresh_token(
        self, principal_id: str, refresh_token: str, expires_at_epoch_s: int
    ) -> None:
        self._credential_store.save(
            CredentialRecord(
                principal_id=principal_id,
                refresh_token=refresh_token,
                expires_at_epoch_s=expires_at_epoch_s,
            )
        )

    def exchange_access_token(
        self, subject: PrincipalRef, state_evidence: StateEvidence
    ) -> TokenExchangeResult:
        if self._config.mode == AuthorityMode.LOCAL_ONLY:
            return self._identity_bridge.exchange_token(subject, state_evidence)

        record = self._credential_store.get(subject.principal_id)
        if record is None:
            raise SidecarError("Missing refresh token for connected mode principal.")

        if hasattr(self._identity_bridge, "refresh_token"):
            refreshable_bridge = cast(RefreshTokenBridge, self._identity_bridge)
            return refreshable_bridge.refresh_token(record.refresh_token, subject, state_evidence)
        raise SidecarError("Connected mode requires an identity bridge with refresh_token support.")

    def revoke_by_invariant(self, principal_id: str) -> None:
        self._revocation_cache.revoke_principal(principal_id)

    def revoke_intent_hash(self, intent_hash: str) -> None:
        self._revocation_cache.revoke_intent_hash(intent_hash)

    def hot_reload_policy(self) -> bool:
        if self._policy_source is None:
            return False
        result = self._policy_source.reload_if_changed()
        if result.changed:
            self._policy_engine.replace_rules(result.rules)
            return True
        return False

    def status(self) -> SidecarStatus:
        return SidecarStatus(
            mode=self._config.mode,
            policy_hot_reload_enabled=self._policy_source is not None,
            revoked_principal_count=len(self._revocation_cache.revoked_principal_ids),
            revoked_intent_count=len(self._revocation_cache.revoked_intent_hashes),
            revoked_mandate_count=len(self._revocation_cache.revoked_mandate_ids),
            proof_event_count=len(self._proof_ledger.events),
        )
