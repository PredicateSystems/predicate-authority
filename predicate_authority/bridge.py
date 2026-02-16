from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

from predicate_contracts import PrincipalRef, StateEvidence


@dataclass(frozen=True)
class TokenExchangeResult:
    access_token: str
    expires_at_epoch_s: int
    token_type: str = "Bearer"


class IdentityBridge:
    """Local placeholder bridge for Phase 1.

    This keeps an explicit interface so Phase 2 can swap in a real OIDC/Entra bridge.
    """

    def __init__(self, token_ttl_seconds: int = 300) -> None:
        self._token_ttl_seconds = token_ttl_seconds

    def exchange_token(
        self, subject: PrincipalRef, state_evidence: StateEvidence
    ) -> TokenExchangeResult:
        expires_at = int(time.time()) + self._token_ttl_seconds
        token_seed = f"{subject.principal_id}|{state_evidence.state_hash}|{expires_at}"
        token_hash = hashlib.sha256(token_seed.encode("utf-8")).hexdigest()
        return TokenExchangeResult(
            access_token=f"local.{token_hash}", expires_at_epoch_s=expires_at
        )
