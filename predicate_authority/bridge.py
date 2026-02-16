from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from enum import Enum

from predicate_contracts import PrincipalRef, StateEvidence


class IdentityProviderType(str, Enum):
    LOCAL = "local"
    OIDC = "oidc"
    ENTRA = "entra"
    OKTA = "okta"


@dataclass(frozen=True)
class TokenExchangeResult:
    access_token: str
    expires_at_epoch_s: int
    token_type: str = "Bearer"
    provider: IdentityProviderType = IdentityProviderType.LOCAL


@dataclass(frozen=True)
class OIDCBridgeConfig:
    issuer: str
    client_id: str
    audience: str
    token_ttl_seconds: int = 300


@dataclass(frozen=True)
class EntraBridgeConfig:
    tenant_id: str
    client_id: str
    audience: str
    token_ttl_seconds: int = 300


class IdentityBridge:
    """Local bridge implementation for development/local-only mode."""

    def __init__(self, token_ttl_seconds: int = 300) -> None:
        self._token_ttl_seconds = token_ttl_seconds

    def exchange_token(
        self, subject: PrincipalRef, state_evidence: StateEvidence
    ) -> TokenExchangeResult:
        expires_at = int(time.time()) + self._token_ttl_seconds
        token_seed = f"{subject.principal_id}|{state_evidence.state_hash}|{expires_at}"
        token_hash = hashlib.sha256(token_seed.encode("utf-8")).hexdigest()
        return TokenExchangeResult(
            access_token=f"local.{token_hash}",
            expires_at_epoch_s=expires_at,
            provider=IdentityProviderType.LOCAL,
        )


class OIDCIdentityBridge:
    """Generic OIDC bridge adapter.

    Phase 2 keeps this as a deterministic local stand-in for real IdP token exchange.
    """

    def __init__(self, config: OIDCBridgeConfig) -> None:
        self._config = config

    def exchange_token(
        self, subject: PrincipalRef, state_evidence: StateEvidence
    ) -> TokenExchangeResult:
        expires_at = int(time.time()) + self._config.token_ttl_seconds
        token_seed = (
            f"{self._config.issuer}|{self._config.client_id}|{self._config.audience}|"
            f"{subject.principal_id}|{state_evidence.state_hash}|{expires_at}"
        )
        token_hash = hashlib.sha256(token_seed.encode("utf-8")).hexdigest()
        return TokenExchangeResult(
            access_token=f"oidc.{token_hash}",
            expires_at_epoch_s=expires_at,
            provider=IdentityProviderType.OIDC,
        )

    def refresh_token(
        self, refresh_token: str, subject: PrincipalRef, state_evidence: StateEvidence
    ) -> TokenExchangeResult:
        expires_at = int(time.time()) + self._config.token_ttl_seconds
        token_seed = (
            f"{refresh_token}|{self._config.issuer}|{subject.principal_id}|"
            f"{state_evidence.state_hash}|{expires_at}"
        )
        token_hash = hashlib.sha256(token_seed.encode("utf-8")).hexdigest()
        return TokenExchangeResult(
            access_token=f"oidc-refresh.{token_hash}",
            expires_at_epoch_s=expires_at,
            provider=IdentityProviderType.OIDC,
        )


class EntraIdentityBridge(OIDCIdentityBridge):
    """Microsoft Entra adapter built on generic OIDC behavior."""

    def __init__(self, config: EntraBridgeConfig) -> None:
        oidc_config = OIDCBridgeConfig(
            issuer=f"https://login.microsoftonline.com/{config.tenant_id}/v2.0",
            client_id=config.client_id,
            audience=config.audience,
            token_ttl_seconds=config.token_ttl_seconds,
        )
        super().__init__(oidc_config)

    def exchange_token(
        self, subject: PrincipalRef, state_evidence: StateEvidence
    ) -> TokenExchangeResult:
        result = super().exchange_token(subject, state_evidence)
        return TokenExchangeResult(
            access_token=result.access_token,
            expires_at_epoch_s=result.expires_at_epoch_s,
            token_type=result.token_type,
            provider=IdentityProviderType.ENTRA,
        )
