from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from predicate_contracts import PrincipalRef, StateEvidence


class IdentityProviderType(str, Enum):
    LOCAL = "local"
    LOCAL_IDP = "local_idp"
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


@dataclass(frozen=True)
class LocalIdPBridgeConfig:
    issuer: str = "http://localhost/predicate-local-idp"
    audience: str = "api://predicate-authority"
    signing_key: str = "predicate-local-idp-dev-key"
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


class LocalIdPBridge:
    """Local IdP emulator for dev/offline/air-gapped workflows."""

    def __init__(self, config: LocalIdPBridgeConfig) -> None:
        self._config = config

    def exchange_token(
        self, subject: PrincipalRef, state_evidence: StateEvidence
    ) -> TokenExchangeResult:
        expires_at = int(time.time()) + self._config.token_ttl_seconds
        token = self._mint_token(
            subject=subject,
            state_evidence=state_evidence,
            expires_at_epoch_s=expires_at,
            grant_kind="access",
            refresh_token=None,
        )
        return TokenExchangeResult(
            access_token=token,
            expires_at_epoch_s=expires_at,
            provider=IdentityProviderType.LOCAL_IDP,
        )

    def refresh_token(
        self, refresh_token: str, subject: PrincipalRef, state_evidence: StateEvidence
    ) -> TokenExchangeResult:
        expires_at = int(time.time()) + self._config.token_ttl_seconds
        token = self._mint_token(
            subject=subject,
            state_evidence=state_evidence,
            expires_at_epoch_s=expires_at,
            grant_kind="refresh_access",
            refresh_token=refresh_token,
        )
        return TokenExchangeResult(
            access_token=token,
            expires_at_epoch_s=expires_at,
            provider=IdentityProviderType.LOCAL_IDP,
        )

    def _mint_token(
        self,
        subject: PrincipalRef,
        state_evidence: StateEvidence,
        expires_at_epoch_s: int,
        grant_kind: str,
        refresh_token: str | None,
    ) -> str:
        header = {"alg": "HS256", "typ": "JWT", "kid": "predicate-local-idp-dev"}
        payload: dict[str, str | int | None] = {
            "iss": self._config.issuer,
            "aud": self._config.audience,
            "sub": subject.principal_id,
            "state_hash": state_evidence.state_hash,
            "state_source": state_evidence.source,
            "token_kind": grant_kind,
            "exp": expires_at_epoch_s,
            "iat": int(time.time()),
            "tenant_id": subject.tenant_id,
            "session_id": subject.session_id,
            "refresh_token_hash": (
                hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
                if refresh_token is not None
                else None
            ),
        }
        header_b64 = _b64url_json(header)
        payload_b64 = _b64url_json(payload)
        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = hmac.new(
            self._config.signing_key.encode("utf-8"), signing_input, hashlib.sha256
        ).digest()
        signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("utf-8")
        return f"{header_b64}.{payload_b64}.{signature_b64}"


def _b64url_json(value: Mapping[str, str | int | None]) -> str:
    encoded = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("utf-8")
