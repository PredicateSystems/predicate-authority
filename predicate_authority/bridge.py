from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit

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
class OktaBridgeConfig:
    issuer: str
    client_id: str
    audience: str
    token_ttl_seconds: int = 300
    required_claims: tuple[str, ...] = ("sub",)
    allowed_signing_algs: tuple[str, ...] = ("RS256",)
    clock_skew_leeway_seconds: int = 30
    tenant_claim: str = "tenant_id"
    scope_claim: str = "scope"
    role_claim: str = "groups"
    allowed_tenants: tuple[str, ...] = ()
    required_scopes: tuple[str, ...] = ()
    required_roles: tuple[str, ...] = ()
    enable_jwks_validation: bool = False
    jwks_url: str | None = None
    discovery_url: str | None = None
    jwks_cache_ttl_seconds: int = 300
    jwks_timeout_s: float = 1.0
    jwks_max_retries: int = 1
    jwks_backoff_initial_s: float = 0.1


@dataclass(frozen=True)
class OktaTokenClaims:
    issuer: str
    subject: str
    audience: tuple[str, ...]
    claims: dict[str, object]


class TokenValidationError(RuntimeError):
    pass


@dataclass(frozen=True)
class _JwksCacheState:
    expires_at_epoch_s: int
    keys_by_kid: dict[str, dict[str, object]]


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
    """Microsoft Entra adapter built on generic OIDC behavior.

    Phase 2 keeps this as a deterministic local stand-in for real IdP token exchange.
    """

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


class OktaIdentityBridge(OIDCIdentityBridge):
    """Okta adapter built on generic OIDC behavior.

    Phase 2 keeps this as a deterministic local stand-in for real IdP token exchange.
    """

    def __init__(self, config: OktaBridgeConfig) -> None:
        self._okta_config = config
        self._jwks_cache: _JwksCacheState | None = None
        if (
            config.enable_jwks_validation
            and config.jwks_url is None
            and config.discovery_url is None
        ):
            raise ValueError(
                "Okta JWKS validation is enabled but no jwks_url/discovery_url configured."
            )
        oidc_config = OIDCBridgeConfig(
            issuer=config.issuer,
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
            provider=IdentityProviderType.OKTA,
        )

    def validate_token_claims(self, token: str, now_epoch_s: int | None = None) -> OktaTokenClaims:
        header, payload = _decode_jwt_parts(token)
        alg = header.get("alg")
        if not isinstance(alg, str) or alg.strip() == "":
            raise TokenValidationError("Token header missing required algorithm: alg")
        if alg.lower() == "none":
            raise TokenValidationError("Token algorithm 'none' is not allowed")
        if alg not in self._okta_config.allowed_signing_algs:
            raise TokenValidationError("Token algorithm is not in Okta allowlist")
        self._validate_jwks_kid(header=header, now_epoch_s=now_epoch_s)

        issuer = payload.get("iss")
        if not isinstance(issuer, str) or issuer.strip() == "":
            raise TokenValidationError("Token missing required issuer claim: iss")
        if issuer != self._okta_config.issuer:
            raise TokenValidationError("Token issuer mismatch for configured Okta issuer")

        audience_raw = payload.get("aud")
        audiences = _normalize_audience(audience_raw)
        if self._okta_config.audience not in audiences:
            raise TokenValidationError("Token audience mismatch for configured Okta audience")

        for claim_name in self._okta_config.required_claims:
            if claim_name not in payload:
                raise TokenValidationError(f"Token missing required claim: {claim_name}")
            claim_value = payload.get(claim_name)
            if isinstance(claim_value, str) and claim_value.strip() == "":
                raise TokenValidationError(f"Token claim is empty: {claim_name}")
            if claim_value is None:
                raise TokenValidationError(f"Token claim is null: {claim_name}")

        subject = payload.get("sub")
        if not isinstance(subject, str) or subject.strip() == "":
            raise TokenValidationError("Token missing required subject claim: sub")
        self._validate_temporal_claims(payload=payload, now_epoch_s=now_epoch_s)
        self._validate_tenant_scope_role_guards(payload=payload)
        return OktaTokenClaims(
            issuer=issuer,
            subject=subject,
            audience=audiences,
            claims=payload,
        )

    def _validate_temporal_claims(
        self, payload: dict[str, object], now_epoch_s: int | None
    ) -> None:
        now_value = int(time.time()) if now_epoch_s is None else int(now_epoch_s)
        leeway = max(0, int(self._okta_config.clock_skew_leeway_seconds))

        exp = _required_int_claim(payload=payload, claim_name="exp")
        iat = _required_int_claim(payload=payload, claim_name="iat")

        nbf_raw = payload.get("nbf")
        nbf = _optional_int_claim(claim_name="nbf", claim_value=nbf_raw)

        if exp < now_value - leeway:
            raise TokenValidationError("Token is expired (exp outside allowed leeway)")
        if nbf is not None and nbf > now_value + leeway:
            raise TokenValidationError("Token not yet valid (nbf outside allowed leeway)")
        if iat > now_value + leeway:
            raise TokenValidationError("Token issued-at time is in the future beyond leeway")

    def _validate_tenant_scope_role_guards(self, payload: dict[str, object]) -> None:
        tenant_claim_name = self._okta_config.tenant_claim
        tenant_value_raw = payload.get(tenant_claim_name)
        tenant_value = tenant_value_raw if isinstance(tenant_value_raw, str) else None
        if len(self._okta_config.allowed_tenants) > 0:
            if tenant_value is None or tenant_value.strip() == "":
                raise TokenValidationError(
                    f"Token missing tenant claim required for allow-list: {tenant_claim_name}"
                )
            if tenant_value not in self._okta_config.allowed_tenants:
                raise TokenValidationError("Token tenant is not in configured allow-list")

        scope_values = _normalize_string_collection(payload.get(self._okta_config.scope_claim))
        for required_scope in self._okta_config.required_scopes:
            if required_scope not in scope_values:
                raise TokenValidationError("Token missing required scope")

        role_values = _normalize_string_collection(payload.get(self._okta_config.role_claim))
        for required_role in self._okta_config.required_roles:
            if required_role not in role_values:
                raise TokenValidationError("Token missing required role/group")

    def _validate_jwks_kid(self, header: dict[str, object], now_epoch_s: int | None) -> None:
        if not self._okta_config.enable_jwks_validation:
            return
        kid = header.get("kid")
        if not isinstance(kid, str) or kid.strip() == "":
            raise TokenValidationError("Token header missing required key id: kid")
        now_value = int(time.time()) if now_epoch_s is None else int(now_epoch_s)
        key = self._get_key_for_kid(kid=kid, now_epoch_s=now_value)
        if key is None:
            raise TokenValidationError(f"No JWKS key found for kid: {kid}")

    def _get_key_for_kid(self, kid: str, now_epoch_s: int) -> dict[str, object] | None:
        cache = self._jwks_cache
        cache_fresh = cache is not None and now_epoch_s <= cache.expires_at_epoch_s
        if cache_fresh and kid in cache.keys_by_kid:
            return cache.keys_by_kid[kid]

        fetched = self._fetch_jwks_keys_with_retry()
        self._jwks_cache = _JwksCacheState(
            expires_at_epoch_s=now_epoch_s + max(1, int(self._okta_config.jwks_cache_ttl_seconds)),
            keys_by_kid=fetched,
        )
        return fetched.get(kid)

    def _fetch_jwks_keys_with_retry(self) -> dict[str, dict[str, object]]:
        attempts = max(0, int(self._okta_config.jwks_max_retries)) + 1
        last_exc: Exception | None = None
        for attempt in range(attempts):
            try:
                return self._fetch_jwks_keys_once()
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt == attempts - 1:
                    break
                sleep_s = float(self._okta_config.jwks_backoff_initial_s) * (2**attempt)
                time.sleep(max(0.0, sleep_s))
        raise TokenValidationError(
            "JWKS fetch failed after retries "
            f"(attempts={attempts}, timeout_s={self._okta_config.jwks_timeout_s})"
        ) from last_exc

    def _fetch_jwks_keys_once(self) -> dict[str, dict[str, object]]:
        jwks_url = self._resolve_jwks_url()
        payload = _http_get_json(url=jwks_url, timeout_s=float(self._okta_config.jwks_timeout_s))
        keys_raw = payload.get("keys")
        if not isinstance(keys_raw, list):
            raise TokenValidationError("JWKS response missing keys array")
        keys_by_kid: dict[str, dict[str, object]] = {}
        for item in keys_raw:
            if not isinstance(item, dict):
                continue
            kid = item.get("kid")
            if isinstance(kid, str) and kid != "":
                keys_by_kid[kid] = item
        if len(keys_by_kid) == 0:
            raise TokenValidationError("JWKS response contains no usable kid entries")
        return keys_by_kid

    def _resolve_jwks_url(self) -> str:
        if self._okta_config.jwks_url is not None and self._okta_config.jwks_url.strip() != "":
            return self._okta_config.jwks_url
        discovery_url = self._okta_config.discovery_url
        if discovery_url is None or discovery_url.strip() == "":
            raise TokenValidationError("No JWKS endpoint configured")
        payload = _http_get_json(
            url=discovery_url, timeout_s=float(self._okta_config.jwks_timeout_s)
        )
        jwks_uri = payload.get("jwks_uri")
        if not isinstance(jwks_uri, str) or jwks_uri.strip() == "":
            raise TokenValidationError("OIDC discovery response missing jwks_uri")
        return jwks_uri


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


def _decode_jwt_payload(token: str) -> dict[str, object]:
    _, payload = _decode_jwt_parts(token)
    return payload


def _decode_jwt_parts(token: str) -> tuple[dict[str, object], dict[str, object]]:
    segments = token.split(".")
    if len(segments) != 3:
        raise TokenValidationError("Token must be a 3-segment JWT")
    header = _decode_jwt_segment(segments[0])
    payload_segment = segments[1]
    payload = _decode_jwt_segment(payload_segment)
    return header, payload


def _decode_jwt_segment(segment: str) -> dict[str, object]:
    padding = "=" * (-len(segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode((segment + padding).encode("utf-8"))
        loaded = json.loads(decoded.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise TokenValidationError("Token segment is not valid base64url JSON") from exc
    if not isinstance(loaded, dict):
        raise TokenValidationError("Token segment must be a JSON object")
    return loaded


def _normalize_audience(audience_raw: object) -> tuple[str, ...]:
    if isinstance(audience_raw, str):
        if audience_raw.strip() == "":
            return ()
        return (audience_raw,)
    if isinstance(audience_raw, list):
        normalized = tuple(item for item in audience_raw if isinstance(item, str) and item != "")
        return normalized
    return ()


def _required_int_claim(payload: dict[str, object], claim_name: str) -> int:
    value = payload.get(claim_name)
    if not isinstance(value, int):
        raise TokenValidationError(f"Token missing required numeric claim: {claim_name}")
    return int(value)


def _optional_int_claim(claim_name: str, claim_value: object) -> int | None:
    if claim_value is None:
        return None
    if not isinstance(claim_value, int):
        raise TokenValidationError(f"Token claim must be numeric when present: {claim_name}")
    return int(claim_value)


def _normalize_string_collection(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        if value.strip() == "":
            return ()
        return tuple(item for item in value.split() if item != "")
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str) and item != "")
    return ()


def _http_get_json(url: str, timeout_s: float) -> dict[str, object]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.netloc == "":
        raise TokenValidationError("JWKS URL must be a valid http/https URL")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    if parsed.scheme == "https":
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            parsed.netloc, timeout=timeout_s
        )
    else:
        connection = http.client.HTTPConnection(parsed.netloc, timeout=timeout_s)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read().decode("utf-8")
    finally:
        connection.close()
    if response.status >= 400:
        raise TokenValidationError(f"JWKS HTTP error: {response.status}")
    try:
        loaded = json.loads(body)
    except json.JSONDecodeError as exc:
        raise TokenValidationError("JWKS response is not valid JSON") from exc
    if not isinstance(loaded, dict):
        raise TokenValidationError("JWKS response must be a JSON object")
    return loaded
