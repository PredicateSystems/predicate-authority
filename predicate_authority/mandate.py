from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import asdict

from predicate_contracts import ActionRequest, MandateClaims, SignedMandate


class LocalMandateSigner:
    def __init__(self, secret_key: str, ttl_seconds: int = 300) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self._secret_key = secret_key.encode("utf-8")
        self._ttl_seconds = ttl_seconds

    def issue(
        self,
        request: ActionRequest,
        parent_mandate: SignedMandate | None = None,
    ) -> SignedMandate:
        issued_at = int(time.time())
        expires_at = issued_at + self._ttl_seconds
        intent_hash = hashlib.sha256(request.action_spec.intent.encode("utf-8")).hexdigest()
        mandate_id_seed = (
            f"{request.principal.principal_id}|"
            f"{request.action_spec.action}|"
            f"{request.action_spec.resource}|"
            f"{intent_hash}|"
            f"{request.state_evidence.state_hash}|"
            f"{issued_at}"
        )
        mandate_id = hashlib.sha256(mandate_id_seed.encode("utf-8")).hexdigest()[:24]
        delegated_by = parent_mandate.claims.principal_id if parent_mandate is not None else None
        delegation_depth = (
            parent_mandate.claims.delegation_depth + 1 if parent_mandate is not None else 0
        )
        delegation_chain_hash = self._compute_delegation_chain_hash(
            request=request,
            mandate_id=mandate_id,
            intent_hash=intent_hash,
            delegated_by=delegated_by,
            delegation_depth=delegation_depth,
            parent_mandate=parent_mandate,
        )

        claims = MandateClaims(
            mandate_id=mandate_id,
            principal_id=request.principal.principal_id,
            action=request.action_spec.action,
            resource=request.action_spec.resource,
            intent_hash=intent_hash,
            state_hash=request.state_evidence.state_hash,
            issued_at_epoch_s=issued_at,
            expires_at_epoch_s=expires_at,
            delegated_by=delegated_by,
            delegation_depth=delegation_depth,
            delegation_chain_hash=delegation_chain_hash,
        )
        token, signature = self._sign_claims(claims)
        return SignedMandate(token=token, claims=claims, signature=signature)

    def verify(self, token: str) -> SignedMandate | None:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        encoded_header, encoded_payload, encoded_signature = parts
        signing_input = f"{encoded_header}.{encoded_payload}".encode()
        expected_signature = self._hmac(signing_input)
        expected_signature_encoded = self._base64url_encode(expected_signature)
        if not hmac.compare_digest(expected_signature_encoded, encoded_signature):
            return None

        try:
            payload_json = self._base64url_decode(encoded_payload).decode("utf-8")
            payload = json.loads(payload_json)
            claims = MandateClaims(**payload)
        except (ValueError, TypeError, json.JSONDecodeError):
            return None

        now_epoch = int(time.time())
        if claims.expires_at_epoch_s < now_epoch:
            return None
        if claims.delegation_depth < 0:
            return None
        if claims.delegation_depth == 0 and claims.delegated_by is not None:
            return None
        if claims.delegation_depth > 0 and claims.delegated_by is None:
            return None
        if claims.delegation_chain_hash is None:
            return None
        return SignedMandate(token=token, claims=claims, signature=encoded_signature)

    def verify_delegation(
        self,
        mandate: SignedMandate,
        parent_mandate: SignedMandate | None = None,
    ) -> bool:
        claims = mandate.claims
        if claims.delegation_chain_hash is None:
            return False
        if parent_mandate is None:
            if claims.delegation_depth != 0 or claims.delegated_by is not None:
                return False
            expected_hash = self._compute_delegation_chain_hash_for_claims(
                claims=claims,
                parent_mandate=None,
            )
            return hmac.compare_digest(expected_hash, claims.delegation_chain_hash)

        parent_claims = parent_mandate.claims
        if claims.delegated_by != parent_claims.principal_id:
            return False
        if claims.delegation_depth != parent_claims.delegation_depth + 1:
            return False
        expected_hash = self._compute_delegation_chain_hash_for_claims(
            claims=claims,
            parent_mandate=parent_mandate,
        )
        return hmac.compare_digest(expected_hash, claims.delegation_chain_hash)

    def _sign_claims(self, claims: MandateClaims) -> tuple[str, str]:
        header_json = json.dumps(
            {"alg": "HS256", "typ": "JWT"}, separators=(",", ":"), sort_keys=True
        )
        payload_json = json.dumps(asdict(claims), separators=(",", ":"), sort_keys=True)

        encoded_header = self._base64url_encode(header_json.encode("utf-8"))
        encoded_payload = self._base64url_encode(payload_json.encode("utf-8"))
        signing_input = f"{encoded_header}.{encoded_payload}".encode()
        signature = self._base64url_encode(self._hmac(signing_input))
        token = f"{encoded_header}.{encoded_payload}.{signature}"
        return token, signature

    def _hmac(self, payload: bytes) -> bytes:
        return hmac.new(self._secret_key, payload, hashlib.sha256).digest()

    @staticmethod
    def _compute_delegation_chain_hash(
        request: ActionRequest,
        mandate_id: str,
        intent_hash: str,
        delegated_by: str | None,
        delegation_depth: int,
        parent_mandate: SignedMandate | None,
    ) -> str:
        parent_chain = (
            parent_mandate.claims.delegation_chain_hash if parent_mandate is not None else "root"
        )
        parent_mandate_id = (
            parent_mandate.claims.mandate_id if parent_mandate is not None else "none"
        )
        chain_seed = (
            f"{parent_chain}|"
            f"{parent_mandate_id}|"
            f"{delegated_by or 'none'}|"
            f"{delegation_depth}|"
            f"{mandate_id}|"
            f"{request.principal.principal_id}|"
            f"{request.action_spec.action}|"
            f"{request.action_spec.resource}|"
            f"{intent_hash}|"
            f"{request.state_evidence.state_hash}"
        )
        return hashlib.sha256(chain_seed.encode("utf-8")).hexdigest()

    @classmethod
    def _compute_delegation_chain_hash_for_claims(
        cls,
        claims: MandateClaims,
        parent_mandate: SignedMandate | None,
    ) -> str:
        parent_chain = (
            parent_mandate.claims.delegation_chain_hash if parent_mandate is not None else "root"
        )
        parent_mandate_id = (
            parent_mandate.claims.mandate_id if parent_mandate is not None else "none"
        )
        chain_seed = (
            f"{parent_chain}|"
            f"{parent_mandate_id}|"
            f"{claims.delegated_by or 'none'}|"
            f"{claims.delegation_depth}|"
            f"{claims.mandate_id}|"
            f"{claims.principal_id}|"
            f"{claims.action}|"
            f"{claims.resource}|"
            f"{claims.intent_hash}|"
            f"{claims.state_hash}"
        )
        return hashlib.sha256(chain_seed.encode("utf-8")).hexdigest()

    @staticmethod
    def _base64url_encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _base64url_decode(value: str) -> bytes:
        padding = "=" * ((4 - len(value) % 4) % 4)
        return base64.urlsafe_b64decode(value + padding)
