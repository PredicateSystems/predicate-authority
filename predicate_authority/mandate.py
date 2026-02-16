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

    def issue(self, request: ActionRequest) -> SignedMandate:
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

        claims = MandateClaims(
            mandate_id=mandate_id,
            principal_id=request.principal.principal_id,
            action=request.action_spec.action,
            resource=request.action_spec.resource,
            intent_hash=intent_hash,
            state_hash=request.state_evidence.state_hash,
            issued_at_epoch_s=issued_at,
            expires_at_epoch_s=expires_at,
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
        return SignedMandate(token=token, claims=claims, signature=encoded_signature)

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
    def _base64url_encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _base64url_decode(value: str) -> bytes:
        padding = "=" * ((4 - len(value) % 4) % 4)
        return base64.urlsafe_b64decode(value + padding)
