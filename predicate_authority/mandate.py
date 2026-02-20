from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import asdict, dataclass
from typing import Any, Literal, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from predicate_contracts import ActionRequest, MandateClaims, SignedMandate


@dataclass(frozen=True)
class _SigningKeyMaterial:
    secret_key: bytes
    private_key: ec.EllipticCurvePrivateKey
    public_key: ec.EllipticCurvePublicKey


class LocalMandateSigner:
    def __init__(
        self,
        secret_key: str,
        ttl_seconds: int = 300,
        signing_alg: Literal["ES256", "HS256"] = "ES256",
        allow_legacy_hs256_verify: bool = True,
        token_issuer: str | None = None,
        token_audience: str | None = None,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        if signing_alg not in {"ES256", "HS256"}:
            raise ValueError("signing_alg must be one of: ES256, HS256")
        self._ttl_seconds = ttl_seconds
        self._signing_alg = signing_alg
        self._allow_legacy_hs256_verify = allow_legacy_hs256_verify
        self._token_issuer = token_issuer if token_issuer is not None else "predicate-authorityd"
        self._token_audience = (
            token_audience if token_audience is not None else "predicate-authority"
        )
        initial_kid = self._key_id_for_secret(secret_key)
        initial_material = self._build_key_material(secret_key)
        self._active_kid = initial_kid
        self._next_kid: str | None = None
        self._verification_keys: dict[str, _SigningKeyMaterial] = {initial_kid: initial_material}

    def key_lifecycle_status(self) -> dict[str, object]:
        return {
            "active_kid": self._active_kid,
            "next_kid": self._next_kid,
            "verification_kids": tuple(sorted(self._verification_keys.keys())),
            "signing_alg": self._signing_alg,
        }

    def stage_next_signing_key(self, secret_key: str) -> str:
        next_kid = self._key_id_for_secret(secret_key)
        self._verification_keys[next_kid] = self._build_key_material(secret_key)
        self._next_kid = next_kid
        return next_kid

    def activate_staged_signing_key(self) -> str:
        if self._next_kid is None:
            raise RuntimeError("No staged signing key to activate.")
        self._active_kid = self._next_kid
        self._next_kid = None
        return self._active_kid

    def retire_verification_key(self, kid: str) -> bool:
        if kid == self._active_kid or kid == self._next_kid:
            return False
        if kid not in self._verification_keys:
            return False
        del self._verification_keys[kid]
        return True

    def issue(
        self,
        request: ActionRequest,
        parent_mandate: SignedMandate | None = None,
    ) -> SignedMandate:
        issued_at = int(time.time())
        expires_at = issued_at + self._ttl_seconds
        issued_at_ns = time.time_ns()
        intent_hash = hashlib.sha256(request.action_spec.intent.encode("utf-8")).hexdigest()
        delegated_by = parent_mandate.claims.principal_id if parent_mandate is not None else None
        parent_mandate_id = parent_mandate.claims.mandate_id if parent_mandate is not None else None
        delegation_depth = (
            parent_mandate.claims.delegation_depth + 1 if parent_mandate is not None else 0
        )
        mandate_id_seed = (
            f"{request.principal.principal_id}|"
            f"{request.action_spec.action}|"
            f"{request.action_spec.resource}|"
            f"{intent_hash}|"
            f"{request.state_evidence.state_hash}|"
            f"{delegated_by or 'none'}|"
            f"{parent_mandate_id or 'none'}|"
            f"{delegation_depth}|"
            f"{issued_at}|"
            f"{issued_at_ns}"
        )
        mandate_id = hashlib.sha256(mandate_id_seed.encode("utf-8")).hexdigest()[:24]
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
            parent_mandate_id=parent_mandate_id,
            delegation_depth=delegation_depth,
            delegation_chain_hash=delegation_chain_hash,
            iss=self._token_issuer,
            aud=self._token_audience,
            sub=request.principal.principal_id,
            iat=issued_at,
            exp=expires_at,
            nbf=issued_at,
            jti=mandate_id,
        )
        token, signature = self._sign_claims(claims)
        return SignedMandate(token=token, claims=claims, signature=signature)

    def verify(self, token: str) -> SignedMandate | None:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        encoded_header, encoded_payload, encoded_signature = parts
        alg, kid = self._parse_header_fields(encoded_header)
        if alg is None:
            return None
        signing_input = f"{encoded_header}.{encoded_payload}".encode()
        if not self._verify_signature(
            alg=alg,
            signing_input=signing_input,
            encoded_signature=encoded_signature,
            kid=kid,
        ):
            return None

        claims = self._parse_claims(encoded_payload)
        if claims is None:
            return None

        now_epoch = int(time.time())
        if not self._claims_valid_for_epoch(claims, now_epoch):
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
        active_material = self._verification_keys[self._active_kid]
        header_json = json.dumps(
            {"alg": self._signing_alg, "typ": "JWT", "kid": self._active_kid},
            separators=(",", ":"),
            sort_keys=True,
        )
        payload_json = json.dumps(asdict(claims), separators=(",", ":"), sort_keys=True)

        encoded_header = self._base64url_encode(header_json.encode("utf-8"))
        encoded_payload = self._base64url_encode(payload_json.encode("utf-8"))
        signing_input = f"{encoded_header}.{encoded_payload}".encode()
        if self._signing_alg == "HS256":
            signature_bytes = self._hmac(signing_input, secret_key=active_material.secret_key)
        else:
            der_signature = active_material.private_key.sign(
                signing_input, ec.ECDSA(hashes.SHA256())
            )
            signature_bytes = self._der_signature_to_raw(der_signature)
        signature = self._base64url_encode(signature_bytes)
        token = f"{encoded_header}.{encoded_payload}.{signature}"
        return token, signature

    def _hmac(self, payload: bytes, secret_key: bytes) -> bytes:
        return hmac.new(secret_key, payload, hashlib.sha256).digest()

    def _verify_signature(
        self,
        alg: str,
        signing_input: bytes,
        encoded_signature: str,
        kid: str | None,
    ) -> bool:
        if alg == "HS256":
            if not self._allow_legacy_hs256_verify and self._signing_alg != "HS256":
                return False
            candidate_kids = self._candidate_kids_for_verify(kid)
            for candidate_kid in candidate_kids:
                material = self._verification_keys.get(candidate_kid)
                if material is None:
                    continue
                expected_signature = self._hmac(signing_input, secret_key=material.secret_key)
                expected_signature_encoded = self._base64url_encode(expected_signature)
                if hmac.compare_digest(expected_signature_encoded, encoded_signature):
                    return True
            return False
        if alg == "ES256":
            candidate_kids = self._candidate_kids_for_verify(kid)
            try:
                raw_signature = self._base64url_decode(encoded_signature)
                der_signature = self._raw_signature_to_der(raw_signature)
            except ValueError:
                return False
            for candidate_kid in candidate_kids:
                material = self._verification_keys.get(candidate_kid)
                if material is None:
                    continue
                try:
                    material.public_key.verify(
                        der_signature, signing_input, ec.ECDSA(hashes.SHA256())
                    )
                    return True
                except InvalidSignature:
                    continue
            return False
        return False

    def _candidate_kids_for_verify(self, kid: str | None) -> tuple[str, ...]:
        if isinstance(kid, str) and kid.strip() != "":
            normalized = kid.strip()
            if normalized in self._verification_keys:
                return (normalized,)
        if self._active_kid in self._verification_keys:
            return (self._active_kid, *tuple(self._verification_keys.keys()))
        return tuple(self._verification_keys.keys())

    def _parse_header_fields(self, encoded_header: str) -> tuple[str | None, str | None]:
        try:
            header_json = self._base64url_decode(encoded_header).decode("utf-8")
            loaded_header = json.loads(header_json)
        except (ValueError, TypeError, json.JSONDecodeError):
            return None, None
        if not isinstance(loaded_header, dict):
            return None, None
        header: dict[str, Any] = loaded_header
        alg = header.get("alg")
        if not isinstance(alg, str):
            return None, None
        kid_value = header.get("kid")
        kid = kid_value if isinstance(kid_value, str) else None
        return alg, kid

    def _parse_claims(self, encoded_payload: str) -> MandateClaims | None:
        try:
            payload_json = self._base64url_decode(encoded_payload).decode("utf-8")
            loaded_payload = json.loads(payload_json)
        except (ValueError, TypeError, json.JSONDecodeError):
            return None
        if not isinstance(loaded_payload, dict):
            return None
        try:
            return MandateClaims(**loaded_payload)
        except TypeError:
            return None

    @staticmethod
    def _claims_valid_for_epoch(claims: MandateClaims, now_epoch: int) -> bool:
        effective_exp = claims.exp if claims.exp is not None else claims.expires_at_epoch_s
        if effective_exp < now_epoch:
            return False
        if claims.iat is not None and claims.iat > now_epoch:
            return False
        if claims.nbf is not None and claims.nbf > now_epoch:
            return False
        if claims.delegation_depth < 0:
            return False
        if claims.delegation_depth == 0 and claims.delegated_by is not None:
            return False
        if claims.delegation_depth > 0 and claims.delegated_by is None:
            return False
        return claims.delegation_chain_hash is not None

    @classmethod
    def _build_key_material(cls, secret_key: str) -> _SigningKeyMaterial:
        secret = secret_key.encode("utf-8")
        private_key = cls._derive_private_key(secret_key)
        return _SigningKeyMaterial(
            secret_key=secret,
            private_key=private_key,
            public_key=private_key.public_key(),
        )

    @staticmethod
    def _key_id_for_secret(secret_key: str) -> str:
        return hashlib.sha256(f"mandate-signing:{secret_key}".encode()).hexdigest()[:16]

    @staticmethod
    def _derive_private_key(secret_key: str) -> ec.EllipticCurvePrivateKey:
        digest = hashlib.sha256(secret_key.encode("utf-8")).digest()
        private_value = int.from_bytes(digest, "big")
        # Ensure private value is in valid range for the curve.
        order = int(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            16,
        )
        private_value = (private_value % (order - 1)) + 1
        return ec.derive_private_key(private_value, ec.SECP256R1())

    @staticmethod
    def _der_signature_to_raw(der_signature: bytes) -> bytes:
        r_value, s_value = cast(tuple[int, int], utils.decode_dss_signature(der_signature))
        return r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")

    @staticmethod
    def _raw_signature_to_der(raw_signature: bytes) -> bytes:
        if len(raw_signature) != 64:
            raise ValueError("ES256 signature must be 64 bytes")
        r_value = int.from_bytes(raw_signature[:32], "big")
        s_value = int.from_bytes(raw_signature[32:], "big")
        return cast(bytes, utils.encode_dss_signature(r_value, s_value))

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
