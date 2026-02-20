from __future__ import annotations

import base64
import hmac
import json
from dataclasses import asdict
from hashlib import sha256

# pylint: disable=import-error
from predicate_authority import LocalMandateSigner
from predicate_contracts import (
    ActionRequest,
    ActionSpec,
    PrincipalRef,
    StateEvidence,
    VerificationEvidence,
)


def _jwt_header(token: str) -> dict[str, object]:
    encoded_header = token.split(".")[0]
    padding = "=" * ((4 - len(encoded_header) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded_header + padding).decode("utf-8"))


def _jwt_payload(token: str) -> dict[str, object]:
    encoded_payload = token.split(".")[1]
    padding = "=" * ((4 - len(encoded_payload) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded_payload + padding).decode("utf-8"))


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _build_legacy_hs256_token(secret_key: str, payload: dict[str, object]) -> str:
    header_json = json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":"), sort_keys=True)
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    encoded_header = _base64url(header_json.encode("utf-8"))
    encoded_payload = _base64url(payload_json.encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode()
    signature = hmac.new(secret_key.encode("utf-8"), signing_input, sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_base64url(signature)}"


def test_mandate_signature_verifies() -> None:
    signer = LocalMandateSigner(secret_key="test-key", ttl_seconds=60)
    request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:writer"),
        action_spec=ActionSpec(
            action="mcp.execute", resource="mcp://tools/write_file", intent="write report"
        ),
        state_evidence=StateEvidence(source="non-web", state_hash="state-xyz"),
        verification_evidence=VerificationEvidence(),
    )

    signed = signer.issue(request)
    verified = signer.verify(signed.token)

    assert verified is not None
    assert verified.claims.mandate_id == signed.claims.mandate_id
    assert verified.claims.intent_hash == signed.claims.intent_hash
    assert verified.claims.delegation_depth == 0
    assert verified.claims.delegated_by is None
    assert verified.claims.delegation_chain_hash is not None


def test_mandate_tamper_is_rejected() -> None:
    signer = LocalMandateSigner(secret_key="test-key", ttl_seconds=60)
    request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:writer"),
        action_spec=ActionSpec(
            action="mcp.execute", resource="mcp://tools/write_file", intent="write report"
        ),
        state_evidence=StateEvidence(source="non-web", state_hash="state-xyz"),
        verification_evidence=VerificationEvidence(),
    )
    signed = signer.issue(request)

    token_parts = signed.token.split(".")
    tampered_payload = token_parts[1][:-1] + ("A" if token_parts[1][-1] != "A" else "B")
    tampered = f"{token_parts[0]}.{tampered_payload}.{token_parts[2]}"
    assert signer.verify(tampered) is None


def test_multi_hop_delegation_claims_and_chain_verification() -> None:
    signer = LocalMandateSigner(secret_key="test-key", ttl_seconds=60)
    root_request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:root"),
        action_spec=ActionSpec(
            action="task.delegate",
            resource="worker:queue/main",
            intent="delegate job",
        ),
        state_evidence=StateEvidence(source="non-web", state_hash="state-root"),
        verification_evidence=VerificationEvidence(),
    )
    root_mandate = signer.issue(root_request)

    child_request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:worker"),
        action_spec=ActionSpec(
            action="job.execute",
            resource="queue://jobs/high-priority",
            intent="execute delegated job",
        ),
        state_evidence=StateEvidence(source="non-web", state_hash="state-worker"),
        verification_evidence=VerificationEvidence(),
    )
    child_mandate = signer.issue(child_request, parent_mandate=root_mandate)

    assert root_mandate.claims.delegation_depth == 0
    assert root_mandate.claims.delegated_by is None
    assert child_mandate.claims.delegation_depth == 1
    assert child_mandate.claims.delegated_by == "agent:root"
    assert child_mandate.claims.delegation_chain_hash is not None

    assert signer.verify_delegation(root_mandate, parent_mandate=None) is True
    assert signer.verify_delegation(child_mandate, parent_mandate=root_mandate) is True
    assert signer.verify_delegation(child_mandate, parent_mandate=None) is False


def test_mandate_signer_defaults_to_es256_issue_and_verify() -> None:
    signer = LocalMandateSigner(secret_key="test-key", ttl_seconds=60)
    request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:writer"),
        action_spec=ActionSpec(
            action="mcp.execute", resource="mcp://tools/write_file", intent="write report"
        ),
        state_evidence=StateEvidence(source="non-web", state_hash="state-xyz"),
        verification_evidence=VerificationEvidence(),
    )

    signed = signer.issue(request)
    header = _jwt_header(signed.token)
    payload = _jwt_payload(signed.token)
    verified = signer.verify(signed.token)

    assert header["alg"] == "ES256"
    assert "kid" in header
    assert payload["iss"] == "predicate-authorityd"
    assert payload["aud"] == "predicate-authority"
    assert payload["sub"] == "agent:writer"
    assert payload["jti"] == signed.claims.mandate_id
    assert payload["iat"] == signed.claims.issued_at_epoch_s
    assert payload["exp"] == signed.claims.expires_at_epoch_s
    assert payload["nbf"] == signed.claims.issued_at_epoch_s
    assert verified is not None


def test_es256_signer_verifies_legacy_hs256_tokens_by_default() -> None:
    legacy = LocalMandateSigner(secret_key="test-key", ttl_seconds=60, signing_alg="HS256")
    current = LocalMandateSigner(secret_key="test-key", ttl_seconds=60)
    request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:writer"),
        action_spec=ActionSpec(
            action="mcp.execute", resource="mcp://tools/write_file", intent="write report"
        ),
        state_evidence=StateEvidence(source="non-web", state_hash="state-xyz"),
        verification_evidence=VerificationEvidence(),
    )
    legacy_token = legacy.issue(request).token
    header = _jwt_header(legacy_token)

    verified = current.verify(legacy_token)

    assert header["alg"] == "HS256"
    assert verified is not None


def test_es256_signer_rejects_legacy_hs256_when_disabled() -> None:
    legacy = LocalMandateSigner(secret_key="test-key", ttl_seconds=60, signing_alg="HS256")
    strict_current = LocalMandateSigner(
        secret_key="test-key",
        ttl_seconds=60,
        signing_alg="ES256",
        allow_legacy_hs256_verify=False,
    )
    request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:writer"),
        action_spec=ActionSpec(
            action="mcp.execute", resource="mcp://tools/write_file", intent="write report"
        ),
        state_evidence=StateEvidence(source="non-web", state_hash="state-xyz"),
        verification_evidence=VerificationEvidence(),
    )
    legacy_token = legacy.issue(request).token

    assert strict_current.verify(legacy_token) is None


def test_new_signer_parses_legacy_payload_without_standard_claims() -> None:
    legacy_signer = LocalMandateSigner(secret_key="test-key", ttl_seconds=60, signing_alg="HS256")
    current_signer = LocalMandateSigner(secret_key="test-key", ttl_seconds=60, signing_alg="ES256")
    request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:writer"),
        action_spec=ActionSpec(
            action="mcp.execute", resource="mcp://tools/write_file", intent="write report"
        ),
        state_evidence=StateEvidence(source="non-web", state_hash="state-xyz"),
        verification_evidence=VerificationEvidence(),
    )
    signed = legacy_signer.issue(request)
    legacy_payload = asdict(signed.claims)
    for key in ("iss", "aud", "sub", "iat", "exp", "nbf", "jti"):
        legacy_payload.pop(key, None)
    legacy_token = _build_legacy_hs256_token("test-key", legacy_payload)

    verified = current_signer.verify(legacy_token)

    assert verified is not None
    assert verified.claims.iss is None
    assert verified.claims.aud is None
    assert verified.claims.sub is None
    assert verified.claims.iat is None
    assert verified.claims.exp is None
    assert verified.claims.nbf is None
    assert verified.claims.jti is None


def test_key_rotation_activate_preserves_overlap_verify_window() -> None:
    signer = LocalMandateSigner(secret_key="key-v1", ttl_seconds=60, signing_alg="ES256")
    request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:writer"),
        action_spec=ActionSpec(
            action="mcp.execute", resource="mcp://tools/write_file", intent="write report"
        ),
        state_evidence=StateEvidence(source="non-web", state_hash="state-xyz"),
        verification_evidence=VerificationEvidence(),
    )
    old_signed = signer.issue(request)
    old_kid = str(_jwt_header(old_signed.token)["kid"])

    staged_kid = signer.stage_next_signing_key("key-v2")
    activated_kid = signer.activate_staged_signing_key()
    new_signed = signer.issue(request)
    new_kid = str(_jwt_header(new_signed.token)["kid"])
    status = signer.key_lifecycle_status()

    assert staged_kid == activated_kid
    assert new_kid == activated_kid
    assert activated_kid != old_kid
    assert signer.verify(old_signed.token) is not None
    assert signer.verify(new_signed.token) is not None
    assert status["active_kid"] == activated_kid
    assert status["next_kid"] is None
    assert old_kid in status["verification_kids"]
    assert activated_kid in status["verification_kids"]


def test_key_rotation_retire_old_key_invalidates_old_token() -> None:
    signer = LocalMandateSigner(secret_key="key-v1", ttl_seconds=60, signing_alg="ES256")
    request = ActionRequest(
        principal=PrincipalRef(principal_id="agent:writer"),
        action_spec=ActionSpec(
            action="mcp.execute", resource="mcp://tools/write_file", intent="write report"
        ),
        state_evidence=StateEvidence(source="non-web", state_hash="state-xyz"),
        verification_evidence=VerificationEvidence(),
    )
    old_signed = signer.issue(request)
    old_kid = str(_jwt_header(old_signed.token)["kid"])
    signer.stage_next_signing_key("key-v2")
    signer.activate_staged_signing_key()
    _ = signer.issue(request)

    retired = signer.retire_verification_key(old_kid)

    assert retired is True
    assert signer.verify(old_signed.token) is None
