from __future__ import annotations

from predicate_authority import LocalMandateSigner
from predicate_contracts import (
    ActionRequest,
    ActionSpec,
    PrincipalRef,
    StateEvidence,
    VerificationEvidence,
)


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

    tampered = signed.token[:-1] + ("A" if signed.token[-1] != "A" else "B")
    assert signer.verify(tampered) is None
